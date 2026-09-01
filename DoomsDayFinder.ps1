#requires -Version 5.1
<#!
.SYNOPSIS
  Read-only forensic scanner for verified DoomsDay indicators.
.DESCRIPTION
  The scanner never executes a candidate payload. It treats confidence as an
  evidence weight, not a statistical probability. DETECTED requires a verified
  hash or at least two independent, high-specificity DoomsDay signatures that
  survive a second inspection.
#>
[CmdletBinding()]
param(
    [ValidateSet('Menu','Quick','Full','File','ADS','Runtime','Update','Export','SelfTest')]
    [string]$Mode = 'Menu',
    [string]$Path,
    [switch]$Deep,
    [switch]$NoPause,
    [switch]$PassThru
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

$script:ToolVersion = '1.1.0'
$script:ProjectRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:SignaturePath = Join-Path $script:ProjectRoot 'signatures\doomsday.json'
$script:ReportDirectory = Join-Path $script:ProjectRoot 'Reports'
$script:SignatureUrl = 'https://raw.githubusercontent.com/zmor749-creator/RevealDoomsDayFinder/main/signatures/doomsday.json'
$script:GenericIndicators = @(
    'minecraft','forge','fabric','module','clickgui','combat','movement','render',
    'player','world','utils','manager','eventbus','mixin'
)
$script:HashCache = @{}
$script:InspectionCache = @{}
$script:Signatures = $null
$script:LastReport = $null
$script:WarningConsoleLimit = 12
$script:Limits = [ordered]@{
    MaximumRecursion = 3
    MaximumDecompressedBytes = 536870912L
    MaximumEntryCount = 200000
    MaximumCompressionRatio = 1000.0
    MaximumNestedEntryBytes = 67108864L
    MaximumMetadataBytes = 4194304L
}

function New-ScanState {
    param([string]$ScanMode)
    [pscustomobject][ordered]@{
        ToolVersion = $script:ToolVersion
        ScanId = [guid]::NewGuid().ToString()
        Mode = $ScanMode
        StartedUtc = [DateTime]::UtcNow
        CompletedUtc = $null
        IsAdministrator = Test-IsAdministrator
        TotalIndexesExtracted = 0
        CandidateFiles = 0
        FilesFound = 0
        FilesFullyScanned = 0
        FilesSkipped = 0
        CorruptedUnreadable = 0
        AdsFindings = 0
        Findings = [System.Collections.ArrayList]::new()
        Warnings = [System.Collections.ArrayList]::new()
        Integrity = [System.Collections.ArrayList]::new()
        Processes = [System.Collections.ArrayList]::new()
        Evidence = [System.Collections.ArrayList]::new()
        AnalyzedSources = [System.Collections.ArrayList]::new()
        UnavailableSources = [System.Collections.ArrayList]::new()
        Statistics = [ordered]@{}
    }
}

function Test-IsAdministrator {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $false }
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Write-Color {
    param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Magenta)
    Write-Host $Text -ForegroundColor $Color
}

function Write-Section {
    param([string]$Title, [ConsoleColor]$Color = [ConsoleColor]::Magenta)
    Write-Color ('=' * 60) $Color
    Write-Color $Title $Color
    Write-Color ('=' * 60) $Color
}

function Write-Stage {
    param([string]$Stage, [string]$Message, [ConsoleColor]$Color = [ConsoleColor]::DarkMagenta)
    $safeStage = if ([string]::IsNullOrWhiteSpace($Stage)) { 'SCAN' } else { $Stage.ToUpperInvariant() }
    Write-Color (('[{0}] {1}' -f $safeStage, $Message)) $Color
}

function Show-RevealBanner {
    $banner = @'
============================================================
                    REVEAL SCREENSHARE
                      DOOMSDAY FINDER
                 FORENSIC DETECTION ENGINE
============================================================
'@
    Write-Host $banner -ForegroundColor Magenta
}

function Write-ScanProgress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$Current,
        [int]$Total,
        [switch]$Completed
    )
    if ([string]::IsNullOrWhiteSpace($Activity)) { $Activity = 'Reveal ScreenShare scan' }
    if ($Completed) {
        Write-Progress -Activity $Activity -Completed
        return
    }
    $percent = if ($Total -gt 0) { [Math]::Min(100, [Math]::Floor(($Current * 100.0) / $Total)) } else { 0 }
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $percent
}

function ConvertTo-SafeDateString {
    param($Value, [string]$Format = 'o')
    if ($null -eq $Value) { return 'UNAVAILABLE' }
    try { return ([DateTime]$Value).ToString($Format) }
    catch { return [string]$Value }
}

function Add-ScanWarning {
    param($State, [string]$Source, [string]$Message, [string]$Path = '')
    [void]$State.Warnings.Add([pscustomobject][ordered]@{
        TimeUtc = [DateTime]::UtcNow
        Source = $Source
        Message = $Message
        Path = $Path
    })
    if ($State.Warnings.Count -le $script:WarningConsoleLimit) {
        Write-Color (('[WARNING] {0}: {1}' -f $Source, $Message)) Yellow
    } elseif ($State.Warnings.Count -eq ($script:WarningConsoleLimit + 1)) {
        Write-Color '[WARNING] Additional warnings are being recorded in the report without filling the console.' Yellow
    }
}

function Add-SourceStatus {
    param($State, [string]$Source, [bool]$Available, [string]$Detail = '')
    $target = if ($Available) { $State.AnalyzedSources } else { $State.UnavailableSources }
    [void]$target.Add([pscustomobject]@{ Source = $Source; Detail = $Detail })
}

function ConvertTo-SafeArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value)
}

function Test-GenericIndicator {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    $normalized = $Value.Trim().ToLowerInvariant()
    return $script:GenericIndicators -contains $normalized
}

function Import-DoomsDaySignatures {
    if (-not (Test-Path -LiteralPath $script:SignaturePath -PathType Leaf)) {
        $script:Signatures = [pscustomobject]@{
            schemaVersion = 1
            family = 'DoomsDay'
            databaseVersion = 'embedded-safe-empty-1'
            generatedUtc = '2026-09-01T00:00:00Z'
            signatures = @()
            knownCleanHashes = @()
        }
        Write-Color '[WARNING] signatures\doomsday.json was not found. Safe empty embedded database loaded; DETECTED is disabled until verified signatures are installed.' Yellow
        return $script:Signatures
    }
    $raw = Get-Content -LiteralPath $script:SignaturePath -Raw -Encoding UTF8
    $db = $raw | ConvertFrom-Json
    if ($null -eq $db.schemaVersion -or $db.schemaVersion -ne 1) {
        throw 'Unsupported signature database schema.'
    }
    if ($db.family -ne 'DoomsDay') { throw 'Signature database family must be DoomsDay.' }
    foreach ($sig in (ConvertTo-SafeArray $db.signatures)) {
        foreach ($required in @('ID','Type','Value','Source','Version','Confidence','Specificity','LastUpdated')) {
            if ($null -eq $sig.PSObject.Properties[$required] -or [string]::IsNullOrWhiteSpace([string]$sig.$required)) {
                throw "Invalid signature: required field '$required' is missing."
            }
        }
        if ((Test-GenericIndicator ([string]$sig.Value)) -and [string]$sig.Specificity -in @('High','VeryHigh','Verified')) {
            throw "Unsafe generic high-specificity signature rejected: $($sig.ID)"
        }
    }
    foreach ($hash in (ConvertTo-SafeArray $db.knownCleanHashes)) {
        if ([string]$hash.SHA256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Invalid known-clean SHA-256.' }
    }
    $script:Signatures = $db
    return $db
}

function Get-SignaturesByType {
    param([string[]]$Type)
    if ($null -eq $script:Signatures) { Import-DoomsDaySignatures | Out-Null }
    return @($script:Signatures.signatures | Where-Object {
        $enabled = if ($_.PSObject.Properties['Enabled']) { [bool]$_.Enabled } else { $true }
        [string]$_.Type -in $Type -and $enabled
    })
}

function Test-KnownCleanHash {
    param([string]$SHA256)
    if ([string]::IsNullOrWhiteSpace($SHA256)) { return $false }
    return $null -ne @($script:Signatures.knownCleanHashes | Where-Object {
        [string]$_.SHA256 -eq $SHA256
    })[0]
}

function Get-StringSha256 {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')
    } finally { $sha.Dispose() }
}

function Get-StreamSha256 {
    param([System.IO.Stream]$Stream)
    $original = 0L
    if ($Stream.CanSeek) { $original = $Stream.Position; $Stream.Position = 0 }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-','') }
    finally {
        $sha.Dispose()
        if ($Stream.CanSeek) { $Stream.Position = $original }
    }
}

function Get-CachedFileSha256 {
    param([Parameter(Mandatory)][string]$LiteralPath, [switch]$BypassCache)
    $item = Get-Item -LiteralPath $LiteralPath -Force
    $key = '{0}|{1}|{2}' -f $item.FullName, $item.Length, $item.LastWriteTimeUtc.Ticks
    if (-not $BypassCache -and $script:HashCache.ContainsKey($key)) { return $script:HashCache[$key] }
    $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
    if (-not $BypassCache) { $script:HashCache[$key] = $hash }
    return $hash
}

function Get-MagicInfoFromStream {
    param([System.IO.Stream]$Stream, [string]$DisplayedExtension = '')
    $position = 0L
    if ($Stream.CanSeek) { $position = $Stream.Position; $Stream.Position = 0 }
    $buffer = New-Object byte[] 8
    $read = $Stream.Read($buffer, 0, $buffer.Length)
    if ($Stream.CanSeek) { $Stream.Position = $position }
    $hex = if ($read -gt 0) { ([BitConverter]::ToString($buffer, 0, $read)).Replace('-',' ') } else { '' }
    $type = 'Unknown'
    if ($read -ge 4 -and $buffer[0] -eq 0x50 -and $buffer[1] -eq 0x4B -and
        (($buffer[2] -eq 0x03 -and $buffer[3] -eq 0x04) -or ($buffer[2] -eq 0x05 -and $buffer[3] -eq 0x06) -or ($buffer[2] -eq 0x07 -and $buffer[3] -eq 0x08))) {
        $type = 'Java Archive / ZIP'
    } elseif ($read -ge 2 -and $buffer[0] -eq 0x4D -and $buffer[1] -eq 0x5A) {
        $type = 'Windows PE'
    } elseif ($read -ge 4 -and $buffer[0] -eq 0xCA -and $buffer[1] -eq 0xFE -and $buffer[2] -eq 0xBA -and $buffer[3] -eq 0xBE) {
        $type = 'Java Class'
    } elseif ($read -ge 2 -and $buffer[0] -eq 0x23 -and $buffer[1] -eq 0x21) {
        $type = 'Script/Text'
    }
    $expected = switch -Regex ($DisplayedExtension.ToLowerInvariant()) {
        '^\.(jar|zip)$' { 'Java Archive / ZIP'; break }
        '^\.(exe|dll)$' { 'Windows PE'; break }
        '^\.class$' { 'Java Class'; break }
        default { '' }
    }
    $mismatch = $false
    if ($DisplayedExtension -and $type -ne 'Unknown') {
        if ($expected) { $mismatch = ($type -ne $expected) }
        elseif ($type -in @('Java Archive / ZIP','Windows PE','Java Class')) { $mismatch = $true }
    }
    [pscustomobject]@{
        MagicBytes = $hex
        ActualType = $type
        ExtensionMismatch = $mismatch
    }
}

function Get-MagicInfo {
    param([Parameter(Mandatory)][string]$LiteralPath)
    $stream = [IO.File]::Open($LiteralPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try { return Get-MagicInfoFromStream -Stream $stream -DisplayedExtension ([IO.Path]::GetExtension($LiteralPath)) }
    finally { $stream.Dispose() }
}

function Test-TextMatch {
    param([string]$Candidate, $Signature)
    if ($null -eq $Candidate) { return $false }
    $mode = if ($Signature.PSObject.Properties['MatchMode']) { [string]$Signature.MatchMode } else { 'Exact' }
    switch ($mode.ToLowerInvariant()) {
        'contains' { return $Candidate.IndexOf([string]$Signature.Value, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
        'prefix' { return $Candidate.StartsWith([string]$Signature.Value, [StringComparison]::OrdinalIgnoreCase) }
        'wildcard' { return $Candidate -like [string]$Signature.Value }
        'regex' {
            try { return [regex]::IsMatch($Candidate, [string]$Signature.Value, [Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromMilliseconds(250)) }
            catch { return $false }
        }
        default { return $Candidate.Equals([string]$Signature.Value, [StringComparison]::OrdinalIgnoreCase) }
    }
}

function Convert-HexToBytes {
    param([string]$Hex)
    $clean = $Hex -replace '[^A-Fa-f0-9]',''
    if ($clean.Length -eq 0 -or ($clean.Length % 2) -ne 0) { throw 'Invalid hex byte sequence.' }
    $bytes = New-Object byte[] ($clean.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16) }
    return $bytes
}

function Test-StreamContainsBytes {
    param([System.IO.Stream]$Stream, [byte[]]$Needle)
    if ($Needle.Length -eq 0) { return $false }
    $original = 0L
    if ($Stream.CanSeek) { $original = $Stream.Position; $Stream.Position = 0 }
    $failure = New-Object int[] $Needle.Length
    $j = 0
    for ($i = 1; $i -lt $Needle.Length; $i++) {
        while ($j -gt 0 -and $Needle[$i] -ne $Needle[$j]) { $j = $failure[$j - 1] }
        if ($Needle[$i] -eq $Needle[$j]) { $j++ }
        $failure[$i] = $j
    }
    $buffer = New-Object byte[] 65536
    $matched = 0
    try {
        while (($count = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            for ($k = 0; $k -lt $count; $k++) {
                while ($matched -gt 0 -and $buffer[$k] -ne $Needle[$matched]) { $matched = $failure[$matched - 1] }
                if ($buffer[$k] -eq $Needle[$matched]) { $matched++ }
                if ($matched -eq $Needle.Length) { return $true }
            }
        }
        return $false
    } finally { if ($Stream.CanSeek) { $Stream.Position = $original } }
}

function Read-ZipEntryText {
    param([IO.Compression.ZipArchiveEntry]$Entry, [long]$MaximumBytes = 4194304)
    if ($Entry.Length -gt $MaximumBytes) { throw "Metadata entry exceeds safe limit: $($Entry.FullName)" }
    $stream = $Entry.Open()
    $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true, 4096, $false)
    try { return $reader.ReadToEnd() }
    finally { $reader.Dispose(); $stream.Dispose() }
}

function Get-ManifestAttributes {
    param([string]$Text)
    $result = [ordered]@{}
    $lastKey = $null
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line.StartsWith(' ') -and $lastKey) { $result[$lastKey] += $line.Substring(1); continue }
        $index = $line.IndexOf(':')
        if ($index -gt 0) {
            $lastKey = $line.Substring(0, $index).Trim()
            $result[$lastKey] = $line.Substring($index + 1).Trim()
        }
    }
    return $result
}

function Add-SignatureMatch {
    param([Collections.ArrayList]$Matches, $Signature, [string]$Location, [string]$Observed)
    if (Test-GenericIndicator ([string]$Signature.Value)) { return }
    if ($null -eq @($Matches | Where-Object { $_.ID -eq $Signature.ID -and $_.Location -eq $Location })[0]) {
        [void]$Matches.Add([pscustomobject][ordered]@{
            ID = [string]$Signature.ID
            Type = [string]$Signature.Type
            Value = [string]$Signature.Value
            Specificity = [string]$Signature.Specificity
            Confidence = [int]$Signature.Confidence
            Source = [string]$Signature.Source
            Location = $Location
            Observed = $Observed
        })
    }
}

function Inspect-ZipStream {
    param(
        [Parameter(Mandatory)][System.IO.Stream]$Stream,
        [Parameter(Mandatory)][string]$DisplayPath,
        [int]$Depth = 0,
        $State
    )
    $result = [pscustomobject][ordered]@{
        DisplayPath = $DisplayPath
        Depth = $Depth
        EntryCount = 0
        ClassCount = 0
        Classes = [System.Collections.ArrayList]::new()
        Packages = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Resources = [System.Collections.ArrayList]::new()
        Embedded = [System.Collections.ArrayList]::new()
        Metadata = [ordered]@{}
        Manifest = [ordered]@{}
        StructuralFingerprint = ''
        Matches = [System.Collections.ArrayList]::new()
        AllEntriesScanned = $false
        SecurityLimitHit = $false
    }
    if ($Depth -gt $script:Limits.MaximumRecursion) { $result.SecurityLimitHit = $true; return $result }
    if ($Stream.CanSeek) { $Stream.Position = 0 }
    $archive = [IO.Compression.ZipArchive]::new($Stream, [IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        $entries = @($archive.Entries)
        $result.EntryCount = $entries.Count
        if ($entries.Count -gt $script:Limits.MaximumEntryCount) { throw [IO.InvalidDataException]::new('ZIP entry-count safety limit exceeded.') }
        $totalExpanded = 0L
        foreach ($entry in $entries) {
            $totalExpanded += [long]$entry.Length
            if ($totalExpanded -gt $script:Limits.MaximumDecompressedBytes) { throw [IO.InvalidDataException]::new('ZIP decompressed-size safety limit exceeded.') }
            if ($entry.CompressedLength -gt 0 -and $entry.Length -gt 1048576) {
                $ratio = [double]$entry.Length / [double]$entry.CompressedLength
                if ($ratio -gt $script:Limits.MaximumCompressionRatio) { throw [IO.InvalidDataException]::new('ZIP compression-ratio safety limit exceeded.') }
            }
        }

        $classSigs = Get-SignaturesByType @('Class')
        $packageSigs = Get-SignaturesByType @('Package')
        $resourceSigs = Get-SignaturesByType @('Resource','EmbeddedNative')
        $manifestSigs = Get-SignaturesByType @('Manifest','ModId','OriginalFilename','LoaderIndicator')
        $contentSigs = Get-SignaturesByType @('String','ByteSequence')
        $classIndex = 0
        foreach ($entry in $entries) {
            $name = $entry.FullName.Replace('\','/')
            if ([string]::IsNullOrEmpty($name)) { continue }
            [void]$result.Resources.Add($name)
            if ($name.EndsWith('.class', [StringComparison]::OrdinalIgnoreCase)) {
                $classIndex++
                $className = $name.Substring(0, $name.Length - 6).Replace('/','.')
                [void]$result.Classes.Add($className)
                $slash = $name.LastIndexOf('/')
                if ($slash -gt 0) {
                    $pkg = $name.Substring(0, $slash).Replace('/','.')
                    if (-not $result.Packages.Contains($pkg)) { [void]$result.Packages.Add($pkg) }
                }
                foreach ($sig in $classSigs) { if (Test-TextMatch $className $sig) { Add-SignatureMatch $result.Matches $sig $name $className } }
                foreach ($sig in $packageSigs) {
                    if ($slash -gt 0 -and (Test-TextMatch $pkg $sig)) { Add-SignatureMatch $result.Matches $sig $name $pkg }
                }
                if ($contentSigs.Count -gt 0) {
                    $entryStream = $entry.Open()
                    try {
                        foreach ($sig in $contentSigs) {
                            $needle = if ([string]$sig.Type -eq 'ByteSequence') { Convert-HexToBytes ([string]$sig.Value) } else { [Text.Encoding]::UTF8.GetBytes([string]$sig.Value) }
                            if (Test-StreamContainsBytes $entryStream $needle) { Add-SignatureMatch $result.Matches $sig $name '[byte content match]' }
                        }
                    } finally { $entryStream.Dispose() }
                }
            }
            foreach ($sig in $resourceSigs) { if (Test-TextMatch $name $sig) { Add-SignatureMatch $result.Matches $sig $name $name } }

            if ($name -match '(?i)^(META-INF/MANIFEST\.MF|mcmod\.info|META-INF/mods\.toml|fabric\.mod\.json|quilt\.mod\.json|plugin\.yml)$' -or $name -match '(?i)^META-INF/services/') {
                try {
                    $text = Read-ZipEntryText $entry $script:Limits.MaximumMetadataBytes
                    $result.Metadata[$name] = $text
                    if ($name -ieq 'META-INF/MANIFEST.MF') { $result.Manifest = Get-ManifestAttributes $text }
                    foreach ($sig in $manifestSigs) { if (Test-TextMatch $text $sig) { Add-SignatureMatch $result.Matches $sig $name '[metadata match]' } }
                } catch { if ($State) { Add-ScanWarning $State 'JAR' $_.Exception.Message $DisplayPath } }
            }

            if ($name -match '(?i)\.(jar|zip)$') {
                [void]$result.Embedded.Add($name)
                if ($Depth -lt $script:Limits.MaximumRecursion) {
                    if ($entry.Length -gt $script:Limits.MaximumNestedEntryBytes) {
                        if ($State) { $State.FilesSkipped++; Add-ScanWarning $State 'NESTED JAR' 'Nested archive exceeds the bounded in-memory inspection limit.' "$DisplayPath!/$name" }
                    } else {
                        $nestedSource = $entry.Open(); $memory = [IO.MemoryStream]::new()
                        try {
                            $nestedSource.CopyTo($memory); $memory.Position = 0
                            $nested = Inspect-ZipStream -Stream $memory -DisplayPath "$DisplayPath!/$name" -Depth ($Depth + 1) -State $State
                            foreach ($match in $nested.Matches) { [void]$result.Matches.Add($match) }
                            foreach ($embeddedName in $nested.Embedded) { [void]$result.Embedded.Add("$name!/$embeddedName") }
                            if (-not $nested.AllEntriesScanned) { $result.SecurityLimitHit = $true }
                        } finally { $nestedSource.Dispose(); $memory.Dispose() }
                    }
                }
            } elseif ($name -match '(?i)\.(dll|so|dylib)$') {
                [void]$result.Embedded.Add($name)
            }
        }
        $result.ClassCount = $classIndex
        $structure = (@($result.Resources | Sort-Object -Unique) -join "`n") + "`n--manifest-keys--`n" + (@($result.Manifest.Keys | Sort-Object) -join "`n")
        $result.StructuralFingerprint = Get-StringSha256 $structure
        foreach ($sig in (Get-SignaturesByType @('StructuralFingerprint'))) {
            if ([string]$sig.Value -eq $result.StructuralFingerprint) { Add-SignatureMatch $result.Matches $sig $DisplayPath $result.StructuralFingerprint }
        }
        $result.AllEntriesScanned = -not $result.SecurityLimitHit
        if ($State) { $State.TotalIndexesExtracted += $entries.Count }
        return $result
    } catch {
        if ($_.Exception.Message -match 'safety limit|bounded') { $result.SecurityLimitHit = $true }
        throw
    } finally { $archive.Dispose() }
}

function Get-CategoryForFile {
    param([string]$Extension, [string]$ActualType, $JarAnalysis, [string]$Source = 'FILE')
    if ($Source -eq 'ADS') { return 'ADS_PAYLOAD' }
    if ($null -ne $JarAnalysis) {
        if ($JarAnalysis.Manifest.Contains('Premain-Class') -or $JarAnalysis.Manifest.Contains('Agent-Class') -or $JarAnalysis.Manifest.Contains('Launcher-Agent-Class')) { return 'JAVA_AGENT' }
        return 'MOD'
    }
    switch ($Extension.ToLowerInvariant()) {
        '.dll' { return 'NATIVE_DLL' }
        '.exe' { return 'LOADER' }
        '.class' { return 'UNKNOWN' }
        default { if ($ActualType -eq 'Windows PE') { return 'LOADER' }; return 'UNKNOWN' }
    }
}

function Get-ScoreForMatches {
    param([object[]]$Matches, [bool]$FilenameMatch, [bool]$RuntimeCorrelation = $false, [bool]$AdsCorrelation = $false)
    $score = 0
    foreach ($match in @($Matches | Sort-Object ID -Unique)) {
        $weight = switch ([string]$match.Type) {
            'SHA256' { 100 }
            'Class' { 35 }
            'Package' { 30 }
            'Resource' { 30 }
            'StructuralFingerprint' { 65 }
            'Manifest' { 30 }
            'ModId' { 50 }
            'ByteSequence' { 45 }
            'EmbeddedNative' { 35 }
            'LoaderIndicator' { 30 }
            'RuntimeIndicator' { 40 }
            'String' { 20 }
            default { 10 }
        }
        $score += [Math]::Min($weight, [int]$match.Confidence)
    }
    if ($RuntimeCorrelation) { $score += 10 }
    if ($AdsCorrelation) { $score += 10 }
    if ($FilenameMatch) { $score += 1 }
    return [Math]::Min(100, $score)
}

function Get-Decision {
    param([object[]]$Matches, [int]$Score, [bool]$KnownClean, [bool]$ContentAvailable = $true)
    $unique = @($Matches | Sort-Object ID -Unique)
    $hashMatch = @($unique | Where-Object { $_.Type -eq 'SHA256' -and $_.Specificity -in @('High','VeryHigh','Verified') }).Count -gt 0
    $strong = @($unique | Where-Object { $_.Specificity -in @('High','VeryHigh','Verified') -and $_.Type -ne 'StructuralFingerprint' })
    $strongTypes = @($strong.Type | Sort-Object -Unique)
    if ($KnownClean -and ($unique.Count -gt 0)) { return [pscustomobject]@{ Verdict='INCONCLUSIVE'; Verification='CONFLICTING'; EligibleForDetected=$false; Reason='Known-clean hash conflicts with signature evidence.' } }
    if (-not $ContentAvailable) { return [pscustomobject]@{ Verdict='REVIEW'; Verification='UNVERIFIED'; EligibleForDetected=$false; Reason='File content was unavailable.' } }
    if ($hashMatch) { return [pscustomobject]@{ Verdict='DETECTED'; Verification='PENDING'; EligibleForDetected=$true; Reason='Verified DoomsDay SHA-256 signature matched.' } }
    if ($strong.Count -ge 2 -and $strongTypes.Count -ge 2) { return [pscustomobject]@{ Verdict='DETECTED'; Verification='PENDING'; EligibleForDetected=$true; Reason='Multiple independent high-specificity DoomsDay indicators matched.' } }
    if ($strong.Count -ge 2 -or $Score -ge 80) { return [pscustomobject]@{ Verdict='HIGH CONFIDENCE'; Verification='PROBABLE'; EligibleForDetected=$false; Reason='Strong indicators require additional independent verification.' } }
    if ($unique.Count -gt 0 -or $Score -ge 40) { return [pscustomobject]@{ Verdict='SUSPICIOUS'; Verification='UNVERIFIED'; EligibleForDetected=$false; Reason='DoomsDay-related indicators require manual review.' } }
    return [pscustomobject]@{ Verdict='INFO'; Verification='UNVERIFIED'; EligibleForDetected=$false; Reason='No verified DoomsDay-specific content indicators.' }
}

function New-Finding {
    param(
        [string]$Family = 'Unknown', [string]$CurrentName, [string]$OriginalName = '', [string]$FullPath,
        [string]$Extension, [string]$ActualFileType, [string]$Category = 'UNKNOWN', [string]$Status = 'CURRENT',
        [string]$LoaderType = 'Unknown', [string]$MinecraftVersion = 'Unknown', [string]$Launcher = 'Unknown',
        [long]$Size = 0, [string]$SHA256 = '', $CreatedUtc = $null, $ModifiedUtc = $null, $LastAccessUtc = $null,
        [string[]]$ExecutionEvidence = @(), [string[]]$EvidenceSources = @(), [object[]]$Evidence = @(),
        [int]$Confidence = 0, [string]$VerificationStatus = 'UNVERIFIED', [string]$Verdict = 'INFO',
        [string[]]$DetectionReasons = @(), [string]$Source = 'FILE', [bool]$ExtensionMismatch = $false,
        [string]$MagicBytes = ''
    )
    [pscustomobject][ordered]@{
        FindingId = 'DDF-' + [guid]::NewGuid().ToString('N').Substring(0,12).ToUpperInvariant()
        Family = $Family
        CurrentName = $CurrentName
        OriginalName = $OriginalName
        Path = $FullPath
        Extension = $Extension
        ActualFileType = $ActualFileType
        ExtensionMismatch = $ExtensionMismatch
        MagicBytes = $MagicBytes
        Category = $Category
        Status = $Status
        LoaderType = $LoaderType
        MinecraftVersion = $MinecraftVersion
        Launcher = $Launcher
        Size = $Size
        SHA256 = $SHA256
        CreatedUtc = $CreatedUtc
        ModifiedUtc = $ModifiedUtc
        LastAccessUtc = $LastAccessUtc
        ExecutionEvidence = @($ExecutionEvidence)
        EvidenceSources = @($EvidenceSources)
        Evidence = @($Evidence)
        Confidence = $Confidence
        VerificationStatus = $VerificationStatus
        Verdict = $Verdict
        DetectionReasons = @($DetectionReasons)
        Source = $Source
    }
}

function Confirm-FileFinding {
    param([string]$LiteralPath, $InitialFinding, [string[]]$InitialMatchIds, $State)
    Write-Stage 'VERIFY' "Second inspection: $LiteralPath"
    try {
        $secondHash = Get-CachedFileSha256 -LiteralPath $LiteralPath -BypassCache
        if ($secondHash -ne $InitialFinding.SHA256) { return [pscustomobject]@{ Verified=$false; Status='CONFLICTING'; Reason='SHA-256 changed between inspections.' } }
        $magic = Get-MagicInfo -LiteralPath $LiteralPath
        $secondIds = [System.Collections.ArrayList]::new()
        foreach ($sig in (Get-SignaturesByType @('SHA256'))) {
            if ([string]$sig.Value -eq $secondHash) { [void]$secondIds.Add([string]$sig.ID) }
        }
        if ($magic.ActualType -eq 'Java Archive / ZIP') {
            $stream = [IO.File]::Open($LiteralPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            try {
                $jar = Inspect-ZipStream -Stream $stream -DisplayPath $LiteralPath -State $null
                foreach ($match in $jar.Matches) { [void]$secondIds.Add([string]$match.ID) }
            } finally { $stream.Dispose() }
        } elseif ($magic.ActualType -in @('Windows PE','Java Class')) {
            $verifyStream = [IO.File]::Open($LiteralPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            try {
                foreach ($sig in (Get-SignaturesByType @('String','ByteSequence','LoaderIndicator','RuntimeIndicator'))) {
                    $needle = if ([string]$sig.Type -eq 'ByteSequence') { Convert-HexToBytes ([string]$sig.Value) } else { [Text.Encoding]::UTF8.GetBytes([string]$sig.Value) }
                    if (Test-StreamContainsBytes $verifyStream $needle) { [void]$secondIds.Add([string]$sig.ID) }
                }
            } finally { $verifyStream.Dispose() }
        }
        $a = @($InitialMatchIds | Sort-Object -Unique)
        $b = @($secondIds | Sort-Object -Unique)
        $missing = @($a | Where-Object { $_ -notin $b })
        if ($missing.Count -gt 0) { return [pscustomobject]@{ Verified=$false; Status='CONFLICTING'; Reason='Signature matches were not reproducible.' } }
        if (Test-KnownCleanHash $secondHash) { return [pscustomobject]@{ Verified=$false; Status='CONFLICTING'; Reason='Known-clean hash matched during verification.' } }
        return [pscustomobject]@{ Verified=$true; Status='VERIFIED'; Reason='Hash and signature evidence reproduced independently.' }
    } catch {
        Add-ScanWarning $State 'VERIFY' $_.Exception.Message $LiteralPath
        return [pscustomobject]@{ Verified=$false; Status='UNVERIFIED'; Reason=$_.Exception.Message }
    }
}

function Invoke-FileInspection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath, $State, [string]$Source = 'FILE', [switch]$AlwaysRecord, [switch]$QuietProgress)
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) { throw "File not found: $LiteralPath" }
    $item = Get-Item -LiteralPath $LiteralPath -Force
    $inspectionKey = $item.FullName.ToLowerInvariant()
    if ($script:InspectionCache.ContainsKey($inspectionKey)) {
        $cachedFinding = $script:InspectionCache[$inspectionKey]
        if ($null -ne $cachedFinding) {
            if ($Source -and $Source -notin @($cachedFinding.EvidenceSources)) { $cachedFinding.EvidenceSources += $Source }
            if ($AlwaysRecord -and $cachedFinding -notin @($State.Findings)) { [void]$State.Findings.Add($cachedFinding) }
        }
        return $cachedFinding
    }
    $State.CandidateFiles++
    $State.FilesFound++
    if (-not $QuietProgress) { Write-Stage 'HASH' "Computing SHA-256: $($item.Name)" }
    try {
        $magic = Get-MagicInfo -LiteralPath $item.FullName
        $sha256 = Get-CachedFileSha256 -LiteralPath $item.FullName
        $matches = [System.Collections.ArrayList]::new()
        foreach ($sig in (Get-SignaturesByType @('SHA256'))) {
            if ([string]$sig.Value -eq $sha256) { Add-SignatureMatch $matches $sig $item.FullName $sha256 }
        }
        $jar = $null
        if ($magic.ActualType -eq 'Java Archive / ZIP') {
            if (-not $QuietProgress) { Write-Stage 'JAR' "Inspecting every archive entry: $($item.Name)" }
            $stream = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            try { $jar = Inspect-ZipStream -Stream $stream -DisplayPath $item.FullName -State $State }
            finally { $stream.Dispose() }
            foreach ($match in $jar.Matches) { [void]$matches.Add($match) }
            if (-not $QuietProgress) { Write-Stage 'CLASS' ("{0} / {0} classes" -f $jar.ClassCount) }
            if (-not $jar.AllEntriesScanned) { $State.FilesSkipped++ }
        } elseif ($magic.ActualType -in @('Windows PE','Java Class')) {
            $contentSigs = Get-SignaturesByType @('String','ByteSequence','LoaderIndicator','RuntimeIndicator')
            if ($contentSigs.Count -gt 0) {
                $stream = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                try {
                    foreach ($sig in $contentSigs) {
                        $needle = if ([string]$sig.Type -eq 'ByteSequence') { Convert-HexToBytes ([string]$sig.Value) } else { [Text.Encoding]::UTF8.GetBytes([string]$sig.Value) }
                        if (Test-StreamContainsBytes $stream $needle) { Add-SignatureMatch $matches $sig $item.FullName '[byte content match]' }
                    }
                } finally { $stream.Dispose() }
            }
        }
        $filenameMatch = $item.Name -match '(?i)dooms[ -_]?day'
        $score = Get-ScoreForMatches -Matches @($matches) -FilenameMatch $filenameMatch -AdsCorrelation:($Source -eq 'ADS')
        $knownClean = Test-KnownCleanHash $sha256
        $decision = Get-Decision -Matches @($matches) -Score $score -KnownClean $knownClean
        if ($filenameMatch -and $matches.Count -eq 0) {
            $decision.Verdict = 'REVIEW'
            $decision.Verification = 'UNVERIFIED'
            $decision.EligibleForDetected = $false
            $decision.Reason = 'Filename-only resemblance requires manual review and cannot identify the family.'
        }
        $reasons = [System.Collections.ArrayList]::new()
        foreach ($match in @($matches | Sort-Object ID -Unique)) { [void]$reasons.Add("$($match.Type) signature $($match.ID) matched at $($match.Location)") }
        if ($filenameMatch) { [void]$reasons.Add('Filename resembles DoomsDay; filename contributes only one informational point.') }
        if ($magic.ExtensionMismatch) { [void]$reasons.Add('Displayed extension does not match file magic bytes.') }
        if ($knownClean) { [void]$reasons.Add('Known-clean hash matched; conflicting evidence protection applied.') }
        if ($reasons.Count -eq 0) { [void]$reasons.Add('No DoomsDay-specific signature matched.') }
        $category = Get-CategoryForFile -Extension $item.Extension -ActualType $magic.ActualType -JarAnalysis $jar -Source $Source
        $finding = New-Finding -Family $(if ($matches.Count -gt 0) { 'DoomsDay' } else { 'Unknown' }) `
            -CurrentName $item.Name -FullPath $item.FullName -Extension $item.Extension -ActualFileType $magic.ActualType `
            -Category $category -Status $(if ($Source -eq 'ADS') { 'ADS' } else { 'CURRENT' }) -Size $item.Length -SHA256 $sha256 `
            -CreatedUtc $item.CreationTimeUtc -ModifiedUtc $item.LastWriteTimeUtc -LastAccessUtc $item.LastAccessTimeUtc `
            -EvidenceSources @($Source) -Evidence @($matches) -Confidence $score -VerificationStatus $decision.Verification `
            -Verdict $decision.Verdict -DetectionReasons @($reasons) -Source $Source -ExtensionMismatch $magic.ExtensionMismatch -MagicBytes $magic.MagicBytes

        if ($decision.EligibleForDetected) {
            $confirm = Confirm-FileFinding -LiteralPath $item.FullName -InitialFinding $finding -InitialMatchIds @($matches.ID) -State $State
            $finding.VerificationStatus = $confirm.Status
            if ($confirm.Verified) { $finding.Verdict = 'DETECTED'; [void]$finding.DetectionReasons.Add($confirm.Reason) }
            else { $finding.Verdict = if ($confirm.Status -eq 'CONFLICTING') { 'INCONCLUSIVE' } else { 'HIGH CONFIDENCE' }; [void]$finding.DetectionReasons.Add($confirm.Reason) }
        }
        $State.FilesFullyScanned++
        if ($AlwaysRecord -or $finding.Verdict -ne 'INFO' -or $filenameMatch -or $magic.ExtensionMismatch) { [void]$State.Findings.Add($finding) }
        $script:InspectionCache[$inspectionKey] = $finding
        return $finding
    } catch [IO.InvalidDataException] {
        $State.CorruptedUnreadable++
        Add-ScanWarning $State 'ARCHIVE' $_.Exception.Message $item.FullName
        return $null
    } catch [UnauthorizedAccessException] {
        $State.FilesSkipped++
        Add-ScanWarning $State 'FILE' 'Access denied.' $item.FullName
        return $null
    } catch {
        $State.CorruptedUnreadable++
        Add-ScanWarning $State 'FILE' $_.Exception.Message $item.FullName
        return $null
    }
}

function Get-NormalizedScanRoots {
    param([string[]]$Roots)
    $resolved = [System.Collections.ArrayList]::new()
    foreach ($root in @($Roots)) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        try {
            if (Test-Path -LiteralPath $root -PathType Container) {
                $fullName = (Get-Item -LiteralPath $root -Force).FullName.TrimEnd('\')
                if ($fullName -and $fullName -notin @($resolved)) { [void]$resolved.Add($fullName) }
            }
        } catch { }
    }
    $kept = [System.Collections.ArrayList]::new()
    foreach ($candidate in @($resolved | Sort-Object Length, @{ Expression={ $_ }; Ascending=$true })) {
        $covered = $false
        foreach ($parent in $kept) {
            if ($candidate.Equals($parent, [StringComparison]::OrdinalIgnoreCase) -or
                $candidate.StartsWith(($parent + '\'), [StringComparison]::OrdinalIgnoreCase)) {
                $covered = $true
                break
            }
        }
        if (-not $covered) { [void]$kept.Add($candidate) }
    }
    return @($kept)
}

function Get-MinecraftLocations {
    $paths = [System.Collections.ArrayList]::new()
    $candidates = @()
    if ($env:APPDATA) {
        $candidates += @(
            (Join-Path $env:APPDATA '.minecraft'),
            (Join-Path $env:APPDATA 'PrismLauncher'),
            (Join-Path $env:APPDATA 'MultiMC'),
            (Join-Path $env:APPDATA 'ATLauncher'),
            (Join-Path $env:APPDATA 'TLauncher'),
            (Join-Path $env:APPDATA '.lunarclient'),
            (Join-Path $env:APPDATA 'Feather'),
            (Join-Path $env:APPDATA 'LabyMod')
        )
    }
    if ($env:LOCALAPPDATA) {
        $candidates += @(
            (Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.4297127D64EC6_8wekyb3d8bbwe\LocalCache\Roaming\.minecraft'),
            (Join-Path $env:LOCALAPPDATA 'ModrinthApp'),
            (Join-Path $env:LOCALAPPDATA 'CurseForge'),
            (Join-Path $env:LOCALAPPDATA 'Programs\PrismLauncher'),
            (Join-Path $env:LOCALAPPDATA 'Badlion Client'),
            (Join-Path $env:LOCALAPPDATA 'Lunar Client')
        )
    }
    if ($env:USERPROFILE) {
        $candidates += @(
            (Join-Path $env:USERPROFILE 'curseforge\minecraft'),
            (Join-Path $env:USERPROFILE 'Documents\Curse\Minecraft'),
            (Join-Path $env:USERPROFILE 'AppData\Roaming\ModrinthApp')
        )
    }
    foreach ($path in @($candidates | Select-Object -Unique)) {
        if ($path -and (Test-Path -LiteralPath $path -PathType Container)) {
            try { [void]$paths.Add((Get-Item -LiteralPath $path -Force).FullName) } catch { }
        }
    }
    return @($paths | Sort-Object -Unique)
}

function Get-CandidateFiles {
    param([string[]]$Roots, $State, [switch]$Full)
    $extensions = @('.jar','.zip','.exe','.dll','.class','.dat','.tmp','.bin','.ps1','.bat','.cmd','.vbs')
    $files = [System.Collections.ArrayList]::new()
    foreach ($root in @(Get-NormalizedScanRoots -Roots $Roots)) {
        Write-Stage 'COLLECT' "Discovering candidates under $root"
        try {
            $children = Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($file in $children) {
                if ($file.Extension.ToLowerInvariant() -in $extensions) { [void]$files.Add($file.FullName) }
            }
        } catch { Add-ScanWarning $State 'DISCOVERY' $_.Exception.Message $root }
    }
    return @($files | Sort-Object -Unique)
}

function Invoke-CandidateScan {
    param([string[]]$Roots, $State, [switch]$Full)
    $files = @(Get-CandidateFiles -Roots $Roots -State $State -Full:$Full)
    $State.CandidateFiles = 0
    if ($files.Count -eq 0) {
        Write-Stage 'SCAN' 'No candidate files were found in the selected locations.'
        return
    }
    Write-Stage 'SCAN' ("{0} candidate files will be analyzed; progress is shown on one updating line." -f $files.Count)
    $index = 0
    foreach ($file in $files) {
        $index++
        $shortName = [IO.Path]::GetFileName($file)
        Write-ScanProgress -Activity 'Reveal ScreenShare - file analysis' -Status ("{0:N0} / {1:N0} - {2}" -f $index, $files.Count, $shortName) -Current $index -Total $files.Count
        Invoke-FileInspection -LiteralPath $file -State $State -QuietProgress | Out-Null
    }
    Write-ScanProgress -Activity 'Reveal ScreenShare - file analysis' -Completed
    Write-Color ("[SCAN] {0:N0} / {1:N0} candidate files analyzed." -f $index, $files.Count) Magenta
}

function Get-ProcessOwner {
    param($CimProcess)
    try {
        $owner = Invoke-CimMethod -InputObject $CimProcess -MethodName GetOwner -ErrorAction Stop
        if ($owner.ReturnValue -eq 0) { return "$($owner.Domain)\$($owner.User)" }
    } catch { }
    return 'Unavailable'
}

function Get-ProcessArchitecture {
    param([int]$ProcessId)
    try {
        if (-not [Environment]::Is64BitOperatingSystem) { return 'x86' }
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        try {
            if ($process.MainModule.FileName -match '(?i)\\SysWOW64\\') { return 'x86' }
            return 'x64 or ARM64'
        } finally { $process.Dispose() }
    } catch { return 'Unknown' }
}

function Get-LauncherFromCommandLine {
    param([string]$CommandLine)
    if (-not $CommandLine) { return 'Unknown' }
    $map = [ordered]@{
        'Lunar'='(?i)lunar'; 'Feather'='(?i)feather'; 'Prism Launcher'='(?i)prismlauncher|\\PrismLauncher\\';
        'MultiMC'='(?i)multimc'; 'Modrinth App'='(?i)modrinth'; 'CurseForge'='(?i)curseforge';
        'ATLauncher'='(?i)atlauncher'; 'LabyMod'='(?i)labymod'; 'TLauncher'='(?i)tlauncher';
        'Badlion'='(?i)badlion'; 'Minecraft Launcher'='(?i)minecraft'
    }
    foreach ($key in $map.Keys) { if ($CommandLine -match $map[$key]) { return $key } }
    return 'Custom / Unknown'
}

function Get-JvmArguments {
    param([string]$CommandLine)
    $result = [ordered]@{ JavaAgent=@(); AgentPath=@(); AgentLib=@(); ClassPath=@() }
    if (-not $CommandLine) { return [pscustomobject]$result }
    $patterns = [ordered]@{
        JavaAgent='(?i)(?:^|\s)-javaagent:(?:"([^"]+)"|([^\s]+))'
        AgentPath='(?i)(?:^|\s)-agentpath:(?:"([^"]+)"|([^\s]+))'
        AgentLib='(?i)(?:^|\s)-agentlib:([^\s]+)'
        ClassPath='(?i)(?:^|\s)(?:-classpath|-cp)\s+(?:"([^"]+)"|([^\s]+))'
    }
    foreach ($key in $patterns.Keys) {
        $values = [System.Collections.ArrayList]::new()
        foreach ($match in [regex]::Matches($CommandLine, $patterns[$key])) {
            $value = ''
            for ($i=1; $i -lt $match.Groups.Count; $i++) { if ($match.Groups[$i].Success) { $value = $match.Groups[$i].Value; break } }
            if ($value) { [void]$values.Add($value) }
        }
        $result[$key] = @($values)
    }
    return [pscustomobject]$result
}

function Get-AuthenticodeInfo {
    param([string]$LiteralPath)
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath
        return [pscustomobject]@{
            Status = [string]$signature.Status
            Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' }
            TimeStamper = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Subject } else { '' }
        }
    } catch { return [pscustomobject]@{ Status='Unavailable'; Signer=''; TimeStamper='' } }
}

function Invoke-RuntimeScan {
    param($State)
    Write-Stage 'PROCESS' 'Inspecting Java and Minecraft-associated processes...'
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -in @('java.exe','javaw.exe') }
        foreach ($process in $processes) {
            $jvm = Get-JvmArguments ([string]$process.CommandLine)
            $processStartTime = $null
            try {
                if ($process.CreationDate -is [DateTime]) {
                    $processStartTime = ([DateTime]$process.CreationDate).ToUniversalTime()
                } elseif ($process.CreationDate) {
                    $processStartTime = [Management.ManagementDateTimeConverter]::ToDateTime([string]$process.CreationDate).ToUniversalTime()
                }
            } catch { $processStartTime = $null }
            $record = [pscustomobject][ordered]@{
                PID = [int]$process.ProcessId
                PPID = [int]$process.ParentProcessId
                ExecutablePath = [string]$process.ExecutablePath
                CommandLine = [string]$process.CommandLine
                StartTime = $processStartTime
                Owner = Get-ProcessOwner $process
                Architecture = Get-ProcessArchitecture ([int]$process.ProcessId)
                Launcher = Get-LauncherFromCommandLine ([string]$process.CommandLine)
                MinecraftAssociation = ([string]$process.CommandLine -match '(?i)minecraft|net\.minecraft|launchwrapper|fabric-loader|forge')
                JvmArguments = $jvm
                LoadedModules = [System.Collections.ArrayList]::new()
            }
            Write-Stage 'MODULE' "Inspecting loaded modules for PID $($record.PID)"
            try {
                $native = Get-Process -Id $record.PID -ErrorAction Stop
                try {
                    foreach ($module in $native.Modules) {
                        $modulePath = [string]$module.FileName
                        $version = $module.FileVersionInfo
                        $auth = Get-AuthenticodeInfo $modulePath
                        $hash = ''
                        try { $hash = Get-CachedFileSha256 $modulePath } catch { $hash = '' }
                        $moduleSize = 0L
                        try { $moduleSize = [long](Get-Item -LiteralPath $modulePath -ErrorAction Stop).Length } catch { $moduleSize = 0L }
                        [void]$record.LoadedModules.Add([pscustomobject][ordered]@{
                            Filename = $module.ModuleName; FullPath = $modulePath; Company = $version.CompanyName
                            ProductName = $version.ProductName; OriginalFilename = $version.OriginalFilename
                            Signer = $auth.Signer; SignatureStatus = $auth.Status; SHA256 = $hash
                            Size = $moduleSize; PID = $record.PID
                        })
                    }
                } finally { $native.Dispose() }
            } catch { Add-ScanWarning $State 'MODULE' $_.Exception.Message "PID $($record.PID)" }
            [void]$State.Processes.Add($record)

            foreach ($agent in @($jvm.JavaAgent)) {
                if (Test-Path -LiteralPath $agent -PathType Leaf) { Invoke-FileInspection -LiteralPath $agent -State $State -Source 'JVM' -AlwaysRecord | Out-Null }
                else {
                    [void]$State.Findings.Add((New-Finding -Family 'Unknown' -CurrentName ([IO.Path]::GetFileName($agent)) -FullPath $agent -Extension ([IO.Path]::GetExtension($agent)) -ActualFileType 'Unavailable' -Category 'JAVA_AGENT' -Status 'RUNTIME_ONLY' -LoaderType 'Java Agent' -Launcher $record.Launcher -ExecutionEvidence @("PID $($record.PID) -javaagent") -EvidenceSources @('JVM arguments') -Confidence 0 -VerificationStatus 'UNVERIFIED' -Verdict 'RUNTIME TRACE' -DetectionReasons @('Java Agent usage is not automatically a cheat; file content was unavailable.') -Source 'JVM'))
                }
            }
            foreach ($agentPath in @($jvm.AgentPath)) {
                $candidate = ($agentPath -split '=')[0]
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { Invoke-FileInspection -LiteralPath $candidate -State $State -Source 'JVM' -AlwaysRecord | Out-Null }
            }
        }
        Add-SourceStatus $State 'Running Processes / JVM Arguments / Loaded Modules' $true ("{0} Java processes" -f @($processes).Count)
    } catch {
        Add-SourceStatus $State 'Running Processes / JVM Arguments / Loaded Modules' $false $_.Exception.Message
        Add-ScanWarning $State 'PROCESS' $_.Exception.Message
    }
}

function Get-SysMainIntegrity {
    param($State)
    Write-Stage 'PREFETCH' 'Checking Prefetch and SysMain integrity...'
    $record = [ordered]@{
        Source='Prefetch/SysMain'; Service='SysMain'; State='Unknown'; StartType='Unknown'; ProcessId=0
        SvchostPath=''; SvchostStartTime=$null; HostedServices=@(); PrefetchStatus='UNKNOWN'
        PrefetchDirectory="$env:SystemRoot\Prefetch"; PrefetchFileCount=0; LastPrefetchFileTimestamp=$null
        EnablePrefetcher=$null
    }
    try {
        $service = Get-CimInstance Win32_Service -Filter "Name='SysMain'" -ErrorAction Stop
        $record.State = [string]$service.State
        $record.StartType = [string]$service.StartMode
        $record.ProcessId = [int]$service.ProcessId
        if ($service.State -eq 'Stopped') { [void]$State.Integrity.Add([pscustomobject]@{ Severity='WARNING'; Code='SYSMAIN_STOPPED'; Message='SysMain is currently stopped; this is not DoomsDay evidence.' }) }
        if ($service.StartMode -eq 'Disabled') { [void]$State.Integrity.Add([pscustomobject]@{ Severity='WARNING'; Code='SYSMAIN_DISABLED'; Message='SysMain is disabled; this is not DoomsDay evidence.' }) }
        if ($service.ProcessId -gt 0) {
            try {
                $hostProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
                $record.SvchostPath = [string]$hostProcess.ExecutablePath
                $hostStartTime = $null
                try {
                    if ($hostProcess.CreationDate -is [DateTime]) {
                        $hostStartTime = ([DateTime]$hostProcess.CreationDate).ToUniversalTime()
                    } elseif ($hostProcess.CreationDate) {
                        $hostStartTime = [Management.ManagementDateTimeConverter]::ToDateTime([string]$hostProcess.CreationDate).ToUniversalTime()
                    }
                } catch { $hostStartTime = $null }
                $record.SvchostStartTime = $hostStartTime
                $record.HostedServices = @(Get-CimInstance Win32_Service | Where-Object ProcessId -eq $service.ProcessId | Select-Object -ExpandProperty Name)
            } catch { Add-ScanWarning $State 'SYSMAIN' $_.Exception.Message }
        }
    } catch { Add-ScanWarning $State 'SYSMAIN' $_.Exception.Message }
    try {
        $prefetchKey = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -ErrorAction Stop
        $record.EnablePrefetcher = [int]$prefetchKey.EnablePrefetcher
    } catch { Add-ScanWarning $State 'PREFETCH' 'EnablePrefetcher could not be read.' }
    try {
        if (-not (Test-Path -LiteralPath $record.PrefetchDirectory -PathType Container)) {
            $record.PrefetchStatus = 'PREFETCH CONFIGURATION UNUSUAL'
            [void]$State.Integrity.Add([pscustomobject]@{ Severity='WARNING'; Code='PREFETCH_DIRECTORY_MISSING'; Message='Prefetch directory is missing.' })
        } else {
            $pf = @(Get-ChildItem -LiteralPath $record.PrefetchDirectory -Filter '*.pf' -File -Force -ErrorAction Stop)
            $record.PrefetchFileCount = $pf.Count
            if ($pf.Count -gt 0) { $record.LastPrefetchFileTimestamp = ($pf | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc }
            if ($record.EnablePrefetcher -eq 0) { $record.PrefetchStatus='PREFETCH DISABLED' }
            elseif ($pf.Count -eq 0) { $record.PrefetchStatus='PREFETCH PARTIALLY AVAILABLE'; [void]$State.Integrity.Add([pscustomobject]@{ Severity='WARNING'; Code='PREFETCH_EMPTY'; Message='Prefetch directory is empty.' }) }
            elseif ($record.EnablePrefetcher -in @(1,2,3)) { $record.PrefetchStatus='PREFETCH ENABLED' }
            else { $record.PrefetchStatus='PREFETCH CONFIGURATION UNUSUAL' }
            foreach ($file in @($pf | Where-Object { $_.Name -match '(?i)^(JAVA|JAVAW|MINECRAFT|.*LAUNCHER.*)-.*\.pf$' })) {
                [void]$State.Evidence.Add([pscustomobject]@{ Source='Prefetch'; Name=$file.Name; Path=$file.FullName; LastWriteTimeUtc=$file.LastWriteTimeUtc; Size=$file.Length; Note='Metadata-only collection; compressed Windows 10/11 Prefetch internals are not decoded.' })
            }
        }
        Add-SourceStatus $State 'Prefetch / SysMain' $true $record.PrefetchStatus
    } catch {
        $record.PrefetchStatus='UNKNOWN'; Add-SourceStatus $State 'Prefetch / SysMain' $false $_.Exception.Message
        Add-ScanWarning $State 'PREFETCH' $_.Exception.Message
    }
    [void]$State.Integrity.Add([pscustomobject]$record)
}

function Get-SechostIntegrity {
    param($State)
    $path = Join-Path $env:SystemRoot 'System32\sechost.dll'
    Write-Stage 'INTEGRITY' "Checking $path"
    $record = [ordered]@{ Source='sechost.dll'; Exists=$false; Path=$path; Size=0; Version=''; MicrosoftSignature=$false; Signer=''; SignatureStatus='Unavailable'; SHA256='' }
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $record.Exists = $true
        try {
            $item = Get-Item -LiteralPath $path
            $record.Size = $item.Length; $record.Version = $item.VersionInfo.FileVersion
            $auth = Get-AuthenticodeInfo $path
            $record.Signer = $auth.Signer; $record.SignatureStatus = $auth.Status
            $record.MicrosoftSignature = ($auth.Status -eq 'Valid' -and $auth.Signer -match '(?i)Microsoft')
            $record.SHA256 = Get-CachedFileSha256 $path
            if (-not $record.MicrosoftSignature) { [void]$State.Integrity.Add([pscustomobject]@{ Severity='HIGH'; Code='SECHOST_SIGNATURE_FAILED'; Message='sechost.dll signature validation failed.' }) }
        } catch { Add-ScanWarning $State 'SECHOST' $_.Exception.Message $path }
    } else { [void]$State.Integrity.Add([pscustomobject]@{ Severity='HIGH'; Code='SECHOST_MISSING'; Message='sechost.dll is missing.' }) }
    [void]$State.Integrity.Add([pscustomobject]$record)
    Add-SourceStatus $State 'sechost.dll integrity' $record.Exists $record.SignatureStatus
}

function Get-ZoneIdentifier {
    param([string]$HostPath, [string]$StreamName = 'Zone.Identifier')
    $result = [ordered]@{ ZoneId=$null; ReferrerUrl=''; HostUrl='' }
    try {
        $streamPath = "$HostPath`:$StreamName"
        $text = [IO.File]::ReadAllText($streamPath)
        foreach ($line in ($text -split "`r?`n")) {
            $parts = $line -split '=',2
            if ($parts.Count -ne 2) { continue }
            switch ($parts[0].Trim()) {
                'ZoneId' { $value = 0; if ([int]::TryParse($parts[1].Trim(), [ref]$value)) { $result.ZoneId=$value } }
                'ReferrerUrl' { $result.ReferrerUrl=$parts[1].Trim() }
                'HostUrl' { $result.HostUrl=$parts[1].Trim() }
            }
        }
    } catch { }
    return [pscustomobject]$result
}

function Inspect-AdsPayload {
    param([string]$HostPath, $StreamInfo, $State)
    $streamName = [string]$StreamInfo.Stream
    $streamPath = "$HostPath`:$streamName"
    $host = Get-Item -LiteralPath $HostPath -Force
    $stream = [IO.File]::Open($streamPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        $magic = Get-MagicInfoFromStream -Stream $stream -DisplayedExtension ([IO.Path]::GetExtension($HostPath))
        $sha256 = Get-StreamSha256 $stream
        $matches = [System.Collections.ArrayList]::new()
        foreach ($sig in (Get-SignaturesByType @('SHA256'))) { if ([string]$sig.Value -eq $sha256) { Add-SignatureMatch $matches $sig "$HostPath`:$streamName" $sha256 } }
        $jar = $null
        if ($magic.ActualType -eq 'Java Archive / ZIP') {
            $stream.Position = 0
            $jar = Inspect-ZipStream -Stream $stream -DisplayPath "$HostPath`:$streamName" -State $State
            foreach ($match in $jar.Matches) { [void]$matches.Add($match) }
        } else {
            foreach ($sig in (Get-SignaturesByType @('String','ByteSequence','LoaderIndicator','RuntimeIndicator'))) {
                $needle = if ([string]$sig.Type -eq 'ByteSequence') { Convert-HexToBytes ([string]$sig.Value) } else { [Text.Encoding]::UTF8.GetBytes([string]$sig.Value) }
                if (Test-StreamContainsBytes $stream $needle) { Add-SignatureMatch $matches $sig "$HostPath`:$streamName" '[byte content match]' }
            }
        }
        $score = Get-ScoreForMatches @($matches) $false $false $true
        $knownClean = Test-KnownCleanHash $sha256
        $decision = Get-Decision @($matches) $score $knownClean
        $reasons = [System.Collections.ArrayList]::new()
        foreach ($match in @($matches | Sort-Object ID -Unique)) { [void]$reasons.Add("$($match.Type) signature $($match.ID) matched in ADS $streamName") }
        if ($magic.ActualType -eq 'Windows PE') { [void]$reasons.Add('Named ADS contains an embedded PE payload; this is not automatically DoomsDay.') }
        elseif ($magic.ActualType -eq 'Java Archive / ZIP') { [void]$reasons.Add('Named ADS contains an embedded archive payload; this is not automatically DoomsDay.') }
        elseif ($magic.ActualType -eq 'Java Class') { [void]$reasons.Add('Named ADS contains an embedded Java class; this is not automatically DoomsDay.') }
        if ($reasons.Count -eq 0) { [void]$reasons.Add('Named ADS is present but no DoomsDay-specific signature matched.') }
        $finding = New-Finding -Family $(if ($matches.Count -gt 0) {'DoomsDay'} else {'Unknown'}) -CurrentName "$($host.Name):$streamName" `
            -FullPath "$($host.FullName):$streamName" -Extension $host.Extension -ActualFileType $magic.ActualType -Category 'ADS_PAYLOAD' -Status 'ADS' `
            -Size ([long]$StreamInfo.Length) -SHA256 $sha256 -CreatedUtc $host.CreationTimeUtc -ModifiedUtc $host.LastWriteTimeUtc -LastAccessUtc $host.LastAccessTimeUtc `
            -EvidenceSources @('ADS') -Evidence @($matches) -Confidence $score -VerificationStatus $decision.Verification -Verdict $decision.Verdict `
            -DetectionReasons @($reasons) -Source 'ADS' -MagicBytes $magic.MagicBytes
        if ($decision.EligibleForDetected) {
            $stream.Position = 0; $secondHash = Get-StreamSha256 $stream
            if ($secondHash -eq $sha256 -and -not $knownClean) { $finding.VerificationStatus='VERIFIED'; $finding.Verdict='DETECTED'; [void]$finding.DetectionReasons.Add('ADS content hash reproduced during verification.') }
            else { $finding.VerificationStatus='CONFLICTING'; $finding.Verdict='INCONCLUSIVE' }
        }
        [void]$State.Findings.Add($finding); $State.AdsFindings++
        return $finding
    } finally { $stream.Dispose() }
}

function Invoke-AdsScan {
    param([string[]]$Roots, $State, [switch]$DeepScan)
    Write-Stage 'ADS' 'Enumerating NTFS alternate data streams (read-only)...'
    $files = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($root in @(Get-NormalizedScanRoots -Roots $Roots)) {
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Force -Recurse:$DeepScan -ErrorAction SilentlyContinue)) { [void]$files.Add($file.FullName) }
        } catch { Add-ScanWarning $State 'ADS' $_.Exception.Message $root }
    }
    $fileList = @($files | Sort-Object)
    if ($fileList.Count -gt 0) { Write-Stage 'ADS' ("Checking ADS on {0:N0} files with one-line progress." -f $fileList.Count) }
    $fileIndex = 0
    foreach ($file in $fileList) {
        $fileIndex++
        Write-ScanProgress -Activity 'Reveal ScreenShare - ADS analysis' -Status ("{0:N0} / {1:N0} - {2}" -f $fileIndex, $fileList.Count, [IO.Path]::GetFileName($file)) -Current $fileIndex -Total $fileList.Count
        try {
            $streams = @(Get-Item -LiteralPath $file -Stream * -ErrorAction Stop)
            foreach ($streamInfo in $streams) {
                $name = [string]$streamInfo.Stream
                if ($name -in @(':$DATA','::$DATA','$DATA')) { continue }
                if ($name -ieq 'Zone.Identifier') {
                    $zone = Get-ZoneIdentifier -HostPath $file -StreamName $name
                    [void]$State.Evidence.Add([pscustomobject][ordered]@{
                        Source='Zone.Identifier'; HostPath=$file; Stream=$name; Length=[long]$streamInfo.Length
                        ZoneId=$zone.ZoneId; ReferrerUrl=$zone.ReferrerUrl; HostUrl=$zone.HostUrl
                    })
                    continue
                }
                try { Inspect-AdsPayload -HostPath $file -StreamInfo $streamInfo -State $State | Out-Null }
                catch { Add-ScanWarning $State 'ADS' $_.Exception.Message "$file`:$name" }
            }
        } catch [System.Management.Automation.ParameterBindingException] {
            Add-ScanWarning $State 'ADS' 'The current filesystem/provider does not expose the Stream parameter.' $file
            break
        } catch { }
    }
    Write-ScanProgress -Activity 'Reveal ScreenShare - ADS analysis' -Completed
    if ($fileList.Count -gt 0) { Write-Color ("[ADS] {0:N0} files checked; {1:N0} named payload streams found." -f $fileList.Count, $State.AdsFindings) Magenta }
    Add-SourceStatus $State 'NTFS Alternate Data Streams' $true ("{0} named payload streams" -f $State.AdsFindings)
}

function Get-UsnJournalEvidence {
    param($State)
    Write-Stage 'USN' 'Reading NTFS USN journal with fsutil (read-only)...'
    if (-not $State.IsAdministrator) { Add-SourceStatus $State 'USN Journal' $false 'Administrator rights required'; Add-ScanWarning $State 'USN' 'Skipped in LIMITED MODE.'; return }
    $systemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
    try {
        $psi = [Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = 'fsutil.exe'
        $psi.Arguments = "usn readjournal $systemDrive csv"
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
        $process = [Diagnostics.Process]::new(); $process.StartInfo = $psi
        if (-not $process.Start()) { throw 'fsutil could not be started.' }
        $candidatePattern = '(?i)([^,"\r\n]+\.(?:jar|exe|dll|class|zip|dat|tmp|bin|ps1|bat|cmd|vbs))'
        $count = 0
        while (-not $process.StandardOutput.EndOfStream) {
            $line = $process.StandardOutput.ReadLine()
            if ($line -match $candidatePattern) {
                $name = $matches[1].Trim('"',' ')
                $reason = @()
                foreach ($token in @('FILE_CREATE','FILE_DELETE','RENAME_OLD_NAME','RENAME_NEW_NAME','DATA_EXTEND','DATA_OVERWRITE','CLOSE')) { if ($line -match $token) { $reason += $token } }
                [void]$State.Evidence.Add([pscustomobject][ordered]@{ Source='USN Journal'; Name=$name; Reason=@($reason); Raw=$line })
                $count++
                if ($name -match '(?i)dooms[ -_]?day') {
                    $isDeleted = $reason -contains 'FILE_DELETE'
                    [void]$State.Findings.Add((New-Finding -Family 'Unknown' -CurrentName ([IO.Path]::GetFileName($name)) -FullPath $name -Extension ([IO.Path]::GetExtension($name)) -ActualFileType 'Unavailable' -Category $(if($isDeleted){'DELETED_PAYLOAD'}else{'UNKNOWN'}) -Status $(if($isDeleted){'DELETED'}else{'UNKNOWN'}) -EvidenceSources @('USN Journal') -Evidence @($line) -Confidence 1 -VerificationStatus 'UNVERIFIED' -Verdict $(if($isDeleted){'DELETED TRACE'}else{'REVIEW'}) -DetectionReasons @('Filename-only USN trace; file content is unavailable, so DETECTED is forbidden.') -Source 'USN'))
                }
            }
        }
        $errorText = $process.StandardError.ReadToEnd(); $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "fsutil exited with code $($process.ExitCode): $errorText" }
        $process.Dispose()
        Add-SourceStatus $State 'USN Journal' $true "$count candidate lifecycle records"
    } catch { Add-SourceStatus $State 'USN Journal' $false $_.Exception.Message; Add-ScanWarning $State 'USN' $_.Exception.Message }
}

function ConvertFrom-Rot13 {
    param([string]$Text)
    $chars = $Text.ToCharArray()
    for ($i=0; $i -lt $chars.Length; $i++) {
        $code = [int]$chars[$i]
        if ($code -ge 65 -and $code -le 90) { $chars[$i] = [char](65 + (($code - 65 + 13) % 26)) }
        elseif ($code -ge 97 -and $code -le 122) { $chars[$i] = [char](97 + (($code - 97 + 13) % 26)) }
    }
    return -join $chars
}

function Get-RegistryArtifactEvidence {
    param($State)
    Write-Stage 'REGISTRY' 'Collecting Amcache, BAM, UserAssist and MRU evidence...'
    $sourceCount = 0
    $paths = @(
        @{ Source='Amcache'; Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\hivelist' },
        @{ Source='BAM'; Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' },
        @{ Source='BAM'; Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings' },
        @{ Source='RecentDocs'; Path='Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' },
        @{ Source='OpenSaveMRU'; Path='Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU' }
    )
    foreach ($entry in $paths) {
        if (-not (Test-Path -LiteralPath $entry.Path)) { continue }
        try {
            if ($entry.Source -eq 'Amcache') {
                $inventory = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'
                if (Test-Path -LiteralPath $inventory) {
                    $item = Get-Item -LiteralPath $inventory
                    foreach ($name in $item.GetValueNames()) { if ($name -match '(?i)\.(jar|exe|dll|class|zip)$') { [void]$State.Evidence.Add([pscustomobject]@{ Source='PcaSvc/Compatibility Assistant'; Path=$name }) } }
                }
                $amcacheRoot = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted'
                if (Test-Path -LiteralPath $amcacheRoot) {
                    $item = Get-Item -LiteralPath $amcacheRoot
                    foreach ($name in $item.GetValueNames()) { if ($name -match '(?i)\.(jar|exe|dll|class|zip)$') { [void]$State.Evidence.Add([pscustomobject]@{ Source='Amcache/Persisted'; Path=$name }) } }
                }
            } else {
                foreach ($key in @(Get-ChildItem -LiteralPath $entry.Path -Recurse -ErrorAction SilentlyContinue)) {
                    foreach ($name in $key.GetValueNames()) {
                        if ($name -match '(?i)\.(jar|exe|dll|class|zip|ps1|bat|cmd|vbs)$') { [void]$State.Evidence.Add([pscustomobject]@{ Source=$entry.Source; Key=$key.Name; Name=$name }) }
                    }
                }
            }
            $sourceCount++
        } catch { Add-ScanWarning $State $entry.Source $_.Exception.Message $entry.Path }
    }
    try {
        $userAssist = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
        foreach ($countKey in @(Get-ChildItem -LiteralPath $userAssist -Recurse -ErrorAction Stop | Where-Object PSChildName -eq 'Count')) {
            foreach ($name in $countKey.GetValueNames()) {
                $decoded = ConvertFrom-Rot13 $name
                if ($decoded -match '(?i)\.(jar|exe|dll|class|zip|ps1|bat|cmd|vbs)') { [void]$State.Evidence.Add([pscustomobject]@{ Source='UserAssist'; Name=$decoded; Key=$countKey.Name }) }
            }
        }
        $sourceCount++
    } catch { Add-ScanWarning $State 'UserAssist' $_.Exception.Message }
    Add-SourceStatus $State 'Registry Artifacts (Amcache/BAM/UserAssist/MRU)' ($sourceCount -gt 0) "$sourceCount collectors available"
}

function Get-RecentAndLinkEvidence {
    param($State)
    Write-Stage 'RECENT' 'Collecting LNK, Jump List, Recent Files, Recycle Bin and WER metadata...'
    $roots = @()
    if ($env:APPDATA) {
        $roots += (Join-Path $env:APPDATA 'Microsoft\Windows\Recent')
        $roots += (Join-Path $env:APPDATA 'Microsoft\Windows\Recent\AutomaticDestinations')
        $roots += (Join-Path $env:APPDATA 'Microsoft\Windows\Recent\CustomDestinations')
    }
    if ($env:LOCALAPPDATA) {
        $roots += (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER')
        $roots += (Join-Path $env:LOCALAPPDATA 'CrashDumps')
    }
    if ($env:SystemDrive) { $roots += (Join-Path $env:SystemDrive '$Recycle.Bin') }
    $count = 0
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue)) {
                if ($file.Name -match '(?i)\.(lnk|automaticDestinations-ms|customDestinations-ms|wer|dmp)$' -or $file.Name -like '$I*') {
                    $record = [ordered]@{ Source='Recent/LNK/JumpList/RecycleBin/WER'; Name=$file.Name; Path=$file.FullName; Size=$file.Length; ModifiedUtc=$file.LastWriteTimeUtc }
                    if ($file.Extension -ieq '.lnk') {
                        try {
                            $shell = New-Object -ComObject WScript.Shell
                            $shortcut = $shell.CreateShortcut($file.FullName)
                            $record.TargetPath = $shortcut.TargetPath; $record.Arguments = $shortcut.Arguments; $record.WorkingDirectory = $shortcut.WorkingDirectory
                            [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) | Out-Null
                        } catch { }
                    }
                    [void]$State.Evidence.Add([pscustomobject]$record); $count++
                }
            }
        } catch { Add-ScanWarning $State 'RECENT' $_.Exception.Message $root }
    }
    Add-SourceStatus $State 'Recent Files / LNK / Jump Lists / Recycle Bin / WER' $true "$count metadata records"
}

function Get-BrowserDownloadEvidence {
    param($State)
    Write-Stage 'BROWSER' 'Collecting browser download evidence and Zone.Identifier metadata...'
    $profiles = [ordered]@{}
    if ($env:LOCALAPPDATA) {
        $profiles['Chrome'] = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
        $profiles['Edge'] = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'
        $profiles['Brave'] = Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data'
        $profiles['Vivaldi'] = Join-Path $env:LOCALAPPDATA 'Vivaldi\User Data'
    }
    if ($env:APPDATA) {
        $profiles['Firefox'] = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
        $profiles['Opera'] = Join-Path $env:APPDATA 'Opera Software\Opera Stable'
        $profiles['Opera GX'] = Join-Path $env:APPDATA 'Opera Software\Opera GX Stable'
    }
    foreach ($browser in $profiles.Keys) {
        $root = $profiles[$browser]
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        try {
            foreach ($db in @(Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object Name -in @('History','places.sqlite'))) {
                [void]$State.Evidence.Add([pscustomobject][ordered]@{
                    Source='Browser Profile Database'; Browser=$browser; Path=$db.FullName; Size=$db.Length
                    ModifiedUtc=$db.LastWriteTimeUtc; Note='Database presence recorded read-only. URL evidence is collected from Zone.Identifier without opening locked SQLite databases.'
                })
            }
        } catch { Add-ScanWarning $State 'BROWSER' $_.Exception.Message $root }
    }
    $downloads = if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'Downloads' } else { '' }
    $count = 0
    if ($downloads -and (Test-Path -LiteralPath $downloads -PathType Container)) {
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $downloads -File -Recurse -Force -ErrorAction SilentlyContinue)) {
                try {
                    $zoneStream = @(Get-Item -LiteralPath $file.FullName -Stream 'Zone.Identifier' -ErrorAction Stop)[0]
                    if ($zoneStream) {
                        $zone = Get-ZoneIdentifier $file.FullName 'Zone.Identifier'
                        [void]$State.Evidence.Add([pscustomobject][ordered]@{
                            Source='Browser Downloads / Zone.Identifier'; Filename=$file.Name; URL=$zone.HostUrl
                            Referrer=$zone.ReferrerUrl; TargetPath=$file.FullName; DownloadTime=$file.CreationTimeUtc
                            Browser='Unknown'; CurrentFileExists=$true; ZoneId=$zone.ZoneId
                        })
                        $count++
                    }
                } catch { }
            }
        } catch { Add-ScanWarning $State 'BROWSER' $_.Exception.Message $downloads }
    }
    Add-SourceStatus $State 'Browser Downloads / Zone.Identifier' $true "$count Zone.Identifier download records"
    Add-SourceStatus $State 'Browser SQLite download tables' $false 'Pure PowerShell build records profile databases but does not decode SQLite tables; locked databases are never modified or copied.'
}

function Get-PowerShellForensics {
    param($State)
    Write-Stage 'POWERSHELL' 'Reading PSReadLine history and PowerShell Operational logs...'
    $count = 0
    $historyPaths = @()
    if ($env:APPDATA) {
        $historyPaths += (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
        $historyPaths += (Join-Path $env:APPDATA 'Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt')
    }
    foreach ($historyPath in @($historyPaths | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $historyPath -PathType Leaf)) { continue }
        try {
            $lineNumber = 0
            foreach ($line in [IO.File]::ReadLines($historyPath)) {
                $lineNumber++
                if ($line -match '(?i)javaw?|\.jar|\.dll|\.exe|loader|minecraft|agentpath|javaagent') {
                    [void]$State.Evidence.Add([pscustomobject]@{ Source='PSReadLine History'; Path=$historyPath; Line=$lineNumber; Command=$line }); $count++
                }
            }
        } catch { Add-ScanWarning $State 'POWERSHELL' $_.Exception.Message $historyPath }
    }
    try {
        $start = (Get-Date).AddDays(-30)
        $events = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=@(4103,4104); StartTime=$start } -ErrorAction Stop
        foreach ($event in $events) {
            if ($event.Message -match '(?i)javaw?|\.jar|\.dll|\.exe|loader|minecraft|agentpath|javaagent') {
                [void]$State.Evidence.Add([pscustomobject]@{ Source='PowerShell Operational'; EventId=$event.Id; TimeCreatedUtc=$event.TimeCreated.ToUniversalTime(); RecordId=$event.RecordId; Message=$event.Message }); $count++
            }
        }
        Add-SourceStatus $State 'PowerShell History / Operational 4103, 4104' $true "$count relevant records"
    } catch {
        Add-SourceStatus $State 'PowerShell Operational 4103, 4104' $false $_.Exception.Message
        Add-ScanWarning $State 'POWERSHELL' 'Operational log was unavailable; missing history is not cheat evidence.'
    }
}

function Get-WindowsEventEvidence {
    param($State)
    Write-Stage 'EVENTLOG' 'Reading audit-integrity and process-creation events...'
    if (-not $State.IsAdministrator) { Add-SourceStatus $State 'Security Event Log' $false 'Administrator rights required'; return }
    try {
        $start = (Get-Date).AddDays(-30)
        $events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=@(1102,4719,4688); StartTime=$start } -ErrorAction Stop
        foreach ($event in $events) {
            if ($event.Id -in @(1102,4719)) {
                [void]$State.Integrity.Add([pscustomobject]@{ Severity='WARNING'; Code="EVENT_$($event.Id)"; TimeCreatedUtc=$event.TimeCreated.ToUniversalTime(); Message='Security audit configuration/log integrity event observed; not DoomsDay evidence by itself.' })
            } elseif ($event.Message -match '(?i)javaw?|\.jar|\.dll|loader|minecraft|agentpath|javaagent') {
                [void]$State.Evidence.Add([pscustomobject]@{ Source='Security 4688'; EventId=4688; TimeCreatedUtc=$event.TimeCreated.ToUniversalTime(); RecordId=$event.RecordId; Message=$event.Message })
            }
        }
        Add-SourceStatus $State 'Security Event Log (1102/4719/4688)' $true ("{0} events" -f @($events).Count)
    } catch { Add-SourceStatus $State 'Security Event Log' $false $_.Exception.Message; Add-ScanWarning $State 'EVENTLOG' $_.Exception.Message }
}

function Get-AdditionalArtifactMetadata {
    param($State)
    Write-Stage 'ARTIFACT' 'Collecting SRUM, Amcache hive, ShimCache and crash metadata availability...'
    $paths = @(
        @{ Source='SRUM'; Path=(Join-Path $env:SystemRoot 'System32\sru\SRUDB.dat') },
        @{ Source='Amcache Hive'; Path=(Join-Path $env:SystemRoot 'AppCompat\Programs\Amcache.hve') },
        @{ Source='System Registry Hive / ShimCache'; Path=(Join-Path $env:SystemRoot 'System32\config\SYSTEM') }
    )
    foreach ($entry in $paths) {
        if (Test-Path -LiteralPath $entry.Path -PathType Leaf) {
            try {
                $item = Get-Item -LiteralPath $entry.Path -Force
                [void]$State.Evidence.Add([pscustomobject]@{ Source=$entry.Source; Path=$item.FullName; Size=$item.Length; ModifiedUtc=$item.LastWriteTimeUtc; Note='Source availability and metadata collected without modifying or copying the live database/hive.' })
                Add-SourceStatus $State $entry.Source $true 'Metadata available'
            } catch { Add-SourceStatus $State $entry.Source $false $_.Exception.Message }
        } else { Add-SourceStatus $State $entry.Source $false 'Source not present' }
    }
}

function Invoke-QuickScan {
    param($State)
    Write-Section 'QUICK SCAN'
    $roots = Get-MinecraftLocations
    if ($roots.Count -eq 0) { Add-ScanWarning $State 'DISCOVERY' 'No known Minecraft installation directory was found.' }
    else { Invoke-CandidateScan -Roots $roots -State $State }
    Invoke-RuntimeScan -State $State
}

function Get-DefaultAdsRoots {
    param([switch]$IncludeAppData)
    $roots = [System.Collections.ArrayList]::new()
    if ($env:USERPROFILE) {
        foreach ($name in @('Desktop','Downloads','Documents')) {
            $path = Join-Path $env:USERPROFILE $name
            if (Test-Path -LiteralPath $path -PathType Container) { [void]$roots.Add($path) }
        }
    }
    if ($env:TEMP -and (Test-Path -LiteralPath $env:TEMP -PathType Container)) { [void]$roots.Add($env:TEMP) }
    if ($IncludeAppData -and $env:LOCALAPPDATA) { [void]$roots.Add($env:LOCALAPPDATA) }
    if ($IncludeAppData -and $env:APPDATA) { [void]$roots.Add($env:APPDATA) }
    foreach ($path in @(Get-MinecraftLocations)) { [void]$roots.Add($path) }
    return @(Get-NormalizedScanRoots -Roots @($roots))
}

function Invoke-FullScan {
    param($State)
    Write-Section 'FULL FORENSIC SCAN'
    $roots = Get-MinecraftLocations
    if ($roots.Count -eq 0) { Add-ScanWarning $State 'DISCOVERY' 'No known Minecraft installation directory was found.' }
    else { Invoke-CandidateScan -Roots $roots -State $State -Full }
    Invoke-RuntimeScan -State $State
    Get-SysMainIntegrity -State $State
    Get-SechostIntegrity -State $State
    Get-UsnJournalEvidence -State $State
    Get-RegistryArtifactEvidence -State $State
    Get-RecentAndLinkEvidence -State $State
    Get-BrowserDownloadEvidence -State $State
    Get-PowerShellForensics -State $State
    Get-WindowsEventEvidence -State $State
    Get-AdditionalArtifactMetadata -State $State
    Invoke-AdsScan -Roots (Get-DefaultAdsRoots) -State $State -DeepScan
    Write-Stage 'CORRELATE' 'Building evidence chains...'
    Invoke-EvidenceCorrelation -State $State
}

function Invoke-EvidenceCorrelation {
    param($State)
    foreach ($finding in @($State.Findings)) {
        $name = [regex]::Escape([string]$finding.CurrentName)
        if (-not $name) { continue }
        $related = @($State.Evidence | Where-Object { ($_ | ConvertTo-Json -Compress -Depth 5) -match $name })
        foreach ($evidence in $related) {
            $source = [string]$evidence.Source
            if ($source -and $source -notin $finding.EvidenceSources) { $finding.EvidenceSources += $source }
        }
        if ($related.Count -gt 0) { $finding.Evidence += $related }
    }
}

function Update-DoomsDaySignatures {
    Write-Stage 'UPDATE' 'Downloading JSON signature data only; no remote code will be executed.'
    try {
        $response = Invoke-WebRequest -Uri $script:SignatureUrl -UseBasicParsing -TimeoutSec 20 -Headers @{ Accept='application/json' }
        if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode)" }
        $contentType = [string]$response.Headers['Content-Type']
        if ($contentType -and $contentType -notmatch '(?i)application/json|text/plain|octet-stream') { throw "Unexpected content type: $contentType" }
        if ($response.Content.Length -gt 5242880) { throw 'Signature JSON exceeds the 5 MiB safety limit.' }
        $candidate = $response.Content | ConvertFrom-Json
        if ($candidate.schemaVersion -ne 1 -or $candidate.family -ne 'DoomsDay') { throw 'Downloaded signature schema/family is invalid.' }
        $temporary = "$script:SignaturePath.download"
        [IO.File]::WriteAllText($temporary, [string]$response.Content, [Text.UTF8Encoding]::new($false))
        $old = $script:SignaturePath; $script:SignaturePath = $temporary
        try { Import-DoomsDaySignatures | Out-Null }
        finally { $script:SignaturePath = $old }
        Move-Item -LiteralPath $temporary -Destination $script:SignaturePath -Force
        $script:Signatures = $candidate
        Write-Color '[OK] Signature database updated and validated.' Green
        return $true
    } catch {
        Write-Color "[WARNING] Signature update failed: $($_.Exception.Message)" Yellow
        return $false
    }
}

function Show-FindingDetail {
    param($Finding)
    $title = switch ($Finding.Verdict) {
        'DETECTED' { 'DOOMSDAY DETECTED' }
        'DELETED TRACE' { 'DELETED TRACE' }
        default { $Finding.Verdict }
    }
    $color = switch ($Finding.Verdict) {
        'DETECTED' { [ConsoleColor]::Red }
        'HIGH CONFIDENCE' { [ConsoleColor]::Yellow }
        'SUSPICIOUS' { [ConsoleColor]::Yellow }
        'INCONCLUSIVE' { [ConsoleColor]::Yellow }
        default { [ConsoleColor]::Gray }
    }
    Write-Section $title $color
    $rows = [ordered]@{
        'Finding ID'=$Finding.FindingId; 'Family'=$Finding.Family; 'Current Filename'=$Finding.CurrentName
        'Suspected Original Filename'=$(if ($Finding.OriginalName) {$Finding.OriginalName} else {'Unknown'})
        'Full Path'=$Finding.Path; 'Extension'=$Finding.Extension; 'Actual File Type'=$Finding.ActualFileType
        'Extension Mismatch'=$Finding.ExtensionMismatch; 'Detection Category'=$Finding.Category; 'Status'=$Finding.Status
        'Loader Type'=$Finding.LoaderType; 'Minecraft Version'=$Finding.MinecraftVersion; 'Launcher'=$Finding.Launcher
        'File Size'=$Finding.Size; 'SHA-256'=$(if ($Finding.SHA256) {$Finding.SHA256} else {'UNAVAILABLE'})
        'Created UTC'=$Finding.CreatedUtc; 'Modified UTC'=$Finding.ModifiedUtc; 'Last Access UTC'=$Finding.LastAccessUtc
        'Execution Evidence'=(@($Finding.ExecutionEvidence) -join '; '); 'Evidence Sources'=(@($Finding.EvidenceSources) -join ', ')
        'Confidence'="$($Finding.Confidence)/100"; 'Verification Status'=$Finding.VerificationStatus; 'Verdict'=$Finding.Verdict
    }
    foreach ($key in $rows.Keys) { Write-Color (('{0,-30}: {1}' -f $key, $rows[$key])) $color }
    Write-Color 'Detection Reasons:' $color
    foreach ($reason in @($Finding.DetectionReasons)) { Write-Color "  [+] $reason" $color }
}

function Show-FindingsTable {
    param($State)
    if ($null -eq $State -or @($State.Findings).Count -eq 0) { return }
    Write-Section 'FINDINGS TABLE'
    Write-Color ('{0,-14} | {1,4} | {2,-11} | {3,-8} | {4,-15} | {5,-5} | {6,-30} | {7}' -f 'STATUS','CONF','VERIFY','FAMILY','TYPE','EXT','FILE','SOURCE') Magenta
    foreach ($finding in @($State.Findings | Where-Object { $null -ne $_ } | Sort-Object @{Expression='Confidence';Descending=$true})) {
        $status = if ($finding.Verdict -eq 'HIGH CONFIDENCE') {'HIGH'} elseif ($finding.Verdict -eq 'DELETED TRACE') {'DELETED'} else {$finding.Verdict}
        $line = '{0,-14} | {1,4} | {2,-11} | {3,-8} | {4,-15} | {5,-5} | {6,-30} | {7}' -f $status,$finding.Confidence,$finding.VerificationStatus,$finding.Family,$finding.Category,$finding.Extension,$finding.CurrentName,$finding.Source
        $color = if ($finding.Verdict -eq 'DETECTED') {'Red'} elseif ($finding.Verdict -in @('HIGH CONFIDENCE','SUSPICIOUS','INCONCLUSIVE','REVIEW')) {'Yellow'} else {'Gray'}
        Write-Color $line $color
    }
}

function Complete-ScanState {
    param($State)
    if ($null -eq $State) { throw 'Scan state is unavailable.' }
    if ($null -eq $State.Findings) { $State.Findings = [System.Collections.ArrayList]::new() }
    if ($null -eq $State.Warnings) { $State.Warnings = [System.Collections.ArrayList]::new() }
    if ($null -eq $State.UnavailableSources) { $State.UnavailableSources = [System.Collections.ArrayList]::new() }
    $State.CompletedUtc = [DateTime]::UtcNow
    $State.Statistics = [ordered]@{
        DurationSeconds = [Math]::Round(($State.CompletedUtc - $State.StartedUtc).TotalSeconds, 2)
        DoomsDayDetections = @($State.Findings | Where-Object Verdict -eq 'DETECTED').Count
        HighConfidenceFindings = @($State.Findings | Where-Object Verdict -eq 'HIGH CONFIDENCE').Count
        SuspiciousFindings = @($State.Findings | Where-Object Verdict -eq 'SUSPICIOUS').Count
        DeletedTraces = @($State.Findings | Where-Object { $_.Status -eq 'DELETED' -or $_.Verdict -eq 'DELETED TRACE' }).Count
        AdsFindings = $State.AdsFindings
        Warnings = $State.Warnings.Count
    }
    $script:LastReport = $State
}

function Show-ScanComplete {
    param($State)
    if ($null -eq $State) { throw 'Scan state is unavailable.' }
    if ($null -eq $State.CompletedUtc) { Complete-ScanState $State }
    Write-Section 'SCAN COMPLETE'
    $rows = [ordered]@{
        'Total indexes extracted'=$State.TotalIndexesExtracted; 'Candidate files'=$State.CandidateFiles
        'Files found'=$State.FilesFound; 'Files fully scanned'=$State.FilesFullyScanned; 'Files skipped'=$State.FilesSkipped
        'Corrupted/unreadable'=$State.CorruptedUnreadable; 'DoomsDay detections'=$State.Statistics.DoomsDayDetections
        'High confidence findings'=$State.Statistics.HighConfidenceFindings; 'Suspicious findings'=$State.Statistics.SuspiciousFindings
        'Deleted traces'=$State.Statistics.DeletedTraces; 'ADS findings'=$State.Statistics.AdsFindings
    }
    foreach ($key in $rows.Keys) { Write-Color (('{0,-26}: {1}' -f $key, $rows[$key])) Magenta }
    Write-Host ''
    if ($State.FilesSkipped -gt 0 -or $State.CorruptedUnreadable -gt 0 -or $State.UnavailableSources.Count -gt 0) {
        Write-Color '[INCONCLUSIVE]' Yellow
        Write-Color 'Some candidate artifacts or evidence sources could not be fully analyzed.' Yellow
    } elseif ($State.Statistics.DoomsDayDetections -gt 0) {
        Write-Color '[DETECTED]' Red
        Write-Color 'Verified DoomsDay-specific evidence was found. Review every evidence field before action.' Red
    } elseif ($State.Statistics.HighConfidenceFindings -gt 0 -or $State.Statistics.SuspiciousFindings -gt 0) {
        Write-Color '[MANUAL REVIEW REQUIRED]' Yellow
        Write-Color 'No finding met the strict DETECTED rule, but reviewable indicators were found.' Yellow
    } else {
        Write-Color '[NO EVIDENCE FOUND]' Green
        Write-Color 'No DoomsDay indicators were detected in the evidence sources that were successfully analyzed.' Green
    }
    Show-FindingsTable $State
    foreach ($finding in @($State.Findings | Where-Object { $null -ne $_ -and $_.Verdict -in @('DETECTED','HIGH CONFIDENCE','SUSPICIOUS','INCONCLUSIVE','DELETED TRACE','RUNTIME TRACE') })) { Show-FindingDetail $finding }
}

function Convert-ReportToText {
    param($State)
    $builder = [Text.StringBuilder]::new()
    [void]$builder.AppendLine('=' * 60); [void]$builder.AppendLine('REVEAL SCREENSHARE - DOOMSDAY FINDER REPORT'); [void]$builder.AppendLine('=' * 60)
    [void]$builder.AppendLine("Tool Version: $($State.ToolVersion)")
    [void]$builder.AppendLine("Scan ID: $($State.ScanId)")
    [void]$builder.AppendLine("Mode: $($State.Mode)")
    [void]$builder.AppendLine("Started UTC: $(ConvertTo-SafeDateString $State.StartedUtc)")
    [void]$builder.AppendLine("Completed UTC: $(ConvertTo-SafeDateString $State.CompletedUtc)")
    [void]$builder.AppendLine("Administrator: $($State.IsAdministrator)")
    [void]$builder.AppendLine("Candidates: $($State.CandidateFiles)")
    [void]$builder.AppendLine("Fully scanned: $($State.FilesFullyScanned)")
    [void]$builder.AppendLine("Skipped: $($State.FilesSkipped)")
    [void]$builder.AppendLine("Corrupted/unreadable: $($State.CorruptedUnreadable)")
    [void]$builder.AppendLine('')
    foreach ($finding in @($State.Findings | Where-Object { $null -ne $_ })) {
        [void]$builder.AppendLine('=' * 60); [void]$builder.AppendLine("$($finding.Verdict) - $($finding.FindingId)"); [void]$builder.AppendLine('=' * 60)
        foreach ($property in $finding.PSObject.Properties) {
            if ($property.Name -eq 'Evidence') { continue }
            $value = if ($property.Value -is [System.Collections.IEnumerable] -and $property.Value -isnot [string]) { @($property.Value) -join '; ' } else { $property.Value }
            [void]$builder.AppendLine("$($property.Name): $value")
        }
        [void]$builder.AppendLine('')
    }
    [void]$builder.AppendLine('LIMITATION: Confidence is an internal evidence weight, not a statistical probability.')
    [void]$builder.AppendLine('A no-evidence result does not prove that the computer is clean.')
    return $builder.ToString()
}

function Export-ScanReport {
    param($State = $script:LastReport)
    if ($null -eq $State) { Write-Color '[WARNING] No completed scan is available to export.' Yellow; return $null }
    try {
        if ($null -eq $State.CompletedUtc) { Complete-ScanState $State }
        if (-not (Test-Path -LiteralPath $script:ReportDirectory -PathType Container)) {
            try { New-Item -ItemType Directory -Path $script:ReportDirectory -Force | Out-Null }
            catch {
                $fallbackRoot = if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'Documents\DoomsDayFinder' } else { Join-Path ([IO.Path]::GetTempPath()) 'DoomsDayFinder' }
                $script:ReportDirectory = Join-Path $fallbackRoot 'Reports'
                New-Item -ItemType Directory -Path $script:ReportDirectory -Force | Out-Null
                Write-Color "[WARNING] Project folder was not writable. Reports will be saved to $script:ReportDirectory" Yellow
            }
        }
        $stamp = ConvertTo-SafeDateString $State.CompletedUtc 'yyyyMMdd_HHmmss'
        if ($stamp -eq 'UNAVAILABLE') { $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd_HHmmss') }
        $base = Join-Path $script:ReportDirectory "DoomsDayFinder_Report_$stamp"
        $jsonPath = "$base.json"; $textPath = "$base.txt"
        $json = $State | ConvertTo-Json -Depth 20
        [IO.File]::WriteAllText($jsonPath, $json, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($textPath, (Convert-ReportToText $State), [Text.UTF8Encoding]::new($false))
        Write-Color "[REPORT] $jsonPath" Magenta; Write-Color "[REPORT] $textPath" Magenta
        return [pscustomobject]@{ Json=$jsonPath; Text=$textPath }
    } catch {
        Write-Color "[WARNING] The scan completed, but the report could not be exported: $($_.Exception.Message)" Yellow
        return $null
    }
}

function Invoke-BuiltInSelfTest {
    Write-Section 'BUILT-IN SELF TEST'
    $failures = [System.Collections.ArrayList]::new()
    try { if (-not (Test-GenericIndicator 'Minecraft')) { [void]$failures.Add('Generic blacklist') } } catch { [void]$failures.Add($_.Exception.Message) }
    try { if ((Get-StringSha256 'abc') -ne 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD') { [void]$failures.Add('SHA-256') } } catch { [void]$failures.Add($_.Exception.Message) }
    try {
        $stream = [IO.MemoryStream]::new([byte[]](0x00,0xCA,0xFE,0xBA,0xBE,0x00))
        $magic = Get-MagicInfoFromStream $stream '.class'; $stream.Dispose()
        if ($magic.ActualType -ne 'Java Class') { [void]$failures.Add('Magic bytes') }
    } catch { [void]$failures.Add($_.Exception.Message) }
    try {
        $decision = Get-Decision @() 99 $false
        if ($decision.Verdict -eq 'DETECTED') { [void]$failures.Add('Score-only DETECTED guard') }
    } catch { [void]$failures.Add($_.Exception.Message) }
    if ($failures.Count -eq 0) { Write-Color '[PASS] Core safety invariants passed.' Green; return $true }
    foreach ($failure in $failures) { Write-Color "[FAIL] $failure" Red }
    return $false
}

function Invoke-ScanMode {
    param([string]$SelectedMode, [string]$SelectedPath = '', [switch]$DeepAds)
    $script:InspectionCache = @{}
    $state = New-ScanState $SelectedMode
    if (-not $state.IsAdministrator) { Write-Color '[LIMITED MODE] Administrator-only forensic sources will be skipped.' Yellow }
    switch ($SelectedMode) {
        'Quick' { Invoke-QuickScan $state }
        'Full' { Invoke-FullScan $state }
        'File' {
            if (-not $SelectedPath) { throw 'A file path is required.' }
            Write-Section 'FILE SCAN'; Invoke-FileInspection -LiteralPath $SelectedPath -State $state -AlwaysRecord | Out-Null
        }
        'ADS' {
            Write-Section 'DEEP ADS SCAN'; $roots = if ($SelectedPath) { @($SelectedPath) } else { Get-DefaultAdsRoots -IncludeAppData }
            Invoke-AdsScan -Roots $roots -State $state -DeepScan
        }
        'Runtime' { Write-Section 'RUNTIME SCAN'; Invoke-RuntimeScan $state }
        default { throw "Unsupported scan mode: $SelectedMode" }
    }
    Complete-ScanState $state
    Show-ScanComplete $state
    Export-ScanReport $state | Out-Null
    return $state
}

function Show-MainMenu {
    try { Clear-Host } catch { }
    Show-RevealBanner
    Write-Color '[1] Quick Scan' Magenta
    Write-Color '[2] Full Forensic Scan' Magenta
    Write-Color '[3] Scan File' Magenta
    Write-Color '[4] Deep ADS Scan' Magenta
    Write-Color '[5] Runtime Scan' Magenta
    Write-Color '[6] Update Signatures' Magenta
    Write-Color '[7] Export Last Report' Magenta
    Write-Color '[0] Exit' Magenta
}

function Start-DoomsDayFinderMenu {
    do {
        Show-MainMenu
        $choice = Read-Host 'Select'
        try {
            switch ($choice) {
                '1' { Invoke-ScanMode 'Quick' | Out-Null }
                '2' { Invoke-ScanMode 'Full' | Out-Null }
                '3' { $file = (Read-Host 'Enter the full path of the file').Trim('"'); Invoke-ScanMode 'File' $file | Out-Null }
                '4' { $root = (Read-Host 'Optional root path (press Enter for default locations)').Trim('"'); Invoke-ScanMode 'ADS' $root -DeepAds | Out-Null }
                '5' { Invoke-ScanMode 'Runtime' | Out-Null }
                '6' { Update-DoomsDaySignatures | Out-Null }
                '7' { Export-ScanReport | Out-Null }
                '0' { return }
                default { Write-Color '[WARNING] Invalid selection.' Yellow }
            }
        } catch { Write-Color "[ERROR] $($_.Exception.Message)" Red }
        if (-not $NoPause -and $choice -ne '0') { [void](Read-Host 'Press Enter to return to the main menu') }
    } while ($true)
}

if ($MyInvocation.InvocationName -ne '.') {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Write-Color '[FATAL] DoomsDay Finder supports Windows 10/11 only.' Red
        exit 5
    }
    if ($Mode -ne 'Menu') { Show-RevealBanner }
    try { Import-DoomsDaySignatures | Out-Null }
    catch { Write-Color "[FATAL] Signature database validation failed: $($_.Exception.Message)" Red; exit 2 }
    try {
        switch ($Mode) {
            'Menu' { Start-DoomsDayFinderMenu }
            'Update' { if (-not (Update-DoomsDaySignatures)) { exit 3 } }
            'Export' { Export-ScanReport | Out-Null }
            'SelfTest' { if (-not (Invoke-BuiltInSelfTest)) { exit 4 } }
            default {
                $result = Invoke-ScanMode -SelectedMode $Mode -SelectedPath $Path -DeepAds:$Deep
                if ($PassThru) { $result }
            }
        }
    } catch {
        Write-Color "[ERROR] $($_.Exception.Message)" Red
        if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) {
            Write-Color ("[ERROR] Script line: {0}" -f $_.InvocationInfo.ScriptLineNumber) Red
        }
        if ($_.ScriptStackTrace) { Write-Color ("[ERROR] Stack: {0}" -f $_.ScriptStackTrace) DarkRed }
        exit 1
    }
}
