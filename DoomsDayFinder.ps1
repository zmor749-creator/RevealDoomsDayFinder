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
    [ValidateSet('Menu','Fast','Quick','Full','File','ADS','Runtime','Update','Export','SelfTest')]
    [string]$Mode = 'Fast',
    [string]$Path,
    [switch]$Deep,
    [switch]$NoPause,
    [switch]$PassThru,
    [ValidateRange(1,8)][int]$Workers = [Math]::Max(1,[Math]::Min(4,[Environment]::ProcessorCount))
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

$script:ToolVersion = '1.4.0'
$script:AnalysisProfile = 'Detailed'
$script:PrefetchNativeApi = $null
$script:ScannerScriptPath = $MyInvocation.MyCommand.Path
$script:WorkerCount = $Workers
$script:IsWorker = $false
$script:WorkerCancellation = $null
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
$script:ProgressWidth = 0
$script:ProgressLastUpdate = [DateTime]::MinValue
$script:ProgressCurrent = 0
$script:ProgressTotal = 0
$script:ConsoleNativeApi = $null
$script:ContentPlanCache = @{}
$script:ClassIndexCache = @{}
$script:ClassIndexCacheOrder = [Collections.Generic.Queue[string]]::new()
$script:ClassIndexCacheBytes = 0L
$script:ClassCacheHits = 0L
$script:ClassCacheMisses = 0L
$script:FileInventory = $null
$script:ScanClock = $null
$script:PhaseClock = $null
$script:ActivePhase = ''
$script:PhaseTimings = [Collections.ArrayList]::new()
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
        AnalysisProfile = $script:AnalysisProfile
        Scope = ''
        StartedUtc = [DateTime]::UtcNow
        CompletedUtc = $null
        IsAdministrator = Test-IsAdministrator
        SignatureCount = @(Get-SignaturesByType @('SHA256','Class','Package','Resource','Manifest','ModId','OriginalFilename','String','ByteSequence','StructuralFingerprint','EmbeddedNative','LoaderIndicator','RuntimeIndicator')).Count
        VerifiedSignatureCount = @($script:Signatures.signatures | Where-Object { $_.PSObject.Properties['Verified'] -and $_.Verified -is [bool] -and $_.Verified -and (-not $_.PSObject.Properties['Enabled'] -or $_.Enabled) }).Count
        TotalIndexesExtracted = 0
        CandidateFiles = 0
        FilesFound = 0
        FilesFullyScanned = 0
        FilesSkipped = 0
        DiscoveredFiles = 0
        PartialFiles = 0
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
        Performance = [ordered]@{ ElapsedSeconds=0.0; PhaseTimings=@(); ClassCacheHits=0L; ClassCacheMisses=0L; InventoryFiles=0; Workers=1; ParallelJobs=0; PeakActive=0; WorkerDiagnostics=@() }
    }
}

function Test-IsAdministrator {
    if ($script:IsWorker) { return $script:WorkerAdministrator }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $false }
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Write-Color {
    param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Magenta)
    if ($script:IsWorker) { return }
    if ($script:ProgressWidth -gt 0) {
        Write-Host ("`r" + (' ' * $script:ProgressWidth) + "`r") -NoNewline
        $script:ProgressWidth = 0
    }
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
    if ($script:IsWorker) { return }
    $safeStage = if ([string]::IsNullOrWhiteSpace($Stage)) { 'SCAN' } else { $Stage.ToUpperInvariant() }
    if ($null -ne $script:PhaseClock -and $safeStage -ne $script:ActivePhase) {
        [void]$script:PhaseTimings.Add([pscustomobject]@{ Phase=$script:ActivePhase; Seconds=[Math]::Round($script:PhaseClock.Elapsed.TotalSeconds,3) })
        $script:PhaseClock.Restart(); $script:ActivePhase=$safeStage
    }
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

function Format-ScanProgressLine {
    param([string]$Status, [int]$Current, [int]$Total)
    $elapsed=if ($null -ne $script:ScanClock) { ' | '+$script:ScanClock.Elapsed.ToString('hh\:mm\:ss') } else { '' }
    if ($Total -le 0) { return ('[INDEX] {0:N0} files{1} | {2}' -f $Current,$elapsed,$Status) }
    $percent = [Math]::Min(100, [Math]::Floor(($Current * 100.0) / $Total))
    return ('[SCAN] {0:N0} / {1:N0} | {2}%{3} | {4}' -f $Current,$Total,$percent,$elapsed,$Status)
}

function Write-ScanProgress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$Current,
        [int]$Total,
        [switch]$Completed
    )
    if ($script:IsWorker) { return }
    if ($Completed) {
        if ($script:ProgressWidth -gt 0) { Write-Host ("`r" + (' ' * $script:ProgressWidth) + "`r") -NoNewline; $script:ProgressWidth=0 }
        $script:ProgressLastUpdate=[DateTime]::MinValue
        return
    }
    $finalUpdate = $Total -gt 0 -and $Current -ge $Total
    if (-not $finalUpdate -and (([DateTime]::UtcNow-$script:ProgressLastUpdate).TotalMilliseconds -lt 150)) { return }
    $script:ProgressLastUpdate=[DateTime]::UtcNow
    $line = Format-ScanProgressLine -Status $Status -Current $Current -Total $Total
    $width=100
    try { if ($Host.UI.RawUI.WindowSize.Width -gt 10) { $width=$Host.UI.RawUI.WindowSize.Width-1 } } catch { }
    if ($line.Length -gt $width) { $line=$line.Substring(0,$width) }
    Write-Host ("`r" + $line.PadRight([Math]::Min($width,[Math]::Max($script:ProgressWidth,$line.Length)))) -NoNewline -ForegroundColor Magenta
    $script:ProgressWidth=$line.Length
}

function Get-ScanConsoleMode {
    param([uint32]$OriginalMode)
    # Preserve CTRL+C, line input and all other flags. Only disable QuickEdit.
    return [uint32](($OriginalMode -bor [uint32]0x80) -band ([uint32]::MaxValue -bxor [uint32]0x40))
}

function Get-ConsoleNativeApi {
    if ($null -ne $script:ConsoleNativeApi) { return $script:ConsoleNativeApi }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $null }
    # Bind three documented Windows console APIs in memory using PowerShell/.NET.
    # No C# source, compiler, downloaded code, registry writes or payload execution.
    $name=[Reflection.AssemblyName]::new('RevealConsole_'+[guid]::NewGuid().ToString('N'))
    $assembly=[Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($name,[Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module=$assembly.DefineDynamicModule($name.Name)
    $type=$module.DefineType('RevealConsoleApi',([Reflection.TypeAttributes]::Public -bor [Reflection.TypeAttributes]::Abstract -bor [Reflection.TypeAttributes]::Sealed))
    $attributes=[Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl
    $library=Join-Path ([Environment]::SystemDirectory) 'kernel32.dll'
    $definitions=@(
        @{ Name='GetStdHandle'; Return=[IntPtr]; Parameters=[Type[]]@([int]) },
        @{ Name='GetConsoleMode'; Return=[int]; Parameters=[Type[]]@([IntPtr],[uint32].MakeByRefType()) },
        @{ Name='SetConsoleMode'; Return=[int]; Parameters=[Type[]]@([IntPtr],[uint32]) }
    )
    foreach ($definition in $definitions) {
        $method=$type.DefinePInvokeMethod($definition.Name,$library,$definition.Name,$attributes,
            [Reflection.CallingConventions]::Standard,$definition.Return,$definition.Parameters,
            [Runtime.InteropServices.CallingConvention]::Winapi,[Runtime.InteropServices.CharSet]::Ansi)
        $method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    }
    $script:ConsoleNativeApi=$type.CreateType()
    return $script:ConsoleNativeApi
}

function Enter-ScanConsoleMode {
    $guard=[pscustomobject]@{ Changed=$false; OriginalMode=[uint32]0; Handle=[IntPtr]::Zero; Api=$null; Warning='' }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $guard }
    try {
        $api=Get-ConsoleNativeApi
        $handle=$api::GetStdHandle(-10)
        [uint32]$original=0
        # Redirected stdin, ISE and non-console hosts may not expose a console.
        if ($api::GetConsoleMode($handle,[ref]$original) -eq 0) { return $guard }
        $scanMode=Get-ScanConsoleMode $original
        if ($scanMode -eq $original) { return $guard }
        if ($api::SetConsoleMode($handle,$scanMode) -eq 0) { throw 'Console mode change was not accepted.' }
        $guard.OriginalMode=$original; $guard.Handle=$handle; $guard.Api=$api; $guard.Changed=$true
    } catch {
        $guard.Warning='QuickEdit protection unavailable. If text selection pauses this console, press Esc to resume. '+$_.Exception.Message
    }
    return $guard
}

function Exit-ScanConsoleMode {
    param($Guard)
    if ($null -eq $Guard -or -not $Guard.Changed) { return }
    try {
        $api=$Guard.Api
        if ($api::SetConsoleMode($Guard.Handle,$Guard.OriginalMode) -eq 0) { throw 'Console mode restoration was not accepted.' }
        $Guard.Changed=$false
    } catch { Write-Color ('[WARNING] Could not restore console selection mode: '+$_.Exception.Message) Yellow }
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
    $record = [pscustomobject]@{ Source = $Source; Detail = $Detail }
    if ($Available) { [void]$State.AnalyzedSources.Add($record) }
    else { [void]$State.UnavailableSources.Add($record) }
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
        # Same unverified research data as the distributed JSON. No verified family hashes are invented.
        $raw = @'
{
  "schemaVersion": 1,
  "family": "DoomsDay",
  "databaseVersion": "2026-09-01-community-research",
  "generatedUtc": "2026-09-01T00:00:00Z",
  "notes": "Community byte patterns have not been validated against authentic DoomsDay samples. They can produce review findings but cannot authorize DETECTED. Overlapping patterns share one independence group. No detection-rate claim is supported.",
  "signatures": [
    {
      "ID": "COMMUNITY-ZEDOON-BYTES-1",
      "Type": "ByteSequence",
      "Value": "6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A160C14005C6588B800",
      "Source": "https://github.com/zedoonvm1/powershell-scripts/blob/main/DoomsDayDetector.ps1",
      "Version": "upstream-observed-2026-09-01",
      "Confidence": 20,
      "Specificity": "Medium",
      "LastUpdated": "2026-09-01",
      "Verified": false,
      "IndependenceGroup": "community-loader-bytecode-unvalidated",
      "Enabled": true
    },
    {
      "ID": "COMMUNITY-ZEDOON-BYTES-2",
      "Type": "ByteSequence",
      "Value": "0C1504851D85160A6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A16",
      "Source": "https://github.com/zedoonvm1/powershell-scripts/blob/main/DoomsDayDetector.ps1",
      "Version": "upstream-observed-2026-09-01",
      "Confidence": 20,
      "Specificity": "Medium",
      "LastUpdated": "2026-09-01",
      "Verified": false,
      "IndependenceGroup": "community-loader-bytecode-unvalidated",
      "Enabled": true
    },
    {
      "ID": "COMMUNITY-ZEDOON-BYTES-3",
      "Type": "ByteSequence",
      "Value": "5910071088544C2A2BB8004D3B033DA7000A2B1C03548402011C1008A1FFF61A9E000C1A110800A2000503AC04AC00000000000A0005004E000101FA000001D3",
      "Source": "https://github.com/zedoonvm1/powershell-scripts/blob/main/DoomsDayDetector.ps1",
      "Version": "upstream-observed-2026-09-01",
      "Confidence": 20,
      "Specificity": "Medium",
      "LastUpdated": "2026-09-01",
      "Verified": false,
      "IndependenceGroup": "community-loader-bytecode-unvalidated",
      "Enabled": true
    }
  ],
  "knownCleanHashes": []
}
'@
        Write-Color '[WARNING] Local signature JSON not found; embedded unverified community patterns loaded. DETECTED remains disabled.' Yellow
    } else {
        $raw = Get-Content -LiteralPath $script:SignaturePath -Raw -Encoding UTF8
    }
    $db = $raw | ConvertFrom-Json
    if ($null -eq $db.schemaVersion -or $db.schemaVersion -ne 1) {
        throw 'Unsupported signature database schema.'
    }
    if ($db.family -ne 'DoomsDay') { throw 'Signature database family must be DoomsDay.' }
    $ids=@{}
    foreach ($sig in (ConvertTo-SafeArray $db.signatures)) {
        foreach ($required in @('ID','Type','Value','Source','Version','Confidence','Specificity','LastUpdated')) {
            if ($null -eq $sig.PSObject.Properties[$required] -or [string]::IsNullOrWhiteSpace([string]$sig.$required)) {
                throw "Invalid signature: required field '$required' is missing."
            }
        }
        if ($ids.ContainsKey([string]$sig.ID)) { throw 'Duplicate signature ID.' }; $ids[[string]$sig.ID]=$true
        if ($sig.Type -notin @('SHA256','Class','Package','Resource','Manifest','ModId','OriginalFilename','String','ByteSequence','StructuralFingerprint','EmbeddedNative','LoaderIndicator','RuntimeIndicator')) { throw "Unsupported signature type: $($sig.Type)" }
        if ($sig.Specificity -notin @('Low','Medium','High','VeryHigh','Verified') -or [int]$sig.Confidence -lt 0 -or [int]$sig.Confidence -gt 100) { throw 'Invalid signature weight/specificity.' }
        if ($sig.PSObject.Properties['Verified'] -and $sig.Verified -isnot [bool]) { throw 'Verified must be a JSON boolean.' }
        if ($sig.PSObject.Properties['Enabled'] -and $sig.Enabled -isnot [bool]) { throw 'Enabled must be a JSON boolean.' }
        if ($sig.Type -in @('SHA256','StructuralFingerprint') -and $sig.Value -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Invalid SHA-256 fingerprint.' }
        if ($sig.Type -eq 'ByteSequence' -and ($sig.Value -notmatch '^(?:[A-Fa-f0-9]{2}\s*)+$' -or $sig.Value.Length -gt 131072)) { throw 'Invalid byte sequence.' }
        if ($sig.PSObject.Properties['Verified'] -and $sig.Verified) {
            if ($sig.PSObject.Properties['MatchMode'] -and $sig.MatchMode -in @('Regex','Wildcard')) { throw 'Verified patterns cannot use unbounded regex or wildcard matching.' }
            if ($sig.Type -eq 'ByteSequence' -and ($sig.Value -replace '\s','').Length -lt 32) { throw 'Verified byte sequence is too short.' }
            if ($sig.Type -ne 'SHA256' -and (-not $sig.PSObject.Properties['IndependenceGroup'] -or -not $sig.IndependenceGroup)) { throw 'Verified non-hash signatures require a reviewed independence group.' }
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
    return @($script:Signatures.knownCleanHashes | Where-Object {
        [string]$_.SHA256 -eq $SHA256
    }).Count -gt 0
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
    $stream = Open-ReadOnlyEvidenceStream $LiteralPath
    try { return Get-MagicInfoFromStream -Stream $stream -DisplayedExtension ([IO.Path]::GetExtension($LiteralPath)) }
    finally { $stream.Dispose() }
}

function Open-ReadOnlyEvidenceStream {
    param([string]$LiteralPath)
    $colon=$LiteralPath.IndexOf(':', [Math]::Min(2,$LiteralPath.Length))
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and $colon -ge 2) {
        $basePath=$LiteralPath.Substring(0,$colon); $streamName=$LiteralPath.Substring($colon+1)
        $information=Get-Item -LiteralPath $basePath -Stream $streamName -ErrorAction Stop
        if ([long]$information.Length -gt $script:Limits.MaximumNestedEntryBytes) { throw [IO.InvalidDataException]::new('ADS exceeds the 64 MiB in-memory provider safety budget.') }
        $memory=[IO.MemoryStream]::new()
        try {
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                Get-Content -LiteralPath $basePath -Stream $streamName -AsByteStream -ReadCount 65536 -ErrorAction Stop | ForEach-Object { $chunk=[byte[]]$_; if ($memory.Length+$chunk.Length -gt $script:Limits.MaximumNestedEntryBytes) { throw 'ADS changed beyond safety budget.' }; $memory.Write($chunk,0,$chunk.Length) }
            } else {
                Get-Content -LiteralPath $basePath -Stream $streamName -Encoding Byte -ReadCount 65536 -ErrorAction Stop | ForEach-Object { $chunk=[byte[]]$_; if ($memory.Length+$chunk.Length -gt $script:Limits.MaximumNestedEntryBytes) { throw 'ADS changed beyond safety budget.' }; $memory.Write($chunk,0,$chunk.Length) }
            }
            if ($memory.Length -ne [long]$information.Length) { throw 'ADS length changed during read.' }
            $memory.Position=0
            return ,$memory
        } catch { $memory.Dispose(); throw }
    }
    return [IO.File]::Open($LiteralPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
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

function Get-ContentScanPlan {
    param([object[]]$Signatures=@())
    $keyParts=[Collections.Generic.List[string]]::new()
    foreach ($signature in $Signatures) {
        foreach ($value in @([string]$signature.ID,[string]$signature.Type,[string]$signature.Value)) { $keyParts.Add($value.Length.ToString()+':'+$value) }
    }
    $key=[string]::Join('|',$keyParts.ToArray())
    if ($script:ContentPlanCache.ContainsKey($key)) { return $script:ContentPlanCache[$key] }
    $encoding = [Text.Encoding]::GetEncoding(28591)
    $patterns = [Collections.Generic.List[object]]::new()
    $overlap = 0
    $signatureIndex=0
    foreach ($signature in $Signatures) {
        $needles = @()
        if ($signature.Type -eq 'ByteSequence') { $needles += ,(Convert-HexToBytes $signature.Value) }
        else {
            $needles += ,[Text.Encoding]::UTF8.GetBytes([string]$signature.Value)
            $needles += ,[Text.Encoding]::Unicode.GetBytes([string]$signature.Value)
        }
        foreach ($needle in $needles) {
            if ($needle.Length -eq 0 -or $needle.Length -gt 65536) { throw 'Content signature length is outside the safe range.' }
            $patterns.Add([pscustomobject]@{ Index=$signatureIndex; Text=$encoding.GetString($needle) })
            $overlap = [Math]::Max($overlap, $needle.Length - 1)
        }
        $signatureIndex++
    }
    $plan=[pscustomobject]@{ Patterns=$patterns.ToArray(); Overlap=$overlap; Encoding=$encoding }
    if ($script:ContentPlanCache.Count -ge 64) { $script:ContentPlanCache.Clear() }
    $script:ContentPlanCache[$key]=$plan
    return $plan
}

function Read-ContentInspection {
    param([IO.Stream]$Stream, [object[]]$Signatures = @(), [long]$MaximumBytes = [long]::MaxValue,
        [switch]$Capture, [switch]$CaptureContainers, $Budget, $Plan, [switch]$SkipClassCapture)
    if ($null -eq $Plan) { $Plan=Get-ContentScanPlan $Signatures }
    $encoding=$Plan.Encoding; $patterns=$Plan.Patterns; $overlap=$Plan.Overlap
    $found = @{}
    $tail = ''
    # Small classes should not allocate a 64 KiB buffer per entry; large files
    # benefit from fewer pipeline iterations. No content length is skipped.
    $bufferSize=[int][Math]::Max(8L,[Math]::Min(1048576L,$MaximumBytes))
    $buffer = [byte[]]::new($bufferSize)
    $sha = [Security.Cryptography.SHA256]::Create()
    $memory = $null
    $prefix = [IO.MemoryStream]::new()
    $total = 0L
    $actualType = 'Unknown'
    try {
        while (($count = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            Test-WorkerCancellation
            $total += $count
            if ($script:ProgressTotal -gt 0 -and $total -ge 1048576 -and ([DateTime]::UtcNow-$script:ProgressLastUpdate).TotalMilliseconds -ge 150) {
                Write-ScanProgress -Current $script:ProgressCurrent -Total $script:ProgressTotal -Status ('Reading content: {0:N1} MiB' -f ($total/1MB))
            }
            if ($total -gt $MaximumBytes) { throw [IO.InvalidDataException]::new('Decompressed stream exceeded its declared/safe length.') }
            if ($null -ne $Budget) {
                $Budget.Bytes += $count
                if ($Budget.Bytes -gt $script:Limits.MaximumDecompressedBytes) { throw [IO.InvalidDataException]::new('ZIP cumulative decompressed-size safety limit exceeded.') }
            }
            if ($prefix.Length -lt 8) { $prefix.Write($buffer,0,[Math]::Min($count,8-[int]$prefix.Length)) }
            if ($total -eq $count) {
                $magic = Get-MagicInfoFromStream $prefix ''
                $actualType = $magic.ActualType
                if ($Capture -or ($CaptureContainers -and ($actualType -eq 'Java Archive / ZIP' -or ($actualType -eq 'Java Class' -and -not $SkipClassCapture)))) { $memory = [IO.MemoryStream]::new() }
            }
            if ($null -ne $memory) {
                if ($total -le $script:Limits.MaximumNestedEntryBytes) { $memory.Write($buffer,0,$count) }
                else { $memory.Dispose(); $memory = $null }
            }
            [void]$sha.TransformBlock($buffer,0,$count,$null,0)
            if ($patterns.Count -gt 0) {
                $text = $tail + $encoding.GetString($buffer,0,$count)
                foreach ($pattern in $patterns) {
                    $signature=$Signatures[$pattern.Index]
                    if (-not $found.ContainsKey($signature.ID) -and $text.IndexOf($pattern.Text,[StringComparison]::Ordinal) -ge 0) { $found[$signature.ID] = $signature }
                }
                $tail = if ($text.Length -gt $overlap) { $text.Substring($text.Length-$overlap) } else { $text }
            }
        }
        [void]$sha.TransformFinalBlock([byte[]]@(),0,0)
        return [pscustomobject]@{
            SHA256=([BitConverter]::ToString($sha.Hash)).Replace('-',''); Length=$total
            ActualType=$actualType; Matches=@($found.Values); Bytes=$(if ($null -ne $memory) { ,$memory.ToArray() } else { $null })
        }
    } finally { $sha.Dispose(); $prefix.Dispose(); if ($null -ne $memory) { $memory.Dispose() } }
}

function Read-ClassU2 {
    param([IO.BinaryReader]$Reader)
    return (([int]$Reader.ReadByte() -shl 8) -bor [int]$Reader.ReadByte())
}

function Read-ClassU4 {
    param([IO.BinaryReader]$Reader)
    return (([long](Read-ClassU2 $Reader) -shl 16) -bor [long](Read-ClassU2 $Reader))
}

function Read-JavaClassIndex {
    param([byte[]]$Bytes)
    $memory = [IO.MemoryStream]::new($Bytes,$false)
    $reader = [IO.BinaryReader]::new($memory)
    try {
        if (((([long]$reader.ReadByte() -shl 24) -bor ([long]$reader.ReadByte() -shl 16) -bor ([long]$reader.ReadByte() -shl 8) -bor [long]$reader.ReadByte())) -ne 3405691582L) { throw 'Invalid Java class magic.' }
        $minor = (([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte()); $major = (([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())
        $count = (([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())
        $pool = New-Object object[] $count
        $classes = @{}
        for ($i=1; $i -lt $count; $i++) {
            if (($i -band 127) -eq 0) { Test-WorkerCancellation }
            $tag = [int]$reader.ReadByte()
            if ($tag -eq 1) { $length=(([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte()); $textBytes=$reader.ReadBytes($length); if ($textBytes.Length -ne $length) { throw 'Truncated constant pool UTF8.' }; $pool[$i]=[Text.Encoding]::UTF8.GetString($textBytes) }
            elseif ($tag -eq 7) { $classes[$i]=(([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte()) }
            elseif ($tag -in @(3,4,9,10,11,12,17,18)) { [void]$reader.ReadUInt32() }
            elseif ($tag -in @(5,6)) { [void]$reader.ReadUInt64(); $i++ }
            elseif ($tag -in @(8,16,19,20)) { [void]$reader.ReadUInt16() }
            elseif ($tag -eq 15) { [void]$reader.ReadByte(); [void]$reader.ReadUInt16() }
            else { throw "Unsupported Java constant-pool tag: $tag" }
        }
        $flags=(([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte()); $thisClass=(([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte()); $superClass=(([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())
        $interfaceCount=(([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())
        for ($i=0; $i -lt $interfaceCount; $i++) { [void]((([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())) }
        $shape = [Collections.Generic.List[string]]::new()
        $shape.Add("v=$major;flags=$flags;interfaces=$interfaceCount")
        foreach ($kind in @('field','method')) {
            $members=(([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())
            $shape.Add("$kind-count=$members")
            for ($i=0; $i -lt $members; $i++) {
                $memberFlags=(([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte()); [void]((([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())); $descriptorIndex=(([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())
                if ($descriptorIndex -ge $pool.Length) { throw 'Invalid member descriptor index.' }
                $descriptor=([string]$pool[$descriptorIndex]) -replace 'L[^;]+;', 'LObject;'
                $shape.Add("$kind=$memberFlags;$descriptor")
                $attributes=(([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())
                for ($j=0; $j -lt $attributes; $j++) {
                    [void]((([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())); $length=(([long]$reader.ReadByte() -shl 24) -bor ([long]$reader.ReadByte() -shl 16) -bor ([long]$reader.ReadByte() -shl 8) -bor [long]$reader.ReadByte())
                    if ($length -gt ($memory.Length-$memory.Position)) { throw 'Truncated member attribute.' }
                    [void]$memory.Seek($length,[IO.SeekOrigin]::Current)
                }
            }
        }
        $attributes=(([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())
        for ($j=0; $j -lt $attributes; $j++) {
            [void]((([int]$reader.ReadByte() -shl 8) -bor [int]$reader.ReadByte())); $length=(([long]$reader.ReadByte() -shl 24) -bor ([long]$reader.ReadByte() -shl 16) -bor ([long]$reader.ReadByte() -shl 8) -bor [long]$reader.ReadByte())
            if ($length -gt ($memory.Length-$memory.Position)) { throw 'Truncated class attribute.' }
            [void]$memory.Seek($length,[IO.SeekOrigin]::Current)
        }
        if ($memory.Position -ne $memory.Length -or -not $classes.ContainsKey($thisClass)) { throw 'Invalid class layout.' }
        $references = @($classes.Values | ForEach-Object { if ($_ -lt $pool.Length) { [string]$pool[$_] } } | Sort-Object -Unique)
        return [pscustomobject]@{ Name=[string]$pool[$classes[$thisClass]]; MajorVersion=$major; References=$references; Shape=(Get-StringSha256 (@($shape | Sort-Object) -join "`n")) }
    } finally { $reader.Dispose(); $memory.Dispose() }
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
    if (@($Matches | Where-Object { $_.ID -eq $Signature.ID -and $_.Location -eq $Location }).Count -eq 0) {
        [void]$Matches.Add([pscustomobject][ordered]@{
            ID = [string]$Signature.ID
            Type = [string]$Signature.Type
            Value = [string]$Signature.Value
            Specificity = [string]$Signature.Specificity
            Confidence = [int]$Signature.Confidence
            Source = [string]$Signature.Source
            Location = $Location
            Observed = $Observed
            Verified = ($Signature.PSObject.Properties['Verified'] -and $Signature.Verified -is [bool] -and $Signature.Verified)
            IndependenceGroup = $(if ($Signature.PSObject.Properties['IndependenceGroup']) { [string]$Signature.IndependenceGroup } else { '' })
            EvidenceContainer = $(if ($Location.LastIndexOf('!/') -gt 0) { $Location.Substring(0,$Location.LastIndexOf('!/')) } else { $Location })
        })
    }
}

function Get-CachedClassIndex {
    param([byte[]]$Bytes,[string]$SHA256,[switch]$Independent)
    if (-not $Independent -and $script:ClassIndexCache.ContainsKey($SHA256)) { $script:ClassCacheHits++; return $script:ClassIndexCache[$SHA256].Index }
    $script:ClassCacheMisses++
    $index=Read-JavaClassIndex $Bytes
    if (-not $Independent) {
        $cost=[long]$Bytes.Length+2048
        if ($cost -le 67108864) {
            while ($script:ClassIndexCacheOrder.Count -gt 0 -and ($script:ClassIndexCacheOrder.Count -ge 8192 -or $script:ClassIndexCacheBytes+$cost -gt 67108864)) {
                $old=$script:ClassIndexCacheOrder.Dequeue()
                $script:ClassIndexCacheBytes-=$script:ClassIndexCache[$old].Cost
                $script:ClassIndexCache.Remove($old)
            }
            $script:ClassIndexCache[$SHA256]=[pscustomobject]@{ Index=$index; Cost=$cost }
            $script:ClassIndexCacheOrder.Enqueue($SHA256); $script:ClassIndexCacheBytes+=$cost
        }
    }
    return $index
}

function Inspect-ZipStream {
    param([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][string]$DisplayPath, [int]$Depth=0, $State, $Budget, [switch]$Independent)
    if ($null -eq $Budget) { $Budget=[pscustomobject]@{ Bytes=0L; Entries=0L } }
    $result = [pscustomobject][ordered]@{
        DisplayPath=$DisplayPath; Depth=$Depth; EntryCount=0; ClassCount=0; ClassesAnalyzed=0
        Classes=[Collections.ArrayList]::new(); Packages=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        Resources=[Collections.ArrayList]::new(); Embedded=[Collections.ArrayList]::new()
        Metadata=[ordered]@{}; Manifest=[ordered]@{}; StructuralFingerprint=''; ContentFingerprint=''; ClassShapeFingerprint=''
        ClassRelationships=[Collections.ArrayList]::new(); EntryHashes=[Collections.ArrayList]::new()
        Matches=[Collections.ArrayList]::new(); AllEntriesScanned=$false; SecurityLimitHit=$false; ClassParsing='Detailed'
    }
    if ($Depth -gt $script:Limits.MaximumRecursion) { $result.SecurityLimitHit=$true; return $result }
    if ($Stream.CanSeek) { $Stream.Position=0 }
    $archive=[IO.Compression.ZipArchive]::new($Stream,[IO.Compression.ZipArchiveMode]::Read,$true)
    $shapes=[Collections.Generic.List[string]]::new()
    try {
        $entries=@($archive.Entries)
        $result.EntryCount=$entries.Count
        $Budget.Entries += $entries.Count
        if ($Budget.Entries -gt $script:Limits.MaximumEntryCount) { throw [IO.InvalidDataException]::new('ZIP cumulative entry-count safety limit exceeded.') }
        $declared=0L
        foreach ($entry in $entries) {
            Test-WorkerCancellation
            $declared += [long]$entry.Length
            if ($declared -gt $script:Limits.MaximumDecompressedBytes) { throw [IO.InvalidDataException]::new('ZIP decompressed-size safety limit exceeded.') }
            if ($entry.Length -gt 1048576 -and ($entry.CompressedLength -eq 0 -or ([double]$entry.Length/[Math]::Max(1,$entry.CompressedLength)) -gt $script:Limits.MaximumCompressionRatio)) { throw [IO.InvalidDataException]::new('ZIP compression-ratio safety limit exceeded.') }
        }
        $classSigs=@(Get-SignaturesByType @('Class'))
        $packageSigs=@(Get-SignaturesByType @('Package'))
        $shapeSigs=@(Get-SignaturesByType @('StructuralFingerprint') | Where-Object { $_.PSObject.Properties['FingerprintKind'] -and $_.FingerprintKind -eq 'ClassShape' })
        $parseClasses=$Independent -or $script:AnalysisProfile -ne 'Signatures' -or $classSigs.Count -gt 0 -or $packageSigs.Count -gt 0 -or $shapeSigs.Count -gt 0
        if (-not $parseClasses) { $result.ClassParsing='All class bytes inspected; constant-pool parsing not requested by installed signatures' }
        $resourceSigs=@(Get-SignaturesByType @('Resource','EmbeddedNative'))
        $metadataSigs=@(Get-SignaturesByType @('Manifest','ModId','LoaderIndicator'))
        $contentSigs=@(Get-SignaturesByType @('String','ByteSequence','LoaderIndicator','RuntimeIndicator'))
        $contentPlan=Get-ContentScanPlan $contentSigs
        $hashSigs=@(Get-SignaturesByType @('SHA256'))
        foreach ($entry in $entries) {
            Test-WorkerCancellation
            $name=$entry.FullName.Replace('\','/')
            if ($script:ProgressTotal -gt 0) { Write-ScanProgress -Current $script:ProgressCurrent -Total $script:ProgressTotal -Status ("Archive entries: {0:N0}; classes analyzed: {1:N0}" -f $entries.Count,$result.ClassesAnalyzed) }
            if (-not $name -or $name.EndsWith('/')) { continue }
            $location="$DisplayPath!/$name"
            [void]$result.Resources.Add($name)
            $isMetadata=$name -match '(?i)^(META-INF/MANIFEST\.MF|mcmod\.info|META-INF/(neo)?mods\.toml|fabric\.mod\.json|quilt\.mod\.json|plugin\.yml)$|^META-INF/services/'
            $isClass=$name.EndsWith('.class',[StringComparison]::OrdinalIgnoreCase)
            if ($isClass) { $result.ClassCount++ }
            $entryStream=$entry.Open()
            try { $content=Read-ContentInspection -Stream $entryStream -Signatures $contentSigs -Plan $contentPlan -MaximumBytes $entry.Length -Capture:$isMetadata -CaptureContainers -Budget $Budget -SkipClassCapture:(-not $parseClasses) }
            finally { $entryStream.Dispose() }
            if ($content.Length -ne $entry.Length) { throw [IO.InvalidDataException]::new("ZIP entry length mismatch: $name") }
            foreach ($sig in $content.Matches) { Add-SignatureMatch $result.Matches $sig $location '[byte content match]' }
            foreach ($sig in $hashSigs) { if ($sig.Value -eq $content.SHA256) { Add-SignatureMatch $result.Matches $sig $location $content.SHA256 } }
            [void]$result.EntryHashes.Add([pscustomobject]@{ Path=$location; SHA256=$content.SHA256; Length=$content.Length; ActualType=$content.ActualType })
            foreach ($sig in $resourceSigs) { if (Test-TextMatch $name $sig) { Add-SignatureMatch $result.Matches $sig $location $name } }
            if ($isClass -or $content.ActualType -eq 'Java Class') {
                if (-not $isClass) { $result.ClassCount++ }
                if (-not $parseClasses) { $result.ClassesAnalyzed++ }
                else { try {
                    if ($null -eq $content.Bytes) { throw 'Class exceeds in-memory parsing safety budget.' }
                    $class=Get-CachedClassIndex -Bytes $content.Bytes -SHA256 $content.SHA256 -Independent:$Independent
                    $className=$class.Name.Replace('/','.')
                    [void]$result.Classes.Add($className)
                    $result.ClassesAnalyzed++
                    $shapes.Add($class.Shape)
                    [void]$result.ClassRelationships.Add([pscustomobject]@{ Class=$className; References=$class.References })
                    $dot=$className.LastIndexOf('.')
                    $package=if ($dot -gt 0) { $className.Substring(0,$dot) } else { '' }
                    if ($package) { [void]$result.Packages.Add($package) }
                    foreach ($sig in $classSigs) { if (Test-TextMatch $className $sig) { Add-SignatureMatch $result.Matches $sig $location $className } }
                    foreach ($sig in $packageSigs) { if ($package -and (Test-TextMatch $package $sig)) { Add-SignatureMatch $result.Matches $sig $location $package } }
                } catch {
                    $result.SecurityLimitHit=$true
                    if ($null -ne $State) { Add-ScanWarning $State 'CLASS' $_.Exception.Message $location }
                } }
            }
            if ($isMetadata) {
                if ($entry.Length -gt $script:Limits.MaximumMetadataBytes -or $null -eq $content.Bytes) {
                    $result.SecurityLimitHit=$true
                    if ($null -ne $State) { Add-ScanWarning $State 'METADATA' 'Metadata parse safety limit reached; byte content was still inspected.' $location }
                } else {
                    $metadataText=[Text.Encoding]::UTF8.GetString($content.Bytes)
                    $result.Metadata[$name]=$metadataText
                    if ($name -ieq 'META-INF/MANIFEST.MF') { $result.Manifest=Get-ManifestAttributes $metadataText }
                    foreach ($sig in $metadataSigs) { if (Test-TextMatch $metadataText $sig) { Add-SignatureMatch $result.Matches $sig $location '[metadata match]' } }
                }
            }
            if ($content.ActualType -eq 'Java Archive / ZIP' -or $name -match '(?i)\.(jar|zip)$') {
                [void]$result.Embedded.Add($location)
                if ($Depth -ge $script:Limits.MaximumRecursion -or $null -eq $content.Bytes) {
                    $result.SecurityLimitHit=$true
                    if ($null -ne $State) { Add-ScanWarning $State 'NESTED JAR' 'Recursion or memory safety limit reached; nested contents remain unanalyzed.' $location }
                } else {
                    $nestedStream=[IO.MemoryStream]::new([byte[]]$content.Bytes,$false)
                    try {
                        $nested=Inspect-ZipStream $nestedStream $location ($Depth+1) $State $Budget -Independent:$Independent
                        foreach ($match in $nested.Matches) { [void]$result.Matches.Add($match) }
                        foreach ($nestedName in $nested.Embedded) { [void]$result.Embedded.Add($nestedName) }
                        if (-not $nested.AllEntriesScanned) { $result.SecurityLimitHit=$true }
                    } finally { $nestedStream.Dispose() }
                }
            } elseif ($content.ActualType -eq 'Windows PE' -or $name -match '(?i)\.(dll|so|dylib)$') { [void]$result.Embedded.Add($location) }
        }
        $structure=(@($result.Resources | Sort-Object -Unique) -join "|") + '|manifest|' + (@($result.Manifest.Keys | Sort-Object) -join '|')
        $result.StructuralFingerprint=Get-StringSha256 $structure
        $result.ContentFingerprint=Get-StringSha256 (@($result.EntryHashes | ForEach-Object { $_.SHA256 } | Sort-Object) -join '|')
        if ($parseClasses) { $result.ClassShapeFingerprint=Get-StringSha256 (@($shapes | Sort-Object) -join '|') }
        foreach ($sig in @(Get-SignaturesByType @('StructuralFingerprint'))) {
            $observed=$result.StructuralFingerprint
            if ($sig.PSObject.Properties['FingerprintKind']) {
                if ($sig.FingerprintKind -eq 'Content') { $observed=$result.ContentFingerprint }
                elseif ($sig.FingerprintKind -eq 'ClassShape') { $observed=$result.ClassShapeFingerprint }
            }
            if ($sig.Value -eq $observed) { Add-SignatureMatch $result.Matches $sig $DisplayPath $observed }
        }
        $result.AllEntriesScanned=-not $result.SecurityLimitHit
        if ($null -ne $State) { $State.TotalIndexesExtracted += $entries.Count }
        return $result
    } finally { $archive.Dispose() }
}
function Get-CategoryForFile {
    param([string]$Extension, [string]$ActualType, $JarAnalysis, [string]$Source = 'FILE')
    if ($Source -eq 'ADS') { return 'ADS_PAYLOAD' }
    if ($null -ne $JarAnalysis) {
        if ($JarAnalysis.Manifest.Contains('Premain-Class') -or $JarAnalysis.Manifest.Contains('Agent-Class') -or $JarAnalysis.Manifest.Contains('Launcher-Agent-Class')) { return 'JAVA_AGENT' }
        if (@($JarAnalysis.Metadata.Keys | Where-Object { $_ -match '(?i)mcmod\.info|mods\.toml|fabric\.mod\.json|quilt\.mod\.json' }).Count -gt 0) { return 'MOD' }
        if ($JarAnalysis.Manifest.Contains('Main-Class')) { return 'LOADER' }
        return 'UNKNOWN'
    }
    switch ($Extension.ToLowerInvariant()) {
        '.dll' { return 'NATIVE_DLL' }
        '.exe' { return 'UNKNOWN' }
        '.class' { return 'UNKNOWN' }
        default { return 'UNKNOWN' }
    }
}

function Get-EvasionContextSignatures {
    param([string]$LiteralPath, [string]$ActualType)
    if ($LiteralPath -eq (Join-Path $script:ProjectRoot 'DoomsDayFinder.ps1')) { return @() }
    if ($ActualType -ne 'Windows PE' -and [IO.Path]::GetExtension($LiteralPath) -notin @('.ps1','.bat','.cmd','.vbs','.py')) { return @() }
    return @(
        [pscustomobject]@{ ID='REVEAL-CONTEXT:JRE_USAGE_PATH'; ContextId='JRE_USAGE_PATH'; Type='String'; Value='.oracle_jre_usage'; ContextOnly=$true },
        [pscustomobject]@{ ID='REVEAL-CONTEXT:JAVA_PROCESS_NAME'; ContextId='JAVA_PROCESS_NAME'; Type='String'; Value='javaw.exe'; ContextOnly=$true },
        [pscustomobject]@{ ID='REVEAL-CONTEXT:MEMORY_WRITE_API'; ContextId='MEMORY_WRITE_API'; Type='String'; Value='WriteProcessMemory'; ContextOnly=$true },
        [pscustomobject]@{ ID='REVEAL-CONTEXT:PYTHON_MEMORY_WRITE'; ContextId='PYTHON_MEMORY_WRITE'; Type='String'; Value='write_bytes'; ContextOnly=$true },
        [pscustomobject]@{ ID='REVEAL-CONTEXT:MEMORY_QUERY_API'; ContextId='MEMORY_QUERY_API'; Type='String'; Value='VirtualQueryEx'; ContextOnly=$true }
    )
}

function Get-EvasionContextIndicators {
    param([string]$LiteralPath, [string]$ActualType)
    $indicators=@(Get-EvasionContextSignatures $LiteralPath $ActualType)
    if ($indicators.Count -eq 0) { return @() }
    $stream=[IO.File]::Open($LiteralPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try { $content=Read-ContentInspection $stream $indicators; return @($content.Matches | Select-Object -ExpandProperty ContextId) }
    finally { $stream.Dispose() }
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
    $hashMatch = @($unique | Where-Object { $_.Type -eq 'SHA256' -and $_.PSObject.Properties['Verified'] -and $_.Verified -eq $true }).Count -gt 0
    $strong = @($unique | Where-Object { $_.Specificity -in @('High','VeryHigh','Verified') -and $_.Type -notin @('StructuralFingerprint','OriginalFilename') })
    if ($KnownClean -and ($unique.Count -gt 0)) { return [pscustomobject]@{ Verdict='INCONCLUSIVE'; Verification='CONFLICTING'; EligibleForDetected=$false; Reason='Known-clean hash conflicts with signature evidence.' } }
    if (-not $ContentAvailable) { return [pscustomobject]@{ Verdict='REVIEW'; Verification='UNVERIFIED'; EligibleForDetected=$false; Reason='File content was unavailable.' } }
    if ($hashMatch) { return [pscustomobject]@{ Verdict='DETECTED'; Verification='PENDING'; EligibleForDetected=$true; Reason='Verified DoomsDay SHA-256 signature matched.' } }
    $independent=$false
    foreach ($container in @($strong | Where-Object { $_.PSObject.Properties['EvidenceContainer'] } | Group-Object EvidenceContainer)) {
        $containerGroups=@($container.Group | Where-Object { $_.PSObject.Properties['Verified'] -and $_.Verified -eq $true -and $_.PSObject.Properties['IndependenceGroup'] -and $_.IndependenceGroup } | Select-Object -ExpandProperty IndependenceGroup -Unique)
        if ($containerGroups.Count -ge 2) { $independent=$true }
    }
    if ($independent) { return [pscustomobject]@{ Verdict='DETECTED'; Verification='PENDING'; EligibleForDetected=$true; Reason='Multiple verified independent high-specificity DoomsDay indicators matched in the same artifact.' } }
    if ($strong.Count -ge 2 -or ($unique.Count -gt 0 -and $Score -ge 80)) { return [pscustomobject]@{ Verdict='HIGH CONFIDENCE'; Verification='PROBABLE'; EligibleForDetected=$false; Reason='Strong indicators require additional independent verification.' } }
    if ($unique.Count -gt 0) { return [pscustomobject]@{ Verdict='SUSPICIOUS'; Verification='UNVERIFIED'; EligibleForDetected=$false; Reason='DoomsDay-related indicators require manual review.' } }
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
        [string]$MagicBytes = '', [string[]]$BypassIndicators = @()
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
        BypassIndicators = @($BypassIndicators)
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
    Write-Stage 'VERIFY' 'Reopening candidate and reproducing hash plus signature matches...'
    $stream=$null
    try {
        $stream=Open-ReadOnlyEvidenceStream $LiteralPath
        $secondHash=Get-StreamSha256 $stream
        if ($secondHash -ne $InitialFinding.SHA256) { throw 'SHA-256 changed between inspections.' }
        $magic=Get-MagicInfoFromStream $stream ''
        $secondIds=[Collections.Generic.HashSet[string]]::new()
        foreach ($sig in @(Get-SignaturesByType @('SHA256'))) { if ($sig.Value -eq $secondHash -and -not (Test-GenericIndicator $sig.Value)) { [void]$secondIds.Add($sig.ID) } }
        if ($magic.ActualType -eq 'Java Archive / ZIP') {
            $archive=Inspect-ZipStream -Stream $stream -DisplayPath $LiteralPath -Independent
            if (-not $archive.AllEntriesScanned) { throw 'Second archive inspection was incomplete.' }
            foreach ($match in $archive.Matches) { [void]$secondIds.Add($match.ID) }
            foreach ($entry in $archive.EntryHashes) {
                if ((Test-KnownCleanHash $entry.SHA256) -and @($archive.Matches | Where-Object { $_.Location -eq $entry.Path -or $_.Location.StartsWith($entry.Path+'!/') }).Count -gt 0) { throw 'Known-clean embedded content conflicts with signatures.' }
            }
        } else {
            $stream.Position=0
            $content=Read-ContentInspection $stream @(Get-SignaturesByType @('String','ByteSequence','LoaderIndicator','RuntimeIndicator'))
            foreach ($sig in $content.Matches) { if (-not (Test-GenericIndicator $sig.Value)) { [void]$secondIds.Add($sig.ID) } }
        }
        foreach ($id in $InitialMatchIds) { if (-not $secondIds.Contains($id)) { throw 'Signature matches were not reproducible.' } }
        if (Test-KnownCleanHash $secondHash) { throw 'Known-clean hash conflicts with signatures.' }
        if ((Get-StreamSha256 $stream) -ne $secondHash) { throw 'Content changed during verification.' }
        return [pscustomobject]@{ Verified=$true; Status='VERIFIED'; Reason='Independent reopen, content inspection and SHA-256 verification succeeded.' }
    } catch {
        Add-ScanWarning $State 'VERIFY' $_.Exception.Message $LiteralPath
        return [pscustomobject]@{ Verified=$false; Status='CONFLICTING'; Reason=$_.Exception.Message }
    } finally { if ($null -ne $stream) { $stream.Dispose() } }
}
function Invoke-FileInspection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath, $State, [string]$Source = 'FILE', [switch]$AlwaysRecord, [switch]$QuietProgress)
    try { $item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop; if ($item.PSIsContainer) { throw 'Candidate is not a file.' } }
    catch { $State.CandidateFiles++; $State.FilesSkipped++; Add-ScanWarning $State 'FILE' $_.Exception.Message $LiteralPath; return $null }
    $inspectionKey = '{0}|{1}|{2}' -f $item.FullName.ToLowerInvariant(), $item.Length, $item.LastWriteTimeUtc.Ticks
    $refreshDetails=$false
    if ($script:InspectionCache.ContainsKey($inspectionKey)) {
        $cachedFinding = $script:InspectionCache[$inspectionKey]
        $needsArchiveDetails=$AlwaysRecord -and $null -ne $cachedFinding -and $null -ne $cachedFinding.PSObject.Properties['ArchiveDetailsOmitted']
        if (-not $needsArchiveDetails) {
            if ($null -ne $cachedFinding) {
                if ($Source -and $Source -notin @($cachedFinding.EvidenceSources)) { $cachedFinding.EvidenceSources += $Source }
                if ($AlwaysRecord -and $cachedFinding -notin @($State.Findings)) { [void]$State.Findings.Add($cachedFinding) }
            }
            return $cachedFinding
        }
        $script:InspectionCache.Remove($inspectionKey)
        $refreshDetails=$true; $State.FilesFullyScanned--
    }
    if (-not $refreshDetails) { $State.CandidateFiles++; $State.FilesFound++ }
    if (-not $QuietProgress) { Write-Stage 'HASH' "Computing SHA-256: $($item.Name)" }
    try {
        $magic = Get-MagicInfo -LiteralPath $item.FullName
        $signatureMatches = [System.Collections.ArrayList]::new()
        $evasionIndicators=[Collections.Generic.List[string]]::new()
        $jar = $null
        if ($magic.ActualType -eq 'Java Archive / ZIP') {
            $sha256 = Get-CachedFileSha256 -LiteralPath $item.FullName
            if (-not $QuietProgress) { Write-Stage 'JAR' "Inspecting every archive entry: $($item.Name)" }
            $stream = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            try { $jar = Inspect-ZipStream -Stream $stream -DisplayPath $item.FullName -State $State }
            finally { $stream.Dispose() }
            foreach ($match in $jar.Matches) { [void]$signatureMatches.Add($match) }
            if (-not $QuietProgress) { Write-Stage 'CLASS' ("{0} / {0} classes" -f $jar.ClassCount) }
            if (-not $jar.AllEntriesScanned) { $State.PartialFiles++; $State.FilesSkipped++ }
        } else {
            $contentSigs = @(Get-SignaturesByType @('String','ByteSequence','LoaderIndicator','RuntimeIndicator'))
            $contentSigs += @(Get-EvasionContextSignatures $item.FullName $magic.ActualType)
            if ($contentSigs.Count -gt 0) {
                $stream=[IO.File]::Open($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                try { $content=Read-ContentInspection -Stream $stream -Signatures $contentSigs -MaximumBytes $item.Length }
                finally { $stream.Dispose() }
                $sha256=$content.SHA256
                $hashKey='{0}|{1}|{2}' -f $item.FullName,$item.Length,$item.LastWriteTimeUtc.Ticks
                $script:HashCache[$hashKey]=$sha256
                foreach ($sig in $content.Matches) {
                    if ($sig.PSObject.Properties['ContextOnly'] -and $sig.ContextOnly) { $evasionIndicators.Add([string]$sig.ContextId) }
                    else { Add-SignatureMatch $signatureMatches $sig $item.FullName '[byte content match]' }
                }
            } else { $sha256=Get-CachedFileSha256 -LiteralPath $item.FullName }
            if ($item.Extension -in @('.jar','.zip') -and $magic.ActualType -eq 'Unknown') { throw [IO.InvalidDataException]::new('Archive extension present but no supported ZIP header; content cannot be fully analyzed.') }
        }
        foreach ($sig in (Get-SignaturesByType @('SHA256'))) {
            if ([string]$sig.Value -eq $sha256) { Add-SignatureMatch $signatureMatches $sig $item.FullName $sha256 }
        }
        $filenameMatch = $item.Name -match '(?i)dooms[ -_]?day'
        $score = Get-ScoreForMatches -Matches @($signatureMatches) -FilenameMatch $filenameMatch -AdsCorrelation:($Source -eq 'ADS')
        $knownClean = Test-KnownCleanHash $sha256
        $decision = Get-Decision -Matches @($signatureMatches) -Score $score -KnownClean $knownClean
        $cleanerCombination=('JRE_USAGE_PATH' -in $evasionIndicators -and 'JAVA_PROCESS_NAME' -in $evasionIndicators -and ('MEMORY_WRITE_API' -in $evasionIndicators -or 'PYTHON_MEMORY_WRITE' -in $evasionIndicators))
        if ($cleanerCombination -and $decision.Verdict -eq 'INFO' -and -not $knownClean) {
            $decision.Verdict='REVIEW'
            $decision.Reason='Static memory-cleaner indicators; tool presence is not proof of execution or DoomsDay.'
        }
        if ($filenameMatch -and $signatureMatches.Count -eq 0 -and -not $knownClean) {
            $decision.Verdict = 'REVIEW'
            $decision.Verification = 'UNVERIFIED'
            $decision.EligibleForDetected = $false
            $decision.Reason = 'Filename-only resemblance requires manual review and cannot identify the family.'
        }
        $reasons = [System.Collections.ArrayList]::new()
        if ($cleanerCombination) { [void]$reasons.Add('Java target, memory-write capability and JRE usage path occur together. Manual tool review only; no DoomsDay attribution or execution inferred.') }
        foreach ($match in @($signatureMatches | Sort-Object ID -Unique)) { [void]$reasons.Add("$($match.Type) signature $($match.ID) matched at $($match.Location)") }
        if ($filenameMatch) { [void]$reasons.Add('Filename resembles DoomsDay; filename contributes only one informational point.') }
        if ($magic.ExtensionMismatch) { [void]$reasons.Add('Displayed extension does not match file magic bytes.') }
        if ($knownClean) { [void]$reasons.Add('Known-clean hash matched; conflicting evidence protection applied.') }
        if ($reasons.Count -eq 0) { [void]$reasons.Add('No DoomsDay-specific signature matched.') }
        $category = Get-CategoryForFile -Extension $item.Extension -ActualType $magic.ActualType -JarAnalysis $jar -Source $Source
        $finding = New-Finding -Family $(if ($signatureMatches.Count -gt 0) { 'DoomsDay' } else { 'Unknown' }) `
            -CurrentName $item.Name -FullPath $item.FullName -Extension $item.Extension -ActualFileType $magic.ActualType `
            -Category $category -Status $(if ($Source -eq 'ADS') { 'ADS' } else { 'CURRENT' }) -Size $item.Length -SHA256 $sha256 `
            -CreatedUtc $item.CreationTimeUtc -ModifiedUtc $item.LastWriteTimeUtc -LastAccessUtc $item.LastAccessTimeUtc `
            -EvidenceSources @($Source) -Evidence @($signatureMatches) -Confidence $score -VerificationStatus $decision.Verification `
            -Verdict $decision.Verdict -DetectionReasons @($reasons) -Source $Source -ExtensionMismatch $magic.ExtensionMismatch -MagicBytes $magic.MagicBytes -BypassIndicators $evasionIndicators.ToArray()

        if ($decision.EligibleForDetected) {
            $confirm = Confirm-FileFinding -LiteralPath $item.FullName -InitialFinding $finding -InitialMatchIds @($signatureMatches.ID) -State $State
            $finding.VerificationStatus = $confirm.Status
            if ($confirm.Verified) { $finding.Verdict = 'DETECTED'; $finding.DetectionReasons += $confirm.Reason }
            else { $finding.Verdict = if ($confirm.Status -eq 'CONFLICTING') { 'INCONCLUSIVE' } else { 'HIGH CONFIDENCE' }; $finding.DetectionReasons += $confirm.Reason }
        }
        $freshItem=Get-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
        if ($freshItem.Length -ne $item.Length -or $freshItem.LastWriteTimeUtc -ne $item.LastWriteTimeUtc) { throw 'File changed during inspection; retry required.' }
        if ($null -eq $jar -or $jar.AllEntriesScanned) { $State.FilesFullyScanned++ }
        else { $finding.Verdict='INCONCLUSIVE'; $finding.VerificationStatus='UNVERIFIED'; $finding.DetectionReasons += 'Archive parsing was incomplete.' }
        if ($null -ne $jar) {
            $finding | Add-Member -NotePropertyName ArchiveAnalysis -NotePropertyValue $jar
            [void]$State.Evidence.Add([pscustomobject]@{ Source='Archive Inspection'; Path=$item.FullName; SHA256=$sha256; ClassCount=$jar.ClassCount; ClassesAnalyzed=$jar.ClassesAnalyzed; ClassParsing=$jar.ClassParsing; ContentFingerprint=$jar.ContentFingerprint; ClassShapeFingerprint=$jar.ClassShapeFingerprint; Complete=$jar.AllEntriesScanned })
        }
        $recordFinding=$AlwaysRecord -or $finding.Verdict -ne 'INFO' -or $filenameMatch -or $magic.ExtensionMismatch
        if ($recordFinding) { [void]$State.Findings.Add($finding) }
        if ($null -ne $jar -and -not $recordFinding) {
            # Do not retain every clean library's entire class/resource tree in
            # memory. Content was fully inspected; its summary remains evidence.
            $compact=$finding.PSObject.Copy()
            $compact.PSObject.Properties.Remove('ArchiveAnalysis')
            $compact | Add-Member -NotePropertyName ArchiveDetailsOmitted -NotePropertyValue $true
            $script:InspectionCache[$inspectionKey]=$compact
        } else { $script:InspectionCache[$inspectionKey] = $finding }
        return $finding
    } catch [OperationCanceledException] { throw }
    catch [IO.InvalidDataException] {
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
            (Join-Path $env:USERPROFILE '.lunarclient'),
            (Join-Path $env:USERPROFILE '.feather'),
            (Join-Path $env:USERPROFILE '.minecraft'),
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

function Get-ReadOnlyFiles {
    param([string[]]$Roots, $State, [switch]$Recurse)
    $pending=[Collections.Generic.Stack[string]]::new()
    foreach ($root in @(Get-NormalizedScanRoots $Roots)) { $pending.Push($root) }
    while ($pending.Count -gt 0) {
        $directory=$pending.Pop()
        try {
            Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop | ForEach-Object {
                $child=$_
                if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $State.FilesSkipped++
                    Add-ScanWarning $State 'DISCOVERY' 'Reparse point not followed; include its target explicitly if authorized.' $child.FullName
                } elseif ($child.PSIsContainer) {
                    if ($Recurse) { $pending.Push($child.FullName) }
                } else { $child }
            }
        } catch { $State.FilesSkipped++; Add-ScanWarning $State 'DISCOVERY' $_.Exception.Message $directory }
    }
}

function Get-CandidateFiles {
    param([string[]]$Roots, $State, [switch]$Full)
    $extensions=@('.jar','.zip','.exe','.dll','.class','.dat','.tmp','.bin','.ps1','.bat','.cmd','.vbs','.py')
    $files=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($Full) { $script:FileInventory=[Collections.Generic.List[string]]::new() }
    Write-Stage 'COLLECT' 'Indexing files and checking magic bytes. The total is shown when enumeration finishes.'
    Write-ScanProgress -Activity 'Collect' -Status 'Finding candidates; total pending' -Current 0 -Total 0
    Get-ReadOnlyFiles -Roots $Roots -State $State -Recurse | ForEach-Object {
        $file=$_
        if ($Full) { $script:FileInventory.Add($file.FullName) }
        $State.DiscoveredFiles++
        $candidate=$file.Extension.ToLowerInvariant() -in $extensions
        if (-not $candidate) {
            try { $candidate=(Get-MagicInfo $file.FullName).ActualType -in @('Java Archive / ZIP','Windows PE','Java Class') }
            catch { $State.FilesSkipped++; Add-ScanWarning $State 'MAGIC' $_.Exception.Message $file.FullName }
        }
        if ($candidate) { [void]$files.Add($file.FullName) }
        Write-ScanProgress -Activity 'Collect' -Status ('Candidates: {0:N0}; counting' -f $files.Count) -Current $State.DiscoveredFiles -Total 0
    }
    Write-ScanProgress -Completed
    return @($files | Sort-Object)
}

function Test-WorkerCancellation {
    if ($null -ne $script:WorkerCancellation) { $script:WorkerCancellation.ThrowIfCancellationRequested() }
}

function Initialize-ScannerWorker {
    param([string]$ConfigurationJson,[Threading.CancellationToken]$Token)
    Set-StrictMode -Version 2.0
    $script:ErrorActionPreference='Stop'
    $config=$ConfigurationJson | ConvertFrom-Json
    $script:IsWorker=$true; $script:WorkerCancellation=$Token
    $script:WorkerAdministrator=[bool]$config.IsAdministrator
    $script:ToolVersion=$config.ToolVersion; $script:ProjectRoot=$config.ProjectRoot
    $script:AnalysisProfile=[string]$config.AnalysisProfile
    $script:Signatures=$config.Signatures; $script:GenericIndicators=@($config.GenericIndicators)
    $script:Limits=[ordered]@{}
    foreach ($property in $config.Limits.PSObject.Properties) { $script:Limits[$property.Name]=$property.Value }
    $script:HashCache=@{}; $script:InspectionCache=@{}; $script:ContentPlanCache=@{}
    $script:ClassIndexCache=@{}; $script:ClassIndexCacheOrder=[Collections.Generic.Queue[string]]::new()
    $script:ClassIndexCacheBytes=0L; $script:ClassCacheHits=0L; $script:ClassCacheMisses=0L
    $script:WarningConsoleLimit=0; $script:ProgressWidth=0; $script:ProgressTotal=0
    $script:ProgressCurrent=0; $script:ProgressLastUpdate=[DateTime]::MinValue
    $script:ScanClock=$null; $script:PhaseClock=$null
}

function Invoke-ScannerWorker {
    param($Tasks,$Results,$Active,[Threading.CancellationToken]$Token,[int]$WorkerId,[string]$ConfigurationJson,[string]$TaskMode,[bool]$AlwaysRecord)
    Initialize-ScannerWorker $ConfigurationJson $Token
    $task=$null
    while (-not $Token.IsCancellationRequested -and $Tasks.TryDequeue([ref]$task)) {
        $Active[$WorkerId]=[string]$task
        $started=[DateTime]::UtcNow
        $state=New-ScanState $TaskMode
        $hits=$script:ClassCacheHits; $misses=$script:ClassCacheMisses
        $adsErrors=0; $finding=$null
        try {
            Test-WorkerCancellation
            if ($TaskMode -eq 'ADS') { $adsErrors=Read-AdsHostEvidence -HostPath ([string]$task) -State $state }
            else { $finding=Invoke-FileInspection -LiteralPath ([string]$task) -State $state -QuietProgress -AlwaysRecord:$AlwaysRecord }
            Test-WorkerCancellation
        } catch [OperationCanceledException] { throw }
        catch {
            if ($TaskMode -eq 'ADS') { $adsErrors++; $state.FilesSkipped++ }
            else { if ($state.CandidateFiles -eq 0) { $state.CandidateFiles++ }; $state.CorruptedUnreadable++ }
            Add-ScanWarning $state 'WORKER' $_.Exception.Message ([string]$task)
        } finally {
            $removed=''; [void]$Active.TryRemove($WorkerId,[ref]$removed)
        }
        # Each result transfers ownership of its state and cache entries to the
        # coordinator. Only class/byte-plan caches remain local to this worker.
        $result=[pscustomobject]@{
            Path=[string]$task; State=$state; AdsErrors=$adsErrors
            InspectionCache=$script:InspectionCache; HashCache=$script:HashCache
            ClassCacheHits=$script:ClassCacheHits-$hits; ClassCacheMisses=$script:ClassCacheMisses-$misses
            WorkerId=$WorkerId; StartedUtc=$started; FinishedUtc=[DateTime]::UtcNow
        }
        $script:InspectionCache=@{}; $script:HashCache=@{}; $finding=$null
        $Results.Add($result,$Token)
        $task=$null; $result=$null; $state=$null
    }
}

function Merge-WorkerResult {
    param($Result,$State,[switch]$CaptureDiagnostics)
    $part=$Result.State
    foreach ($name in @('TotalIndexesExtracted','CandidateFiles','FilesFound','FilesFullyScanned','FilesSkipped','PartialFiles','CorruptedUnreadable','AdsFindings')) { $State.$name += $part.$name }
    foreach ($name in @('Findings','Evidence','Integrity','Processes','AnalyzedSources','UnavailableSources')) {
        foreach ($record in $part.$name) { [void]$State.$name.Add($record) }
    }
    if ($State.Mode -eq 'Fast') {
        foreach ($finding in $part.Findings) {
            if ($finding.Verdict -eq 'DETECTED' -and $finding.VerificationStatus -eq 'VERIFIED') {
                Write-Color ("[DETECTED / VERIFIED] {0} | {1} | {2}" -f $finding.Path,$finding.Category,$finding.SHA256) Red
            }
        }
    }
    foreach ($warning in $part.Warnings) { Add-ScanWarning $State $warning.Source $warning.Message $warning.Path }
    foreach ($key in $Result.InspectionCache.Keys) { $script:InspectionCache[$key]=$Result.InspectionCache[$key] }
    foreach ($key in $Result.HashCache.Keys) { $script:HashCache[$key]=$Result.HashCache[$key] }
    $script:ClassCacheHits += $Result.ClassCacheHits; $script:ClassCacheMisses += $Result.ClassCacheMisses
    $State.Performance.ParallelJobs++
    if ($CaptureDiagnostics) {
        $State.Performance.WorkerDiagnostics += [pscustomobject]@{ Path=$Result.Path; WorkerId=$Result.WorkerId; StartedUtc=$Result.StartedUtc; FinishedUtc=$Result.FinishedUtc }
    }
}

function Invoke-ParallelInspection {
    param([string[]]$Files,$State,[ValidateSet('FILE','ADS')][string]$TaskMode='FILE',
        [ValidateRange(1,8)][int]$WorkerLimit=$script:WorkerCount,[switch]$AlwaysRecord,[switch]$CaptureDiagnostics,
        [Threading.CancellationToken]$CancellationToken=[Threading.CancellationToken]::None)
    if ($Files.Count -eq 0) { return 0 }
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'Parallel inspection is unavailable under the current PowerShell language policy.' }
    $limit=[Math]::Min($WorkerLimit,$Files.Count)
    $State.Performance.Workers=[Math]::Max($State.Performance.Workers,$limit)
    $initial=[Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $initial.LanguageMode=$ExecutionContext.SessionState.LanguageMode
    # Use only scanner functions already loaded from this script. Evidence,
    # signature JSON and paths are passed as arguments, never parsed as code.
    foreach ($function in Get-ChildItem Function:) {
        if ($function.ScriptBlock.File -eq $script:ScannerScriptPath) {
            $initial.Commands.Add([Management.Automation.Runspaces.SessionStateFunctionEntry]::new($function.Name,$function.Definition))
        }
    }
    $configuration=[pscustomobject]@{ ToolVersion=$script:ToolVersion; ProjectRoot=$script:ProjectRoot; AnalysisProfile=$script:AnalysisProfile; Signatures=$script:Signatures; GenericIndicators=$script:GenericIndicators; Limits=$script:Limits; IsAdministrator=$State.IsAdministrator } | ConvertTo-Json -Depth 20 -Compress
    $tasks=[Collections.Concurrent.ConcurrentQueue[object]]::new()
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $Files) { if ($seen.Add($file)) { $tasks.Enqueue($file) } }
    $total=$tasks.Count
    $results=[Collections.Concurrent.BlockingCollection[object]]::new($limit*2)
    $active=[Collections.Concurrent.ConcurrentDictionary[int,string]]::new()
    $cancel=[Threading.CancellationTokenSource]::CreateLinkedTokenSource($CancellationToken,[Threading.CancellationToken]::None)
    $jobs=[Collections.Generic.List[object]]::new(); $pool=$null
    $completed=0; $adsErrors=0
    try {
        $cancel.Token.ThrowIfCancellationRequested()
        $pool=[Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($initial)
        [void]$pool.SetMaxRunspaces($limit); [void]$pool.SetMinRunspaces($limit)
        $pool.ThreadOptions=[Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
        $pool.Open()
        for ($workerId=0; $workerId -lt $limit; $workerId++) {
            $engine=[Management.Automation.PowerShell]::Create()
            $engine.RunspacePool=$pool
            [void]$engine.AddCommand('Invoke-ScannerWorker').AddArgument($tasks).AddArgument($results).AddArgument($active).AddArgument($cancel.Token).AddArgument($workerId).AddArgument($configuration).AddArgument($TaskMode).AddArgument([bool]$AlwaysRecord)
            $job=[pscustomobject]@{ Engine=$engine; Async=$null; Ended=$false }
            $jobs.Add($job)
            $job.Async=$engine.BeginInvoke()
        }
        while ($completed -lt $total) {
            $cancel.Token.ThrowIfCancellationRequested()
            $State.Performance.PeakActive=[Math]::Max($State.Performance.PeakActive,$active.Count)
            $result=$null
            if ($results.TryTake([ref]$result,100)) {
                Merge-WorkerResult $result $State -CaptureDiagnostics:$CaptureDiagnostics
                $adsErrors += $result.AdsErrors; $completed++
            }
            Write-ScanProgress -Current $completed -Total $total -Status ('{0} | Active: {1}/{2}' -f $TaskMode,$active.Count,$limit)
            $allEnded=$true
            foreach ($job in $jobs) {
                if (-not $job.Ended -and $job.Async.IsCompleted) {
                    [void]$job.Engine.EndInvoke($job.Async); $job.Ended=$true
                    if ($job.Engine.HadErrors) { throw ('Worker failed: '+($job.Engine.Streams.Error | Out-String)) }
                }
                if (-not $job.Ended) { $allEnded=$false }
            }
            if ($allEnded -and $results.Count -eq 0 -and $completed -lt $total) { throw "$($total-$completed) artifacts remain unanalyzed after a worker failure." }
        }
        foreach ($job in $jobs) {
            if (-not $job.Ended) { [void]$job.Engine.EndInvoke($job.Async); $job.Ended=$true }
            if ($job.Engine.HadErrors) { throw ('Worker failed: '+($job.Engine.Streams.Error | Out-String)) }
        }
        return $adsErrors
    } catch {
        Add-SourceStatus $State ('Parallel '+$TaskMode) $false "$completed / $total completed: $($_.Exception.Message)"
        throw
    } finally {
        $cancel.Cancel()
        # Signal all workers before waiting for any one of them. No detached
        # child processes or orphaned jobs are created by this scheduler.
        $stops=[Collections.Generic.List[object]]::new()
        foreach ($job in $jobs) {
            if ($null -ne $job.Async -and -not $job.Async.IsCompleted) {
                try { $stops.Add([pscustomobject]@{ Engine=$job.Engine; Async=$job.Engine.BeginStop($null,$null) }) } catch { }
            }
        }
        foreach ($stop in $stops) { try { $stop.Engine.EndStop($stop.Async) } catch { } }
        foreach ($job in $jobs) { $job.Engine.Dispose() }
        if ($null -ne $pool) { $pool.Dispose() }
        $results.Dispose(); $cancel.Dispose()
        Write-ScanProgress -Completed
    }
}

function Invoke-CandidateScan {
    param([string[]]$Roots, $State, [switch]$Full)
    $files=@(Get-CandidateFiles -Roots $Roots -State $State -Full:$Full)
    if ($files.Count -eq 0) { Write-Stage 'SCAN' 'No candidate files were found in the selected locations.'; return }
    Write-Stage 'SCAN' ("TOTAL FILES: {0:N0} | Detailed content inspection; no class-count skip." -f $files.Count)
    $script:ProgressTotal=$files.Count
    try {
        if ($script:WorkerCount -gt 1 -and $files.Count -gt 1) {
            Write-Stage 'SCAN' ("Parallel file inspection: up to {0} workers; all classes remain in scope." -f $script:WorkerCount)
            Invoke-ParallelInspection -Files $files -State $State | Out-Null
        } else {
            for ($index=0; $index -lt $files.Count; $index++) {
                $script:ProgressCurrent=$index
                Write-ScanProgress -Status 'Detailed file inspection' -Current $index -Total $files.Count
                Invoke-FileInspection -LiteralPath $files[$index] -State $State -QuietProgress | Out-Null
            }
        }
        Write-ScanProgress -Status 'File phase complete' -Current $files.Count -Total $files.Count
    } finally { Write-ScanProgress -Completed; $script:ProgressTotal=0 }
    Write-Color ("[SCAN] {0:N0} / {0:N0} candidates processed; see coverage counters for incomplete files." -f $files.Count) Magenta
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
            $image=[IO.File]::OpenRead($process.MainModule.FileName)
            $reader=[IO.BinaryReader]::new($image)
            try {
                if ($reader.ReadUInt16() -ne 0x5A4D) { return 'Unknown' }
                $image.Position=0x3C; $offset=$reader.ReadUInt32()
                if ($offset+6 -gt $image.Length) { return 'Unknown' }
                $image.Position=$offset
                if ($reader.ReadUInt32() -ne 0x4550) { return 'Unknown' }
                switch ($reader.ReadUInt16()) { 0x8664 { return 'x64' }; 0x14C { return 'x86' }; 0xAA64 { return 'ARM64' }; default { return 'Unknown' } }
            } finally { $reader.Dispose(); $image.Dispose() }
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

function Split-JvmCommandLine {
    param([string]$CommandLine)
    $tokens=[Collections.Generic.List[string]]::new()
    $current=[Text.StringBuilder]::new()
    $quoted=$false
    for ($i=0; $i -lt $CommandLine.Length; $i++) {
        $char=$CommandLine[$i]
        if ($char -eq '\') {
            $slashes=0
            while ($i -lt $CommandLine.Length -and $CommandLine[$i] -eq '\') { $slashes++; $i++ }
            if ($i -lt $CommandLine.Length -and $CommandLine[$i] -eq '"') {
                [void]$current.Append(('\' * [int][Math]::Floor($slashes/2)))
                if (($slashes % 2) -eq 1) { [void]$current.Append('"') } else { $quoted=-not $quoted }
            } else { [void]$current.Append(('\' * $slashes)); $i-- }
        } elseif ($char -eq '"') { $quoted=-not $quoted }
        elseif ([char]::IsWhiteSpace($char) -and -not $quoted) {
            if ($current.Length -gt 0) { $tokens.Add($current.ToString()); [void]$current.Clear() }
        } else { [void]$current.Append($char) }
    }
    if ($current.Length -gt 0) { $tokens.Add($current.ToString()) }
    return @($tokens)
}

function Get-JvmArguments {
    param([string]$CommandLine)
    $result=[ordered]@{ JavaAgent=@(); AgentPath=@(); AgentLib=@(); ClassPath=@(); Jar=@(); ArgFiles=@(); GameDirectories=@() }
    $tokens=@(Split-JvmCommandLine $CommandLine)
    for ($i=0; $i -lt $tokens.Count; $i++) {
        $token=$tokens[$i]
        if ($token.StartsWith('-javaagent:',[StringComparison]::OrdinalIgnoreCase)) { $result.JavaAgent += $token.Substring(11) }
        elseif ($token.StartsWith('-agentpath:',[StringComparison]::OrdinalIgnoreCase)) { $result.AgentPath += $token.Substring(11) }
        elseif ($token.StartsWith('-agentlib:',[StringComparison]::OrdinalIgnoreCase)) { $result.AgentLib += $token.Substring(10) }
        elseif ($token -in @('-classpath','-cp','--class-path') -and $i+1 -lt $tokens.Count) { $i++; $result.ClassPath += $tokens[$i] }
        elseif ($token -eq '-jar' -and $i+1 -lt $tokens.Count) { $i++; $result.Jar += $tokens[$i] }
        elseif ($token -eq '--gameDir' -and $i+1 -lt $tokens.Count) { $i++; $result.GameDirectories += $tokens[$i] }
        elseif ($token.StartsWith('@')) { $result.ArgFiles += $token.Substring(1) }
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
                        if ($record.MinecraftAssociation) {
                            [void]$State.Evidence.Add([pscustomobject]@{ Source='JVM Loaded Module'; Path=$modulePath; SHA256=$hash; PID=$record.PID; TimeCreatedUtc=$record.StartTime })
                            $moduleFinding=Invoke-FileInspection -LiteralPath $modulePath -State $State -Source 'JVM_MODULE' -QuietProgress
                            if ($null -ne $moduleFinding) { $moduleFinding.ExecutionEvidence += "PID $($record.PID): loaded module observed"; $moduleFinding.Launcher=$record.Launcher }
                        }
                    }
                } finally { $native.Dispose() }
            } catch { Add-SourceStatus $State 'JVM Loaded Modules' $false "PID $($record.PID): $($_.Exception.Message)"; Add-ScanWarning $State 'MODULE' $_.Exception.Message "PID $($record.PID)" }
            [void]$State.Processes.Add($record)

            foreach ($agentArgument in @($jvm.JavaAgent)) {
                $agent=($agentArgument -split '=',2)[0]
                if (Test-Path -LiteralPath $agent -PathType Leaf) { Invoke-FileInspection -LiteralPath $agent -State $State -Source 'JVM' -AlwaysRecord | Out-Null }
                else {
                    [void]$State.Findings.Add((New-Finding -Family 'Unknown' -CurrentName ([IO.Path]::GetFileName($agent)) -FullPath $agent -Extension ([IO.Path]::GetExtension($agent)) -ActualFileType 'Unavailable' -Category 'JAVA_AGENT' -Status 'RUNTIME_ONLY' -LoaderType 'Java Agent' -Launcher $record.Launcher -ExecutionEvidence @("PID $($record.PID) -javaagent") -EvidenceSources @('JVM arguments') -Confidence 0 -VerificationStatus 'UNVERIFIED' -Verdict 'RUNTIME TRACE' -DetectionReasons @('Java Agent usage is not automatically a cheat; file content was unavailable.') -Source 'JVM'))
                }
            }
            foreach ($agentPath in @($jvm.AgentPath)) {
                $candidate = ($agentPath -split '=')[0]
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { Invoke-FileInspection -LiteralPath $candidate -State $State -Source 'JVM' -AlwaysRecord | Out-Null }
                else { [void]$State.Findings.Add((New-Finding -CurrentName ([IO.Path]::GetFileName($candidate)) -FullPath $candidate -Extension ([IO.Path]::GetExtension($candidate)) -Category 'JVMTI' -Status 'RUNTIME_ONLY' -Verdict 'RUNTIME TRACE' -EvidenceSources @('JVM arguments') -ExecutionEvidence @("PID $($record.PID): -agentpath") -DetectionReasons @('Native agent argument observed; unavailable content and agent usage do not establish cheating.'))) }
            }
            foreach ($library in @($jvm.AgentLib)) {
                [void]$State.Evidence.Add([pscustomobject]@{ Source='JVM agentlib'; PID=$record.PID; Library=$library; Note='Library name only; agent usage is not cheat evidence.' })
            }
            $runtimePaths=@($jvm.Jar)
            foreach ($classPath in @($jvm.ClassPath)) { $runtimePaths += @($classPath -split ';') }
            foreach ($runtimePath in @($runtimePaths | Sort-Object -Unique)) {
                if ([IO.Path]::IsPathRooted($runtimePath) -and (Test-Path -LiteralPath $runtimePath -PathType Leaf)) {
                    $runtimeFinding=Invoke-FileInspection -LiteralPath $runtimePath -State $State -Source 'JVM_CLASSPATH' -QuietProgress
                    if ($null -ne $runtimeFinding) { $runtimeFinding.ExecutionEvidence += "PID $($record.PID): command-line reference (not proof of class loading)" }
                } elseif ($runtimePath) { [void]$State.Evidence.Add([pscustomobject]@{ Source='JVM unresolved classpath'; Path=$runtimePath; PID=$record.PID; Note='Relative paths and wildcards are not resolved against the scanner working directory.' }) }
            }
            foreach ($argumentFile in @($jvm.ArgFiles)) { Add-SourceStatus $State 'JVM argument file' $false "Argument-file contents not resolved: $argumentFile" }
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
        $zoneStream=Open-ReadOnlyEvidenceStream $streamPath
        try {
            if ($zoneStream.Length -gt $script:Limits.MaximumMetadataBytes) { throw 'Zone metadata exceeds safe parse size.' }
            $zoneReader=[IO.StreamReader]::new($zoneStream,[Text.Encoding]::UTF8,$true,4096,$true)
            try { $text=$zoneReader.ReadToEnd() } finally { $zoneReader.Dispose() }
        } finally { $zoneStream.Dispose() }
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
    $hostFile = Get-Item -LiteralPath $HostPath -Force
    $stream = Open-ReadOnlyEvidenceStream $streamPath
    try {
        $magic = Get-MagicInfoFromStream -Stream $stream -DisplayedExtension ([IO.Path]::GetExtension($HostPath))
        $sha256 = Get-StreamSha256 $stream
        $signatureMatches = [System.Collections.ArrayList]::new()
        foreach ($sig in (Get-SignaturesByType @('SHA256'))) { if ([string]$sig.Value -eq $sha256) { Add-SignatureMatch $signatureMatches $sig "$HostPath`:$streamName" $sha256 } }
        $jar = $null
        if ($magic.ActualType -eq 'Java Archive / ZIP') {
            $stream.Position = 0
            $jar = Inspect-ZipStream -Stream $stream -DisplayPath "$HostPath`:$streamName" -State $State
            foreach ($match in $jar.Matches) { [void]$signatureMatches.Add($match) }
        } else {
            $stream.Position=0
            $content=Read-ContentInspection $stream @(Get-SignaturesByType @('String','ByteSequence','LoaderIndicator','RuntimeIndicator'))
            if ($content.SHA256 -ne $sha256) { throw 'ADS changed during inspection.' }
            foreach ($sig in $content.Matches) { Add-SignatureMatch $signatureMatches $sig "$HostPath`:$streamName" '[byte content match]' }
        }
        $score = Get-ScoreForMatches @($signatureMatches) $false $false $true
        $knownClean = Test-KnownCleanHash $sha256
        $decision = Get-Decision @($signatureMatches) $score $knownClean
        $reasons = [System.Collections.ArrayList]::new()
        foreach ($match in @($signatureMatches | Sort-Object ID -Unique)) { [void]$reasons.Add("$($match.Type) signature $($match.ID) matched in ADS $streamName") }
        if ($magic.ActualType -eq 'Windows PE') { [void]$reasons.Add('Named ADS contains an embedded PE payload; this is not automatically DoomsDay.') }
        elseif ($magic.ActualType -eq 'Java Archive / ZIP') { [void]$reasons.Add('Named ADS contains an embedded archive payload; this is not automatically DoomsDay.') }
        elseif ($magic.ActualType -eq 'Java Class') { [void]$reasons.Add('Named ADS contains an embedded Java class; this is not automatically DoomsDay.') }
        if ($reasons.Count -eq 0) { [void]$reasons.Add('Named ADS is present but no DoomsDay-specific signature matched.') }
        $finding = New-Finding -Family $(if ($signatureMatches.Count -gt 0) {'DoomsDay'} else {'Unknown'}) -CurrentName "$($hostFile.Name):$streamName" `
            -FullPath "$($hostFile.FullName):$streamName" -Extension $hostFile.Extension -ActualFileType $magic.ActualType -Category 'ADS_PAYLOAD' -Status 'ADS' `
            -Size ([long]$StreamInfo.Length) -SHA256 $sha256 -CreatedUtc $hostFile.CreationTimeUtc -ModifiedUtc $hostFile.LastWriteTimeUtc -LastAccessUtc $hostFile.LastAccessTimeUtc `
            -EvidenceSources @('ADS') -Evidence @($signatureMatches) -Confidence $score -VerificationStatus $decision.Verification -Verdict $decision.Verdict `
            -DetectionReasons @($reasons) -Source 'ADS' -MagicBytes $magic.MagicBytes
        if ($decision.EligibleForDetected) {
            $confirm=Confirm-FileFinding -LiteralPath $streamPath -InitialFinding $finding -InitialMatchIds @($signatureMatches | Select-Object -ExpandProperty ID) -State $State
            $finding.VerificationStatus=$confirm.Status
            $finding.Verdict=if ($confirm.Verified) { 'DETECTED' } else { 'INCONCLUSIVE' }
            $finding.DetectionReasons += $confirm.Reason
        }
        if ($null -ne $jar -and -not $jar.AllEntriesScanned) { $State.FilesSkipped++; $finding.Verdict='INCONCLUSIVE'; $finding.VerificationStatus='UNVERIFIED' }
        [void]$State.Findings.Add($finding); $State.AdsFindings++
        return $finding
    } finally { $stream.Dispose() }
}

function Read-AdsHostEvidence {
    param([string]$HostPath,$State)
    $errors=0
    try {
        Test-WorkerCancellation
        $streams=@(Get-Item -LiteralPath $HostPath -Stream * -ErrorAction Stop)
        foreach ($streamInfo in $streams) {
            Test-WorkerCancellation
            $name=[string]$streamInfo.Stream
            if ($name -in @(':$DATA','::$DATA','$DATA')) { continue }
            try {
                if ($name -ieq 'Zone.Identifier') {
                    $zoneMagic=Get-MagicInfo "$HostPath`:$name"
                    if ($zoneMagic.ActualType -in @('Windows PE','Java Archive / ZIP','Java Class')) {
                        Inspect-AdsPayload -HostPath $HostPath -StreamInfo $streamInfo -State $State | Out-Null
                    } else {
                        $zone=Get-ZoneIdentifier -HostPath $HostPath -StreamName $name
                        [void]$State.Evidence.Add([pscustomobject][ordered]@{
                            Source='Zone.Identifier'; HostPath=$HostPath; Stream=$name; Length=[long]$streamInfo.Length
                            ZoneId=$zone.ZoneId; ReferrerUrl=$zone.ReferrerUrl; HostUrl=$zone.HostUrl
                        })
                    }
                } else { Inspect-AdsPayload -HostPath $HostPath -StreamInfo $streamInfo -State $State | Out-Null }
            } catch [OperationCanceledException] { throw }
            catch { $errors++; $State.CorruptedUnreadable++; Add-ScanWarning $State 'ADS' $_.Exception.Message "$HostPath`:$name" }
        }
    } catch [OperationCanceledException] { throw }
    catch { $errors++; $State.FilesSkipped++; Add-ScanWarning $State 'ADS' $_.Exception.Message $HostPath }
    return $errors
}

function Invoke-AdsScan {
    param([string[]]$Roots, $State, [switch]$DeepScan, [string[]]$FileInventory)
    Write-Stage 'ADS' 'Enumerating NTFS alternate data streams (read-only)...'
    $files = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($PSBoundParameters.ContainsKey('FileInventory')) {
        foreach ($filePath in $FileInventory) { [void]$files.Add($filePath) }
    } else {
        Write-ScanProgress -Activity 'ADS' -Status 'Finding ADS hosts; total pending' -Current 0 -Total 0
        Get-ReadOnlyFiles -Roots $Roots -State $State -Recurse:$DeepScan | ForEach-Object {
            [void]$files.Add($_.FullName)
            Write-ScanProgress -Activity 'ADS' -Status 'Finding ADS hosts; counting' -Current $files.Count -Total 0
        }
    }
    Write-ScanProgress -Completed
    $adsErrors=0
    $fileList = @($files | Sort-Object)
    if ($fileList.Count -gt 0) { Write-Stage 'ADS' ("Checking ADS on {0:N0} files with one-line progress." -f $fileList.Count) }
    if ($script:WorkerCount -gt 1 -and $fileList.Count -gt 1) {
        $adsErrors=Invoke-ParallelInspection -Files $fileList -State $State -TaskMode ADS
    } else {
        $fileIndex=0
        foreach ($file in $fileList) {
            $fileIndex++
            Write-ScanProgress -Activity 'ADS' -Status 'Reading named streams' -Current $fileIndex -Total $fileList.Count
            $adsErrors += Read-AdsHostEvidence -HostPath $file -State $State
        }
    }
    Write-ScanProgress -Activity 'Reveal ScreenShare - ADS analysis' -Completed
    if ($fileList.Count -gt 0) { Write-Color ("[ADS] {0:N0} files checked; {1:N0} named payload streams found." -f $fileList.Count, $State.AdsFindings) Magenta }
    Add-SourceStatus $State 'NTFS Alternate Data Streams (files)' ($adsErrors -eq 0) ("{0} named streams; {1} failures" -f $State.AdsFindings,$adsErrors)
    if ($PSVersionTable.PSVersion -lt [Version]'7.2') { Add-SourceStatus $State 'Directory ADS' $false 'Windows PowerShell 5.1 Stream provider does not enumerate directory streams.' }
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
        Add-SourceStatus $State 'USN Journal (raw CSV candidates)' $true "$count candidate records"
        Add-SourceStatus $State 'USN identity/path reconstruction' $false 'Raw fsutil candidate lines only; no FRN-based rename chain or complete path reconstruction is asserted.'
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
                    foreach ($name in $item.GetValueNames()) { if ($name -match '(?i)\.(jar|exe|dll|class|zip)$') { [void]$State.Evidence.Add([pscustomobject]@{ Source='PcaSvc/Persisted'; Path=$name }) } }
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
    param($State,[switch]$UseCollectedZones)
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
    $databasePaths=[Collections.Generic.List[string]]::new()
    if ($null -ne $script:FileInventory) {
        foreach ($filePath in $script:FileInventory) {
            if ([IO.Path]::GetFileName($filePath) -in @('History','places.sqlite')) { $databasePaths.Add($filePath) }
        }
    }
    foreach ($browser in $profiles.Keys) {
        $root = $profiles[$browser]
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        try {
            $databases=if ($null -ne $script:FileInventory) {
                foreach ($filePath in $databasePaths) {
                    if ($filePath.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { Get-Item -LiteralPath $filePath -Force -ErrorAction Stop }
                }
            } else { Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object Name -in @('History','places.sqlite') }
            foreach ($db in @($databases)) {
                [void]$State.Evidence.Add([pscustomobject][ordered]@{
                    Source='Browser Profile Database'; Browser=$browser; Path=$db.FullName; Size=$db.Length
                    ModifiedUtc=$db.LastWriteTimeUtc; Note='Database presence recorded read-only. URL evidence is collected from Zone.Identifier without opening locked SQLite databases.'
                })
            }
        } catch { Add-ScanWarning $State 'BROWSER' $_.Exception.Message $root }
    }
    $downloads = if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'Downloads' } else { '' }
    $count = 0
    if ($UseCollectedZones) {
        $zones=@($State.Evidence | Where-Object { $_.Source -eq 'Zone.Identifier' })
        foreach ($zone in $zones) {
            try {
                $file=Get-Item -LiteralPath $zone.HostPath -Force -ErrorAction Stop
                [void]$State.Evidence.Add([pscustomobject][ordered]@{
                    Source='Browser Downloads / Zone.Identifier'; Filename=$file.Name; URL=$zone.HostUrl
                    Referrer=$zone.ReferrerUrl; TargetPath=$file.FullName; DownloadTime=$null; FileCreatedUtc=$file.CreationTimeUtc
                    Browser='Unknown'; CurrentFileExists=$true; ZoneId=$zone.ZoneId
                }); $count++
            } catch { Add-ScanWarning $State 'BROWSER' $_.Exception.Message $zone.HostPath }
        }
    } elseif ($downloads -and (Test-Path -LiteralPath $downloads -PathType Container)) {
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $downloads -File -Recurse -Force -ErrorAction SilentlyContinue)) {
                try {
                    $zoneStream = @(Get-Item -LiteralPath $file.FullName -Stream 'Zone.Identifier' -ErrorAction Stop)[0]
                    if ($zoneStream) {
                        $zone = Get-ZoneIdentifier $file.FullName 'Zone.Identifier'
                        [void]$State.Evidence.Add([pscustomobject][ordered]@{
                            Source='Browser Downloads / Zone.Identifier'; Filename=$file.Name; URL=$zone.HostUrl
                            Referrer=$zone.ReferrerUrl; TargetPath=$file.FullName; DownloadTime=$null; FileCreatedUtc=$file.CreationTimeUtc
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
                if ($line -match '(?i)javaw?|\.jar|\.dll|\.exe|loader|minecraft|agentpath|javaagent|oracle_jre_usage|WriteProcessMemory|VirtualQueryEx|pymem') {
                    [void]$State.Evidence.Add([pscustomobject]@{ Source='PSReadLine History'; Path=$historyPath; Line=$lineNumber; Command=$line }); $count++
                }
            }
        } catch { Add-ScanWarning $State 'POWERSHELL' $_.Exception.Message $historyPath }
    }
    try {
        $start = (Get-Date).AddDays(-30)
        $events = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=@(4103,4104); StartTime=$start } -ErrorAction Stop
        foreach ($event in $events) {
            if ($event.Message -match '(?i)javaw?|\.jar|\.dll|\.exe|loader|minecraft|agentpath|javaagent|oracle_jre_usage|WriteProcessMemory|VirtualQueryEx|pymem') {
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
            } elseif ($event.Message -match '(?i)javaw?|\.jar|\.dll|loader|minecraft|agentpath|javaagent|oracle_jre_usage|WriteProcessMemory|VirtualQueryEx|pymem') {
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
                Add-SourceStatus $State ($entry.Source+' metadata') $true 'Metadata available'
                Add-SourceStatus $State ($entry.Source+' record parsing') $false 'Database/hive records are not decoded by this collector.'
            } catch { Add-SourceStatus $State $entry.Source $false $_.Exception.Message }
        } else { Add-SourceStatus $State $entry.Source $false 'Source not present' }
    }
}

function Get-EventXmlFields {
    param([string]$XmlText)
    $settings=[Xml.XmlReaderSettings]::new(); $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit; $settings.XmlResolver=$null
    $source=[IO.StringReader]::new($XmlText); $reader=[Xml.XmlReader]::Create($source,$settings)
    try {
        $document=[Xml.XmlDocument]::new(); $document.XmlResolver=$null; $document.Load($reader)
        $fields=@{}
        foreach ($node in $document.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) { $fields[$node.GetAttribute('Name')]=[string]$node.InnerText }
        return $fields
    } finally { $reader.Dispose(); $source.Dispose() }
}

function Get-SysmonEvidence {
    param($State)
    Write-Stage 'SYSMON' 'Reading existing Java-related events; no service installation or configuration changes.'
    $log='Microsoft-Windows-Sysmon/Operational'
    try {
        $logInfo=Get-WinEvent -ListLog $log -ErrorAction Stop
        if (-not $logInfo.IsEnabled) { Add-SourceStatus $State 'Sysmon' $false 'Log disabled; no inference of cheating.'; return }
        $filter=@{ LogName=$log; Id=@(1,7,8,10,11,15,23,25,26); StartTime=(Get-Date).AddDays(-30) }
        $count=0
        try {
            Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | ForEach-Object {
                $event=$_; $data=Get-EventXmlFields $event.ToXml()
                $values=@($data.Values) -join ' '
                if ($values -match '(?i)javaw?\.exe|minecraft|\.jar(?:\s|$)|oracle_jre_usage|doomsday') {
                    $path=''
                    switch ($event.Id) { 7 { $path=[string]$data.ImageLoaded }; {$_ -in @(11,15,23,26)} { $path=[string]$data.TargetFilename }; default { $path=[string]$data.Image } }
                    $hash=''
                    if ($event.Id -in @(1,7,23,26) -and [string]$data.Hashes -match '(?:^|[,;])SHA256=([A-Fa-f0-9]{64})(?:$|[,;])') { $hash=$Matches[1].ToUpperInvariant() }
                    $record=[pscustomobject]@{ Source='Sysmon'; EventId=$event.Id; RecordId=$event.RecordId; TimeCreatedUtc=$event.TimeCreated.ToUniversalTime(); Path=$path; SHA256=$hash; ProcessGuid=[string]$data.ProcessGuid; Data=$data }
                    [void]$State.Evidence.Add($record); $count++
                    if ($event.Id -in @(8,10) -and [string]$data.TargetImage -match '(?i)\\javaw?\.exe$') {
                        $sourcePath=[string]$data.SourceImage
                        [void]$State.Findings.Add((New-Finding -CurrentName ([IO.Path]::GetFileName($sourcePath)) -FullPath $sourcePath -Extension ([IO.Path]::GetExtension($sourcePath)) -Category 'UNKNOWN' -Status 'UNKNOWN' -Verdict 'RUNTIME TRACE' -EvidenceSources @('Sysmon') -Evidence @($record) -ExecutionEvidence @("Sysmon event $($event.Id), record $($event.RecordId), target $($data.TargetImage)") -DetectionReasons @('Process access or remote-thread event involving Java. Debuggers, overlays and security tools also produce these events; not DoomsDay evidence.')))
                    }
                    if ($event.Id -eq 25) { [void]$State.Integrity.Add([pscustomobject]@{ Severity='WARNING'; Code='SYSMON_PROCESS_TAMPERING'; Path=$path; RecordId=$event.RecordId; Message='Sysmon process-image tampering event; family attribution unavailable.' }) }
                    if ($event.Id -in @(23,26) -and $path) {
                        $hashMatches=@(Get-SignaturesByType @('SHA256') | Where-Object { $_.Value -eq $hash -and $_.PSObject.Properties['Verified'] -and $_.Verified -is [bool] -and $_.Verified })
                        if ($hashMatches.Count -gt 0 -and -not (Test-KnownCleanHash $hash)) {
                            $historicalVerified=$false
                            try {
                                $again=Get-WinEvent -LogName $log -FilterXPath ("*[System[EventRecordID={0}]]" -f $event.RecordId) -ErrorAction Stop
                                $againData=Get-EventXmlFields $again.ToXml()
                                $historicalVerified=([string]$againData.Hashes -eq [string]$data.Hashes -and [string]$againData.TargetFilename -eq $path)
                            } catch { }
                            [void]$State.Findings.Add((New-Finding -Family 'DoomsDay' -CurrentName ([IO.Path]::GetFileName($path)) -FullPath $path -Extension ([IO.Path]::GetExtension($path)) -Status 'DELETED' -Category 'DELETED_PAYLOAD' -SHA256 $hash -Verdict 'DELETED TRACE' -VerificationStatus $(if ($historicalVerified) {'VERIFIED'} else {'UNVERIFIED'}) -EvidenceSources @('Sysmon deletion hash') -Evidence @($record) -DetectionReasons @('Historical SHA-256 matches an attested family signature. Verification concerns the reread event, not recovered payload bytes; current same-path files are not assumed identical.')))
                        }
                    }
                }
            }
        } catch { if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw } }
        Add-SourceStatus $State 'Sysmon' $true "$count relevant events within 30 days; event availability depends on pre-existing configuration."
    } catch { Add-SourceStatus $State 'Sysmon' $false $_.Exception.Message; Add-ScanWarning $State 'SYSMON' 'Existing log could not be read; this is not evidence of bypass.' }
}

function Get-OracleUsageEvidence {
    param($State)
    if (-not $env:ProgramData) { return }
    $root=Join-Path $env:ProgramData 'Oracle\Java\.oracle_jre_usage'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        [void]$State.Evidence.Add([pscustomobject]@{ Source='Oracle JRE usage'; Path=$root; Exists=$false; Note='Absence is normal on many Java installations and is not evidence of deletion or bypass.' })
        return
    }
    foreach ($file in Get-ReadOnlyFiles -Roots @($root) -State $State -Recurse) {
        try {
            $lines=@()
            if ($file.Length -le 1048576) { $lines=@([IO.File]::ReadLines($file.FullName) | Where-Object { $_ -match '(?i)java|\.jar|minecraft' }) }
            [void]$State.Evidence.Add([pscustomobject]@{ Source='Oracle JRE usage'; Path=$file.FullName; ModifiedUtc=$file.LastWriteTimeUtc; RelevantLines=$lines; Note='Java usage context only, not a DoomsDay signature.' })
        } catch { Add-ScanWarning $State 'JRE USAGE' $_.Exception.Message $file.FullName }
    }
}

function Get-PrefetchNativeApi {
    if ($null -ne $script:PrefetchNativeApi) { return $script:PrefetchNativeApi }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'MAM decompression requires Windows.' }
    # Only documented decompression plus the Windows CRC routine; no C# compiler.
    $name=[Reflection.AssemblyName]::new('RevealPrefetch_'+[guid]::NewGuid().ToString('N'))
    $assembly=[Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($name,[Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module=$assembly.DefineDynamicModule($name.Name)
    $type=$module.DefineType('RevealPrefetchApi',([Reflection.TypeAttributes]::Public -bor [Reflection.TypeAttributes]::Abstract -bor [Reflection.TypeAttributes]::Sealed))
    $attributes=[Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl
    $definitions=@(
        @{ Name='RtlGetCompressionWorkSpaceSize'; Parameters=[Type[]]@([uint16],[uint32].MakeByRefType(),[uint32].MakeByRefType()) },
        @{ Name='RtlDecompressBufferEx'; Parameters=[Type[]]@([uint16],[IntPtr],[uint32],[IntPtr],[uint32],[uint32].MakeByRefType(),[IntPtr]) },
        @{ Name='RtlComputeCrc32'; Parameters=[Type[]]@([uint32],[byte[]],[uint32]) }
    )
    foreach ($definition in $definitions) {
        $method=$type.DefinePInvokeMethod($definition.Name,(Join-Path ([Environment]::SystemDirectory) 'ntdll.dll'),$definition.Name,$attributes,
            [Reflection.CallingConventions]::Standard,[uint32],$definition.Parameters,
            [Runtime.InteropServices.CallingConvention]::Winapi,[Runtime.InteropServices.CharSet]::Ansi)
        $method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    }
    $script:PrefetchNativeApi=$type.CreateType()
    return $script:PrefetchNativeApi
}

function Expand-PrefetchBytes {
    param([byte[]]$Bytes)
    if ($Bytes.Length -lt 8 -or $Bytes.Length -gt 32MB) { throw 'Prefetch length outside parser safety bounds.' }
    if ([Text.Encoding]::ASCII.GetString($Bytes,0,3) -ne 'MAM') { return ,$Bytes }
    $format=$Bytes[3] -band 127
    if ($format -ne 4) { throw 'Unsupported MAM compression format.' }
    $expanded=[BitConverter]::ToUInt32($Bytes,4)
    if ($expanded -lt 8 -or $expanded -gt 32MB) { throw 'MAM expanded-size safety limit exceeded.' }
    $offset=8
    $api=Get-PrefetchNativeApi
    if (($Bytes[3] -band 128) -ne 0) {
        if ($Bytes.Length -lt 13) { throw 'Truncated MAM checksum header.' }
        $expected=[BitConverter]::ToUInt32($Bytes,8)
        $check=[byte[]]$Bytes.Clone(); [Array]::Clear($check,8,4)
        if ($api::RtlComputeCrc32(0,$check,[uint32]$check.Length) -ne $expected) { throw 'MAM checksum mismatch.' }
        $offset=12
    }
    if ($Bytes.Length -le $offset) { throw 'MAM compressed block missing.' }
    [uint32]$compressionWorkspace=0; [uint32]$fragmentWorkspace=0
    if ($api::RtlGetCompressionWorkSpaceSize(4,[ref]$compressionWorkspace,[ref]$fragmentWorkspace) -ne 0) { throw 'Windows decompression workspace unavailable.' }
    $workspaceSize=[Math]::Max($compressionWorkspace,$fragmentWorkspace)
    if ($workspaceSize -lt 1 -or $workspaceSize -gt 32MB) { throw 'Invalid decompression workspace size.' }
    $inputMemory=[IntPtr]::Zero; $outputMemory=[IntPtr]::Zero; $workspace=[IntPtr]::Zero
    try {
        $length=$Bytes.Length-$offset
        $inputMemory=[Runtime.InteropServices.Marshal]::AllocHGlobal($length)
        $outputMemory=[Runtime.InteropServices.Marshal]::AllocHGlobal([int]$expanded)
        $workspace=[Runtime.InteropServices.Marshal]::AllocHGlobal([int]$workspaceSize)
        [Runtime.InteropServices.Marshal]::Copy($Bytes,$offset,$inputMemory,$length)
        [uint32]$written=0
        $status=$api::RtlDecompressBufferEx(4,$outputMemory,$expanded,$inputMemory,[uint32]$length,[ref]$written,$workspace)
        if ($status -ne 0 -or $written -ne $expanded) { throw ('MAM decompression failed: status 0x{0:X8}; output {1}/{2}.' -f $status,$written,$expanded) }
        $output=[byte[]]::new([int]$expanded)
        [Runtime.InteropServices.Marshal]::Copy($outputMemory,$output,0,$output.Length)
        return ,$output
    } finally {
        foreach ($pointer in @($inputMemory,$outputMemory,$workspace)) { if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer) } }
    }
}

function Read-PrefetchRecord {
    param([byte[]]$Bytes)
    $data=Expand-PrefetchBytes $Bytes
    if ($data.Length -lt 208 -or [Text.Encoding]::ASCII.GetString($data,4,4) -ne 'SCCA') { throw 'Invalid or truncated SCCA header.' }
    $version=[BitConverter]::ToUInt32($data,0)
    if ($version -notin @(26,30,31)) { throw "Unsupported Prefetch version: $version" }
    $declared=[BitConverter]::ToUInt32($data,12)
    if ($declared -ne $data.Length) { throw 'SCCA declared file size does not match decompressed length.' }
    $offset=[long][BitConverter]::ToUInt32($data,100); $size=[long][BitConverter]::ToUInt32($data,104)
    if ($offset -lt 208 -or $size -lt 2 -or $size%2 -ne 0 -or $offset+$size -gt $data.Length) { throw 'Invalid Prefetch filename section.' }
    $text=[Text.UnicodeEncoding]::new($false,$false,$true).GetString($data,[int]$offset,[int]$size)
    if (-not $text.EndsWith([string][char]0)) { throw 'Unterminated Prefetch filename section.' }
    $references=@($text.Split([char]0) | Where-Object { $_.Length -gt 0 })
    $volumeOffset=[long][BitConverter]::ToUInt32($data,108)
    $volumeCount=[long][BitConverter]::ToUInt32($data,112)
    $volumeSize=[long][BitConverter]::ToUInt32($data,116)
    $recordSize=if ($version -eq 26) { 104L } else { 96L }
    if ($volumeCount -gt 1024 -or $volumeCount*$recordSize -gt $volumeSize -or $volumeOffset+$volumeSize -gt $data.Length) { throw 'Invalid Prefetch volume table.' }
    if ($volumeCount -gt 0 -and $volumeOffset -lt 208) { throw 'Prefetch volume table overlaps the header.' }
    $volumes=[Collections.Generic.List[object]]::new()
    for ($i=0; $i -lt $volumeCount; $i++) {
        $entry=[int]($volumeOffset+$i*$recordSize)
        $pathOffset=[long][BitConverter]::ToUInt32($data,$entry)
        $pathSize=2L*[BitConverter]::ToUInt32($data,$entry+4)
        if ($pathOffset -lt $volumeCount*$recordSize -or $pathSize -le 0 -or $pathOffset+$pathSize -gt $volumeSize) { throw 'Invalid Prefetch volume path.' }
        $volumePath=[Text.Encoding]::Unicode.GetString($data,[int]($volumeOffset+$pathOffset),[int]$pathSize).TrimEnd([char]0)
        $volumes.Add([pscustomobject]@{ DevicePath=$volumePath; Serial=('{0:X8}' -f [BitConverter]::ToUInt32($data,$entry+16)); CreatedFileTime=[BitConverter]::ToInt64($data,$entry+8) })
    }
    $times=[Collections.Generic.List[DateTime]]::new()
    for ($i=0; $i -lt 8; $i++) {
        $fileTime=[BitConverter]::ToInt64($data,128+8*$i)
        if ($fileTime -gt 0) { $times.Add([DateTime]::FromFileTimeUtc($fileTime)) }
    }
    $metricsOffset=[BitConverter]::ToUInt32($data,84)
    $runCount=$null
    if ($metricsOffset -eq 296 -and $version -in @(30,31)) { $runCount=[BitConverter]::ToUInt32($data,200) }
    elseif ($metricsOffset -eq 304 -and $data.Length -ge 212) { $runCount=[BitConverter]::ToUInt32($data,208) }
    [pscustomobject]@{ Version=$version; Executable=[Text.Encoding]::Unicode.GetString($data,16,60).TrimEnd([char]0); RunCount=$runCount; LastRunTimesUtc=$times.ToArray(); References=$references; Volumes=$volumes.ToArray() }
}

function Get-FastLocalVolumes {
    param($State)
    try {
        foreach ($disk in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)) {
            [pscustomobject]@{ Root=([string]$disk.DeviceID+'\'); Serial=([string]$disk.VolumeSerialNumber).Replace('-','').ToUpperInvariant().PadLeft(8,'0') }
        }
    } catch { Add-SourceStatus $State 'Local volume mapping' $false $_.Exception.Message; Add-ScanWarning $State 'VOLUME' $_.Exception.Message }
}

function Resolve-PrefetchReference {
    param([string]$Reference,[object[]]$PrefetchVolumes,[object[]]$CurrentVolumes)
    if ($Reference -match '^[A-Za-z]:\\') {
        if (@($CurrentVolumes | Where-Object { $_.Root -ieq $Reference.Substring(0,3) }).Count -eq 1 -and $Reference -notmatch '(?:^|\\)\.\.(?:\\|$)') { return $Reference }
        return $null
    }
    foreach ($volume in $PrefetchVolumes) {
        $prefix=$volume.DevicePath.TrimEnd('\')+'\'
        if ($Reference.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
            $matches=@($CurrentVolumes | Where-Object { $_.Serial -eq $volume.Serial -and $_.Serial -ne '00000000' })
            # No guessed C: path and no filename-only correlation across drives.
            if ($matches.Count -ne 1) { return $null }
            $relative=$Reference.Substring($prefix.Length)
            if ($relative -match '(^|\\)\.\.(\\|$)|:' -or $relative.StartsWith('\')) { return $null }
            return $matches[0].Root+$relative
        }
    }
    return $null
}

function Add-FastCandidate {
    param([string]$Candidate,[string]$Source,$State,$Candidates,$Hosts,[object[]]$CurrentVolumes,[int]$ProcessId=0,[string]$Artifact='')
    if (-not $Candidate) { return }
    $record=[pscustomobject]@{ Source=$Source; Path=$Candidate; PID=$ProcessId; Artifact=$Artifact; CurrentFileExists=$false; TimeCreatedUtc=$null; Note='Reference only; not proof of payload execution or DoomsDay.' }
    [void]$State.Evidence.Add($record)
    # Do not connect to shares or resolve relative paths against this scanner's cwd.
    $local=($Candidate -match '^[A-Za-z]:\\' -and @($CurrentVolumes | Where-Object { $_.Root -ieq $Candidate.Substring(0,3) }).Count -eq 1)
    if (-not $local -or $Candidate -match '[*?]|(?:^|\\)\.\.(?:\\|$)') {
        Add-SourceStatus $State 'Unresolved candidate reference' $false $Candidate
        return
    }
    try {
        $item=Get-Item -LiteralPath $Candidate -Force -ErrorAction Stop
        if ($item.PSIsContainer) { return }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse candidate not followed.' }
        $record.CurrentFileExists=$true
        if (-not $Hosts.Add($item.FullName)) { return }
        $State.DiscoveredFiles++
        $candidateExtension=$item.Extension -match '^(?i:\.jar|\.zip|\.dll|\.exe|\.class|\.dat|\.tmp|\.bin|\.ps1|\.bat|\.cmd|\.vbs)$'
        $magic=Get-MagicInfo $item.FullName
        if ($candidateExtension -or $magic.ActualType -ne 'Unknown') { [void]$Candidates.Add($item.FullName) }
    } catch [System.Management.Automation.ItemNotFoundException] {
        # A missing historical reference might have moved; deletion is not established.
        if ($Source -like 'JVM*' -or [IO.Path]::GetFileName($Candidate) -match '(?i)dooms[ _-]?day') {
            [void]$State.Findings.Add((New-Finding -CurrentName ([IO.Path]::GetFileName($Candidate)) -FullPath $Candidate -Extension ([IO.Path]::GetExtension($Candidate)) -Status 'UNKNOWN' -Verdict 'REVIEW' -EvidenceSources @($Source) -DetectionReasons @('Referenced file is currently unavailable. Neither deletion nor DoomsDay is established by this reference.')))
        }
        Add-SourceStatus $State 'Missing referenced file' $false $Candidate
    } catch {
        $State.FilesSkipped++; Add-ScanWarning $State $Source $_.Exception.Message $Candidate
    }
}

function Get-FastPrefetchCandidates {
    param($State,$Candidates,$Hosts,[object[]]$CurrentVolumes,[string]$Directory=(Join-Path $env:SystemRoot 'Prefetch'))
    Write-Stage 'PREFETCH' 'Reading Java Prefetch references; no full-disk or USN scan...'
    try { $files=@(Get-ChildItem -LiteralPath $Directory -Filter '*.pf' -File -Force -ErrorAction Stop | Where-Object { $_.Name -match '(?i)^JAVAW?\.EXE-[0-9A-F]+\.pf$' }) }
    catch { Add-SourceStatus $State 'Java Prefetch' $false $_.Exception.Message; Add-ScanWarning $State 'PREFETCH' $_.Exception.Message; return }
    if ($files.Count -eq 0) { Add-SourceStatus $State 'Java Prefetch' $false 'No Java Prefetch files available; absence is not cheat evidence.'; return }
    $index=0; $failures=0
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $files) {
        $index++; Write-ScanProgress -Current $index -Total $files.Count -Status 'Parsing Java Prefetch'
        try {
            if ($file.Length -gt 32MB -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Prefetch input exceeds safety bounds or is a reparse point.' }
            $record=Read-PrefetchRecord ([IO.File]::ReadAllBytes($file.FullName))
            if ($record.Executable -notin @('JAVA.EXE','JAVAW.EXE')) { throw 'Prefetch executable does not match Java selection.' }
            [void]$State.Evidence.Add([pscustomobject]@{ Source='Java Prefetch metadata'; Path=$file.FullName; Version=$record.Version; Executable=$record.Executable; RunCount=$record.RunCount; LastRunTimesUtc=$record.LastRunTimesUtc; Volumes=$record.Volumes; Note='Times apply to Java, not to each referenced file.' })
            $State.TotalIndexesExtracted += $record.References.Count
            foreach ($reference in $record.References) {
                if (-not $seen.Add($reference)) { continue }
                $resolved=Resolve-PrefetchReference $reference $record.Volumes $CurrentVolumes
                if ($resolved) { Add-FastCandidate $resolved 'Java Prefetch reference' $State $Candidates $Hosts $CurrentVolumes -Artifact $file.FullName }
                else {
                    [void]$State.Evidence.Add([pscustomobject]@{ Source='Unresolved Prefetch reference'; Path=$reference; Artifact=$file.FullName; Note='Current local volume could not be uniquely mapped; no path guessed.' })
                    Add-SourceStatus $State 'Prefetch path mapping' $false $reference
                }
            }
        } catch { $failures++; Add-ScanWarning $State 'PREFETCH' $_.Exception.Message $file.FullName }
    }
    Write-ScanProgress -Completed
    Add-SourceStatus $State 'Java Prefetch' ($failures -eq 0) ("$($files.Count) files; $failures parse failures")
}

function Get-FastRuntimeCandidates {
    param($State,$Candidates,$Hosts,$ModRoots,[object[]]$CurrentVolumes)
    Write-Stage 'PROCESS' 'Collecting Java arguments and module paths (not RAM content)...'
    try {
        $processes=@(Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction Stop)
        foreach ($process in $processes) {
            $processIdValue=[int]$process.ProcessId
            $jvm=Get-JvmArguments ([string]$process.CommandLine)
            $record=[pscustomobject]@{ PID=$processIdValue; PPID=[int]$process.ParentProcessId; ExecutablePath=[string]$process.ExecutablePath; CommandLine=[string]$process.CommandLine; JvmArguments=$jvm; Launcher=(Get-LauncherFromCommandLine ([string]$process.CommandLine)); LoadedModules=[Collections.Generic.List[string]]::new() }
            [void]$State.Processes.Add($record)
            if (-not $process.CommandLine) { Add-SourceStatus $State 'JVM command line' $false "PID $processIdValue command line unavailable." }
            foreach ($game in $jvm.GameDirectories) { if ($game -match '^[A-Za-z]:\\') { [void]$ModRoots.Add(($game.TrimEnd('\')+'\mods')) } }
            $paths=@($jvm.Jar)
            foreach ($agent in @($jvm.JavaAgent)+@($jvm.AgentPath)) { $paths += ($agent -split '=',2)[0] }
            foreach ($classPath in $jvm.ClassPath) { $paths += @($classPath -split ';') }
            foreach ($candidate in @($paths | Sort-Object -Unique)) { Add-FastCandidate $candidate 'JVM argument reference' $State $Candidates $Hosts $CurrentVolumes -ProcessId $processIdValue }
            foreach ($argumentFile in $jvm.ArgFiles) { Add-SourceStatus $State 'JVM argument file' $false "Not expanded in Fast: $argumentFile" }
            foreach ($agentlib in $jvm.AgentLib) { [void]$State.Evidence.Add([pscustomobject]@{ Source='JVM agentlib'; PID=$processIdValue; Library=$agentlib; Note='Agent use alone does not identify cheats.' }) }
            $native=$null
            try {
                $native=Get-Process -Id $processIdValue -ErrorAction Stop
                foreach ($module in $native.Modules) {
                    $modulePath=[string]$module.FileName
                    $record.LoadedModules.Add($modulePath)
                    Add-FastCandidate $modulePath 'JVM loaded module' $State $Candidates $Hosts $CurrentVolumes -ProcessId $processIdValue
                }
            } catch { Add-SourceStatus $State 'JVM loaded modules' $false "PID ${processIdValue}: $($_.Exception.Message)" }
            finally { if ($null -ne $native) { $native.Dispose() } }
        }
        Add-SourceStatus $State 'Java runtime references' $true "$($processes.Count) Java processes; no RAM-content inspection."
    } catch { Add-SourceStatus $State 'Java runtime references' $false $_.Exception.Message; Add-ScanWarning $State 'PROCESS' $_.Exception.Message }
}

function Invoke-FastScan {
    param($State,[string]$ExtraPath='')
    Write-Section 'FAST TARGETED SCAN'
    $State.Scope='Java Prefetch references, Java arguments/modules, direct known mods folders and optional explicit path; ADS on these hosts only. No broad AppData, USN, browser history, event-log or RAM-content scan.'
    Write-Color $State.Scope Magenta
    $candidates=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $hosts=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $modRoots=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $volumes=@(Get-FastLocalVolumes $State)
    Get-FastRuntimeCandidates $State $candidates $hosts $modRoots $volumes
    Get-FastPrefetchCandidates $State $candidates $hosts $volumes
    foreach ($root in @(Get-MinecraftLocations)) {
        foreach ($relative in @('mods','.minecraft\mods','minecraft\mods')) { [void]$modRoots.Add((Join-Path $root $relative)) }
    }
    if ($ExtraPath) {
        if (Test-Path -LiteralPath $ExtraPath -PathType Container) { [void]$modRoots.Add($ExtraPath) }
        else { Add-FastCandidate $ExtraPath 'Explicit file' $State $candidates $hosts $volumes }
    }
    Write-Stage 'INDEX' 'Collecting direct mods folders; libraries and unrelated AppData are not traversed...'
    foreach ($root in $modRoots) {
        if ($root -notmatch '^[A-Za-z]:\\' -or @($volumes | Where-Object { $_.Root -ieq $root.Substring(0,3) }).Count -ne 1) { continue }
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        if (((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $State.FilesSkipped++; Add-ScanWarning $State 'MODS' 'Reparse mods root not followed.' $root; continue }
        Get-ReadOnlyFiles -Roots @($root) -State $State -Recurse | ForEach-Object {
            Add-FastCandidate $_.FullName 'Mods folder' $State $candidates $hosts $volumes
            Write-ScanProgress -Current $hosts.Count -Total 0 -Status ("Targeted candidates: $($candidates.Count); counting")
        }
    }
    Write-ScanProgress -Completed
    $files=@($candidates | Sort-Object)
    Write-Stage 'SCAN' ("{0:N0} candidate files; {1} workers; all selected file bytes inspected." -f $files.Count,$script:WorkerCount)
    if ($files.Count -gt 0) { [void](Invoke-ParallelInspection -Files $files -State $State) }
    if ($hosts.Count -gt 0) { Invoke-AdsScan -State $State -FileInventory @($hosts) }
    Invoke-EvidenceCorrelation $State
}

function Invoke-QuickScan {
    param($State)
    Write-Section 'QUICK SCAN'
    $roots = @(Get-MinecraftLocations)
    if ($roots.Count -eq 0) { Add-ScanWarning $State 'DISCOVERY' 'No known Minecraft installation directory was found.' }
    else { Invoke-CandidateScan -Roots $roots -State $State }
    Invoke-RuntimeScan -State $State
}

function Get-DefaultAdsRoots {
    param([switch]$IncludeAppData)
    $roots = [System.Collections.ArrayList]::new()
    foreach ($knownFolder in @([Environment]::GetFolderPath('DesktopDirectory'),[Environment]::GetFolderPath('MyDocuments'))) {
        if ($knownFolder -and (Test-Path -LiteralPath $knownFolder -PathType Container)) { [void]$roots.Add($knownFolder) }
    }
    try {
        $shellFolders=Get-ItemProperty -LiteralPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Stop
        $downloadsId='{374DE290-123F-4565-9164-39C4925E467B}'
        if ($shellFolders.PSObject.Properties[$downloadsId]) {
            $downloadsPath=[Environment]::ExpandEnvironmentVariables([string]$shellFolders.$downloadsId)
            if (Test-Path -LiteralPath $downloadsPath -PathType Container) { [void]$roots.Add($downloadsPath) }
        }
    } catch { }
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
    $roots = @(Get-DefaultAdsRoots -IncludeAppData)
    if ($roots.Count -eq 0) { Add-ScanWarning $State 'DISCOVERY' 'No known Minecraft installation directory was found.' }
    else { Invoke-CandidateScan -Roots $roots -State $State -Full }
    Invoke-RuntimeScan -State $State
    Get-SysMainIntegrity -State $State
    Get-SechostIntegrity -State $State
    Get-UsnJournalEvidence -State $State
    Get-RegistryArtifactEvidence -State $State
    Get-RecentAndLinkEvidence -State $State
    Get-PowerShellForensics -State $State
    Get-WindowsEventEvidence -State $State
    Get-SysmonEvidence -State $State
    Get-OracleUsageEvidence -State $State
    Get-AdditionalArtifactMetadata -State $State
    if ($null -ne $script:FileInventory) { Invoke-AdsScan -State $State -FileInventory $script:FileInventory.ToArray() }
    else { Invoke-AdsScan -Roots $roots -State $State -DeepScan }
    Get-BrowserDownloadEvidence -State $State -UseCollectedZones
    Write-Stage 'CORRELATE' 'Building evidence chains...'
    Invoke-EvidenceCorrelation -State $State
}

function Invoke-EvidenceCorrelation {
    param($State)
    $byPath=@{}; $byHash=@{}
    foreach ($evidence in $State.Evidence) {
        foreach ($property in @('Path','FullPath','HostPath','TargetPath')) {
            if ($evidence.PSObject.Properties[$property] -and $evidence.$property) {
                $pathKey=([string]$evidence.$property).ToLowerInvariant()
                if (-not $byPath.ContainsKey($pathKey)) { $byPath[$pathKey]=[Collections.ArrayList]::new() }
                [void]$byPath[$pathKey].Add($evidence)
            }
        }
        if ($evidence.PSObject.Properties['SHA256'] -and [string]$evidence.SHA256 -match '^[A-Fa-f0-9]{64}$') {
            $hashKey=([string]$evidence.SHA256).ToUpperInvariant()
            if (-not $byHash.ContainsKey($hashKey)) { $byHash[$hashKey]=[Collections.ArrayList]::new() }
            [void]$byHash[$hashKey].Add($evidence)
        }
    }
    foreach ($finding in $State.Findings) {
        $links=[Collections.ArrayList]::new()
        $pathKey=([string]$finding.Path).ToLowerInvariant()
        if ($byPath.ContainsKey($pathKey)) {
            foreach ($evidence in $byPath[$pathKey]) { [void]$links.Add([pscustomobject]@{ Kind='EXACT_PATH_CONTEXT_ONLY'; Record=$evidence }) }
        }
        if ($finding.SHA256 -and $byHash.ContainsKey($finding.SHA256.ToUpperInvariant())) {
            foreach ($evidence in $byHash[$finding.SHA256.ToUpperInvariant()]) { [void]$links.Add([pscustomobject]@{ Kind='EXACT_SHA256'; Record=$evidence }) }
        }
        foreach ($link in $links) {
            $source=[string]$link.Record.Source
            if ($source -and $source -notin $finding.EvidenceSources) { $finding.EvidenceSources += $source }
        }
        if ($links.Count -gt 0) { $finding.Evidence += @($links) }
        # Same path can be reused by a different file. Context never upgrades a verdict.
    }
}
function Update-DoomsDaySignatures {
    Write-Stage 'UPDATE' 'Downloading JSON signature data only; no remote code will be executed.'
    $previousDatabase=$script:Signatures
    try {
        $response = Invoke-WebRequest -Uri $script:SignatureUrl -UseBasicParsing -TimeoutSec 20 -Headers @{ Accept='application/json' }
        if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode)" }
        $contentType = [string]$response.Headers['Content-Type']
        if ($contentType -and $contentType -notmatch '(?i)application/json|text/plain|octet-stream') { throw "Unexpected content type: $contentType" }
        if ($response.Content.Length -gt 5242880) { throw 'Signature JSON exceeds the 5 MiB safety limit.' }
        $candidate = $response.Content | ConvertFrom-Json
        if ($candidate.schemaVersion -ne 1 -or $candidate.family -ne 'DoomsDay') { throw 'Downloaded signature schema/family is invalid.' }
        $temporary = "$script:SignaturePath.download"
        $databaseDirectory=Split-Path -Parent $script:SignaturePath
        if (-not (Test-Path -LiteralPath $databaseDirectory -PathType Container)) { [void][IO.Directory]::CreateDirectory($databaseDirectory) }
        [IO.File]::WriteAllText($temporary, [string]$response.Content, [Text.UTF8Encoding]::new($false))
        $old = $script:SignaturePath; $script:SignaturePath = $temporary
        try { Import-DoomsDaySignatures | Out-Null }
        finally { $script:SignaturePath = $old }
        Move-Item -LiteralPath $temporary -Destination $script:SignaturePath -Force
        $script:Signatures = $candidate
        Write-Color '[OK] Signature database updated and validated.' Green
        return $true
    } catch {
        $script:Signatures=$previousDatabase
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
    if ($State.Scope) { Write-Color ("Scope: $($State.Scope)") Magenta }
    $rows = [ordered]@{
        'Total indexes extracted'=$State.TotalIndexesExtracted; 'Candidate files'=$State.CandidateFiles
        'Files found'=$State.FilesFound; 'Files fully scanned'=$State.FilesFullyScanned; 'Files skipped'=$State.FilesSkipped
        'Corrupted/unreadable'=$State.CorruptedUnreadable; 'DoomsDay detections'=$State.Statistics.DoomsDayDetections
        'High confidence findings'=$State.Statistics.HighConfidenceFindings; 'Suspicious findings'=$State.Statistics.SuspiciousFindings
        'Deleted traces'=$State.Statistics.DeletedTraces; 'ADS findings'=$State.Statistics.AdsFindings
        'Elapsed time'=[TimeSpan]::FromSeconds($State.Performance.ElapsedSeconds).ToString('hh\:mm\:ss')
        'Parallel workers'=$State.Performance.Workers; 'Parallel jobs completed'=$State.Performance.ParallelJobs
    }
    foreach ($key in $rows.Keys) { Write-Color (('{0,-26}: {1}' -f $key, $rows[$key])) Magenta }
    Write-Host ''
    if ($State.VerifiedSignatureCount -eq 0) {
        Write-Color '[INCONCLUSIVE] No verified family signatures are installed. Community-pattern findings are unverified and must not be used as a ban decision.' Yellow
    } elseif ($State.FilesSkipped -gt 0 -or $State.CorruptedUnreadable -gt 0 -or $State.UnavailableSources.Count -gt 0) {
        Write-Color '[INCONCLUSIVE]' Yellow
        Write-Color 'Some candidate artifacts or evidence sources could not be fully analyzed.' Yellow
    } elseif ($State.Statistics.DoomsDayDetections -gt 0) {
        Write-Color '[DETECTED]' Red
        Write-Color 'Verified DoomsDay-specific evidence was found. Review every evidence field before action.' Red
    } elseif (@($State.Findings | Where-Object Verdict -ne 'INFO').Count -gt 0) {
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
    [void]$builder.AppendLine("Elapsed seconds: $($State.Performance.ElapsedSeconds)")
    [void]$builder.AppendLine("Parallel workers: $($State.Performance.Workers); jobs completed: $($State.Performance.ParallelJobs); peak active observed: $($State.Performance.PeakActive)")
    foreach ($timing in $State.Performance.PhaseTimings) { [void]$builder.AppendLine("Phase $($timing.Phase): $($timing.Seconds) seconds") }
    [void]$builder.AppendLine("Scan ID: $($State.ScanId)")
    [void]$builder.AppendLine("Mode: $($State.Mode)")
    [void]$builder.AppendLine("Analysis profile: $($State.AnalysisProfile)")
    [void]$builder.AppendLine("Scope: $($State.Scope)")
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
        $stamp = ConvertTo-SafeDateString $State.CompletedUtc 'yyyyMMdd_HHmmss_fff'
        if ($stamp -eq 'UNAVAILABLE') { $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd_HHmmss') }
        $base = Join-Path $script:ReportDirectory ("DoomsDayFinder_Report_{0}_{1}" -f $stamp,$State.ScanId.Substring(0,8))
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
        $stream = [IO.MemoryStream]::new([byte[]](0xCA,0xFE,0xBA,0xBE,0x00))
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
    $previousProfile=$script:AnalysisProfile
    $script:AnalysisProfile=if ($SelectedMode -eq 'Fast') { 'Signatures' } else { 'Detailed' }
    $script:InspectionCache = @{}
    $script:HashCache = @{}
    $script:ContentPlanCache.Clear()
    $script:ClassIndexCache.Clear(); $script:ClassIndexCacheOrder.Clear(); $script:ClassIndexCacheBytes=0L
    $script:ClassCacheHits=0L; $script:ClassCacheMisses=0L; $script:FileInventory=$null
    $script:PhaseTimings.Clear(); $script:ActivePhase='PREPARE'
    $script:ScanClock=[Diagnostics.Stopwatch]::StartNew()
    $script:PhaseClock=[Diagnostics.Stopwatch]::StartNew()
    $script:ProgressLastUpdate = [DateTime]::MinValue
    $consoleGuard = Enter-ScanConsoleMode
    try {
        $state = New-ScanState $SelectedMode
        if ($consoleGuard.Warning) { Add-ScanWarning $state 'CONSOLE' $consoleGuard.Warning }
        if (-not $state.IsAdministrator) { Write-Color '[LIMITED MODE] Administrator-only forensic sources will be skipped.' Yellow }
        switch ($SelectedMode) {
            'Fast' { Invoke-FastScan $state $SelectedPath }
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
        $script:ScanClock.Stop(); $script:PhaseClock.Stop()
        [void]$script:PhaseTimings.Add([pscustomobject]@{ Phase=$script:ActivePhase; Seconds=[Math]::Round($script:PhaseClock.Elapsed.TotalSeconds,3) })
        $state.Performance.ElapsedSeconds=[Math]::Round($script:ScanClock.Elapsed.TotalSeconds,3)
        $state.Performance.PhaseTimings=@($script:PhaseTimings)
        $state.Performance.ClassCacheHits=$script:ClassCacheHits; $state.Performance.ClassCacheMisses=$script:ClassCacheMisses
        if ($null -ne $script:FileInventory) { $state.Performance.InventoryFiles=$script:FileInventory.Count }
        $script:PhaseClock=$null
        Complete-ScanState $state
        Show-ScanComplete $state
        Export-ScanReport $state | Out-Null
        return $state
    } finally {
        $script:AnalysisProfile=$previousProfile
        if ($null -ne $script:ScanClock) { $script:ScanClock.Stop(); $script:ScanClock=$null }
        if ($null -ne $script:PhaseClock) { $script:PhaseClock.Stop(); $script:PhaseClock=$null }
        $script:FileInventory=$null
        $script:ClassIndexCache.Clear(); $script:ClassIndexCacheOrder.Clear(); $script:ClassIndexCacheBytes=0L
        $script:InspectionCache.Clear(); $script:ContentPlanCache.Clear()
        try { Write-ScanProgress -Completed }
        finally { Exit-ScanConsoleMode $consoleGuard }
    }
}

function Show-MainMenu {
    try { Clear-Host } catch { }
    Show-RevealBanner
    Write-Color '[1] Fast Scan - Java + Prefetch + mods (recommended)' Magenta
    Write-Color '[2] Full Forensic Scan' Magenta
    Write-Color '[3] Scan File' Magenta
    Write-Color '[4] Deep ADS Scan' Magenta
    Write-Color '[5] Runtime Scan' Magenta
    Write-Color '[6] Update Signatures' Magenta
    Write-Color '[7] Export Last Report' Magenta
    Write-Color '[8] Minecraft Directory Scan (broader)' Magenta
    Write-Color '[0] Exit' Magenta
}

function Start-DoomsDayFinderMenu {
    do {
        Show-MainMenu
        $choice = Read-Host 'Select'
        try {
            switch ($choice) {
                '1' { Invoke-ScanMode 'Fast' | Out-Null }
                '2' { Invoke-ScanMode 'Full' | Out-Null }
                '3' { $file = (Read-Host 'Enter the full path of the file').Trim('"'); Invoke-ScanMode 'File' $file | Out-Null }
                '4' { $root = (Read-Host 'Optional root path (press Enter for default locations)').Trim('"'); Invoke-ScanMode 'ADS' $root -DeepAds | Out-Null }
                '5' { Invoke-ScanMode 'Runtime' | Out-Null }
                '6' { Update-DoomsDaySignatures | Out-Null }
                '7' { Export-ScanReport | Out-Null }
                '8' { Invoke-ScanMode 'Quick' | Out-Null }
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
