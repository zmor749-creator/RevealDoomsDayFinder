#requires -Version 5.1
[CmdletBinding()]
param([string]$ScannerPath=(Join-Path $PSScriptRoot '..\DoomsDayFinder.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null; $parseErrors=$null
[void][Management.Automation.Language.Parser]::ParseFile((Resolve-Path $ScannerPath),[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors | Out-String) }
. $ScannerPath
$testDirectory=Join-Path ([IO.Path]::GetTempPath()) ('RevealTests-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testDirectory)
$testResults=[Collections.ArrayList]::new()
function Assert-True { param([bool]$Condition,[string]$Message='Assertion failed'); if (-not $Condition) { throw $Message } }
function Test-Case {
    param([string]$Name,[scriptblock]$Body)
    try { & $Body | Out-Null; [void]$testResults.Add([pscustomobject]@{ Test=$Name; Result='PASS'; Error='' }); Write-Host "PASS $Name" -ForegroundColor Green }
    catch { [void]$testResults.Add([pscustomobject]@{ Test=$Name; Result='FAIL'; Error=$_.Exception.Message }); Write-Host "FAIL $Name : $($_.Exception.Message)" -ForegroundColor Red }
}
function New-TestSignature {
    param([string]$Type,[string]$Value,[string]$Group='fixture',[bool]$Verified=$true)
    [pscustomobject]@{ ID=[guid]::NewGuid().ToString('N'); Type=$Type; Value=$Value; Source='Synthetic regression fixture; NOT a DoomsDay signature'; Version='1'; Confidence=100; Specificity='High'; LastUpdated='2026-09-01'; Verified=$Verified; IndependenceGroup=$Group }
}
function Set-TestDatabase {
    param([object[]]$Entries=@(),[object[]]$Clean=@())
    $script:Signatures=[pscustomobject]@{ schemaVersion=1; family='DoomsDay'; databaseVersion='SYNTHETIC-TEST-ONLY'; signatures=@($Entries); knownCleanHashes=@($Clean) }
    $script:InspectionCache=@{}; $script:HashCache=@{}
}
function Get-TestClassBytes {
    param([string]$Name='fixture/Example')
    $buffer=[Collections.Generic.List[byte]]::new()
    $buffer.AddRange([byte[]](0xCA,0xFE,0xBA,0xBE,0,0,0,52,0,5,1))
    $nameBytes=[Text.Encoding]::UTF8.GetBytes($Name)
    $buffer.Add([byte]($nameBytes.Length -shr 8)); $buffer.Add([byte]($nameBytes.Length -band 255)); $buffer.AddRange($nameBytes)
    $buffer.AddRange([byte[]](7,0,1,1,0,16)); $buffer.AddRange([Text.Encoding]::ASCII.GetBytes('java/lang/Object'))
    $buffer.AddRange([byte[]](7,0,3,0,33,0,2,0,4,0,0,0,0,0,0,0,0))
    return ,$buffer.ToArray()
}
function New-TestArchive {
    param([string]$Name,[int]$Classes=1,[hashtable]$Extra=@{})
    $archivePath=Join-Path $testDirectory $Name
    $stream=[IO.File]::Create($archivePath)
    $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$true)
    try {
        for ($i=0; $i -lt $Classes; $i++) {
            $entry=$zip.CreateEntry("fixture/C$i.class")
            $entryStream=$entry.Open()
            try { $bytes=Get-TestClassBytes "fixture/C$i"; $entryStream.Write($bytes,0,$bytes.Length) } finally { $entryStream.Dispose() }
        }
        foreach ($key in $Extra.Keys) {
            $entry=$zip.CreateEntry($key); $entryStream=$entry.Open()
            try { [byte[]]$bytes=$Extra[$key]; $entryStream.Write($bytes,0,$bytes.Length) } finally { $entryStream.Dispose() }
        }
    } finally { $zip.Dispose(); $stream.Dispose() }
    return $archivePath
}
function Inspect-TestFile {
    param([string]$File)
    $script:InspectionCache=@{}; $script:HashCache=@{}
    $state=New-ScanState 'File'
    $finding=Invoke-FileInspection -LiteralPath $File -State $state -AlwaysRecord -QuietProgress
    [pscustomobject]@{ State=$state; Finding=$finding }
}
Set-TestDatabase
$plain=New-TestArchive 'clean.jar' 1 @{ 'fixture/resource.txt'=[Text.Encoding]::UTF8.GetBytes('fixture-only-marker-7fe56cd1') }
Test-Case 'Core self-test' { Assert-True (Invoke-BuiltInSelfTest) }
Test-Case 'Unknown total never displays division by zero or fake percentage' {
    $line=Format-ScanProgressLine -Status 'Candidates: 120; counting' -Current 16182 -Total 0
    Assert-True ($line -like '[[]INDEX]*' -and $line -notmatch '/\s*0|%' -and $line -match 'Candidates: 120')
}
Test-Case 'Known total displays genuine scan progress' {
    $line=Format-ScanProgressLine -Status 'Detailed file inspection' -Current 7 -Total 10
    Assert-True ($line -eq '[SCAN] 7 / 10 | 70% | Detailed file inspection')
}
Test-Case 'Unknown-total updates are throttled too' {
    $script:ProgressLastUpdate=[DateTime]::UtcNow.AddMinutes(1)
    try {
        $output=@(Write-ScanProgress -Current 16182 -Total 0 -Status 'Counting' 6>&1)
        Assert-True ($output.Count -eq 0)
    } finally { Write-ScanProgress -Completed }
}
Test-Case 'Final known-total update bypasses throttle and remains one line' {
    $script:ProgressLastUpdate=[DateTime]::UtcNow.AddMinutes(1)
    try {
        $output=@(Write-ScanProgress -Current 10 -Total 10 -Status 'Done' 6>&1)
        Assert-True ($output.Count -eq 1 -and $output[0].ToString() -match '100%' -and $output[0].ToString() -notmatch "`n")
    } finally { Write-ScanProgress -Completed }
}
Test-Case 'Candidate discovery consumes each file before requesting the next' {
    Set-TestDatabase
    function Get-ReadOnlyFiles {
        param([string[]]$Roots,$State,[switch]$Recurse)
        Get-Item -LiteralPath $plain
        Assert-True ($State.DiscoveredFiles -eq 1) 'Discovery buffered output instead of streaming it.'
        Get-Item -LiteralPath $plain
    }
    $s=New-ScanState Full
    $result=@(Get-CandidateFiles -Roots @($testDirectory) -State $s -Full)
    Assert-True ($s.DiscoveredFiles -eq 2 -and $result.Count -eq 1 -and $result[0] -eq $plain)
}
Test-Case 'Directory traversal is streamed and retains recursive coverage' {
    Set-TestDatabase
    $root=Join-Path $testDirectory 'discovery'
    $sub=Join-Path $root 'nested'; [void][IO.Directory]::CreateDirectory($sub)
    [IO.File]::WriteAllText((Join-Path $root 'first.txt'),'plain')
    [IO.File]::Copy($plain,(Join-Path $sub 'renamed.png'))
    $s=New-ScanState Full
    $all=@(Get-ReadOnlyFiles -Roots @($root) -State $s -Recurse)
    Assert-True ($all.Count -eq 2 -and $s.FilesSkipped -eq 0)
    $candidates=@(Get-CandidateFiles -Roots @($root) -State $s -Full)
    Assert-True ($s.DiscoveredFiles -eq 2 -and $candidates.Count -eq 1 -and $candidates[0] -like '*renamed.png')
}
Test-Case 'QuickEdit mask preserves all other input flags including CTRL+C' {
    foreach ($mode in @([uint32]0,[uint32]0x47,[uint32]0x1F7,[uint32]::MaxValue)) {
        $changed=Get-ScanConsoleMode $mode
        Assert-True (($changed -band 0x40) -eq 0 -and ($changed -band 0x80) -ne 0)
        Assert-True (($changed -band ([uint32]::MaxValue -bxor [uint32]0xC0)) -eq ($mode -band ([uint32]::MaxValue -bxor [uint32]0xC0)))
    }
}
Test-Case 'Console cleanup runs when a scan fails' {
    Set-TestDatabase
    $script:ConsoleCleanupTest=0
    function Enter-ScanConsoleMode { [pscustomobject]@{ Warning='' } }
    function Exit-ScanConsoleMode { param($Guard); $script:ConsoleCleanupTest++ }
    function Invoke-QuickScan { param($State); throw 'Expected fixture scan failure' }
    $failed=$false
    try { Invoke-ScanMode Quick | Out-Null } catch { $failed=$_.Exception.Message -eq 'Expected fixture scan failure' }
    Assert-True ($failed -and $script:ConsoleCleanupTest -eq 1)
}
Test-Case 'Empty source lists do not become null' { $s=New-ScanState File; Add-SourceStatus $s A $true; Add-SourceStatus $s B $false; Assert-True ($s.AnalyzedSources.Count -eq 1 -and $s.UnavailableSources.Count -eq 1) }
Test-Case 'No-signature clean JAR' { Set-TestDatabase; $r=Inspect-TestFile $plain; Assert-True ($r.Finding.Verdict -eq 'INFO' -and $r.State.FilesFullyScanned -eq 1) }
Test-Case 'Class binary parser' { $c=Read-JavaClassIndex (Get-TestClassBytes); Assert-True ($c.Name -eq 'fixture/Example' -and 'java/lang/Object' -in $c.References) }
Test-Case 'Optimized class parser preserves numeric and reference tag widths' {
    $original=Get-TestClassBytes; $extra=[Collections.Generic.List[byte]]::new(); $slots=0
    foreach ($tag in @(3,4,5,6,8,9,10,11,12,15,16,17,18,19,20)) {
        $extra.Add([byte]$tag); $slots++
        $width=if ($tag -in @(5,6)) { $slots++; 8 } elseif ($tag -in @(3,4,9,10,11,12,17,18)) { 4 } elseif ($tag -eq 15) { 3 } else { 2 }
        $extra.AddRange([byte[]]::new($width))
    }
    $prefix=$original.Length-14; $bytes=[byte[]]::new($original.Length+$extra.Count)
    [Array]::Copy($original,0,$bytes,0,$prefix); [Array]::Copy($extra.ToArray(),0,$bytes,$prefix,$extra.Count)
    [Array]::Copy($original,$prefix,$bytes,$prefix+$extra.Count,14)
    $bytes[8]=0; $bytes[9]=[byte](5+$slots)
    $result=Read-JavaClassIndex $bytes; $base=Read-JavaClassIndex $original
    Assert-True ($result.Name -eq $base.Name -and $result.Shape -eq $base.Shape)
}
Test-Case 'Clean archive cache releases trees but explicit findings retain details' {
    Set-TestDatabase; $s=New-ScanState Full
    $initial=Invoke-FileInspection -LiteralPath $plain -State $s -QuietProgress
    $compact=Invoke-FileInspection -LiteralPath $plain -State $s -QuietProgress
    Assert-True ($initial.ArchiveAnalysis.ClassesAnalyzed -eq 1 -and $null -eq $compact.PSObject.Properties['ArchiveAnalysis'])
    $detailed=Invoke-FileInspection -LiteralPath $plain -State $s -AlwaysRecord -QuietProgress
    Assert-True ($detailed.ArchiveAnalysis.ClassesAnalyzed -eq 1 -and $s.FilesFullyScanned -eq 1 -and $s.CandidateFiles -eq 1)
}
Test-Case 'Class cache reuses only identical content hashes' {
    $bytes=Get-TestClassBytes; $m=[IO.MemoryStream]::new($bytes)
    try { $hash=Get-StreamSha256 $m } finally { $m.Dispose() }
    $first=Get-CachedClassIndex $bytes $hash; $hits=$script:ClassCacheHits
    $second=Get-CachedClassIndex $bytes $hash
    Assert-True ($script:ClassCacheHits -eq $hits+1 -and $first.Name -eq $second.Name)
}
Test-Case 'Independent verification bypasses the class cache' {
    $bytes=Get-TestClassBytes; $m=[IO.MemoryStream]::new($bytes)
    try { $hash=Get-StreamSha256 $m } finally { $m.Dispose() }
    [void](Get-CachedClassIndex $bytes $hash)
    $misses=$script:ClassCacheMisses
    $index=Get-CachedClassIndex $bytes $hash -Independent
    Assert-True ($script:ClassCacheMisses -eq $misses+1 -and $index.Name -eq 'fixture/Example')
    $blocked=$false
    try { Get-CachedClassIndex ([byte[]](0,1,2)) $hash -Independent | Out-Null } catch { $blocked=$true }
    Assert-True $blocked 'Independent verification incorrectly trusted cached content.'
}
Test-Case 'Cached byte plan never keeps stale signature verification metadata' {
    $sig=New-TestSignature String 'unique-plan-fixture'; $bytes=[Text.Encoding]::UTF8.GetBytes($sig.Value)
    $m=[IO.MemoryStream]::new($bytes)
    try { [void](Read-ContentInspection $m @($sig)) } finally { $m.Dispose() }
    $replacement=New-TestSignature String $sig.Value 'fixture' $false; $replacement.ID=$sig.ID
    $m=[IO.MemoryStream]::new($bytes)
    try { $r=Read-ContentInspection $m @($replacement); Assert-True ($r.Matches.Count -eq 1 -and -not $r.Matches[0].Verified) } finally { $m.Dispose() }
}
Test-Case 'Large mod 1847 classes: no class-count skip' { Set-TestDatabase; $large=New-TestArchive 'large.jar' 1847; $r=Inspect-TestFile $large; Assert-True ($r.Finding.ArchiveAnalysis.ClassCount -eq 1847 -and $r.Finding.ArchiveAnalysis.ClassesAnalyzed -eq 1847 -and $r.State.FilesSkipped -eq 0 -and $r.Finding.Verdict -ne 'DETECTED') }
Test-Case 'Verified synthetic hash survives rename' { $hash=Get-CachedFileSha256 $plain; Set-TestDatabase @((New-TestSignature SHA256 $hash)); $renamed=Join-Path $testDirectory 'performance.jar'; [IO.File]::Copy($plain,$renamed); $r=Inspect-TestFile $renamed; Assert-True ($r.Finding.Verdict -eq 'DETECTED' -and $r.Finding.VerificationStatus -eq 'VERIFIED') }
Test-Case 'Extension spoofing' { $renamed=Join-Path $testDirectory 'wallpaper.png'; [IO.File]::Copy($plain,$renamed); $r=Inspect-TestFile $renamed; Assert-True ($r.Finding.Verdict -eq 'DETECTED' -and $r.Finding.ExtensionMismatch) }
Test-Case 'Nested hash with renamed embedded extension' { $outer=New-TestArchive 'outer.jar' 0 @{ 'payload.dat'=[IO.File]::ReadAllBytes($plain) }; $r=Inspect-TestFile $outer; Assert-True ($r.Finding.Verdict -eq 'DETECTED' -and $r.Finding.Evidence[0].Location -like '*!/payload.dat') }
Test-Case 'One high signature cannot detect' { Set-TestDatabase @((New-TestSignature Class 'fixture.C0')); Assert-True ((Inspect-TestFile $plain).Finding.Verdict -ne 'DETECTED') }
Test-Case 'Class and package with same independence group cannot detect' { Set-TestDatabase @((New-TestSignature Class 'fixture.C0' 'same'),(New-TestSignature Package 'fixture' 'same')); Assert-True ((Inspect-TestFile $plain).Finding.Verdict -ne 'DETECTED') }
Test-Case 'Two independently attested synthetic signatures' { Set-TestDatabase @((New-TestSignature Class 'fixture.C0' 'class'),(New-TestSignature Resource 'fixture/resource.txt' 'resource')); Assert-True ((Inspect-TestFile $plain).Finding.Verdict -eq 'DETECTED') }
Test-Case 'Unverified hash is not detected' { Set-TestDatabase @((New-TestSignature SHA256 (Get-CachedFileSha256 $plain) 'hash' $false)); Assert-True ((Inspect-TestFile $plain).Finding.Verdict -ne 'DETECTED') }
Test-Case 'Known clean hash blocks conflicting signature' { Set-TestDatabase @((New-TestSignature SHA256 (Get-CachedFileSha256 $plain))) @([pscustomobject]@{ SHA256=(Get-CachedFileSha256 $plain) }); $r=Inspect-TestFile $plain; Assert-True ($r.Finding.Verdict -eq 'INCONCLUSIVE' -and $r.Finding.VerificationStatus -eq 'CONFLICTING') }
Test-Case 'Generic Minecraft string is ignored' { Set-TestDatabase @((New-TestSignature String 'Minecraft')); $x=New-TestArchive 'generic.jar' 1 @{ 'a.txt'=[Text.Encoding]::UTF8.GetBytes('Minecraft Forge Module Combat Mixin') }; Assert-True ((Inspect-TestFile $x).Finding.Verdict -ne 'DETECTED') }
Test-Case 'Score-only 100 remains non-detection' { Assert-True ((Get-Decision @() 100 $false).Verdict -ne 'DETECTED') }
Test-Case 'Missing content never detected' { Assert-True (-not (Get-Decision @() 100 $false $false).EligibleForDetected) }
Test-Case 'Filename-only remains review' { Set-TestDatabase; $x=Join-Path $testDirectory 'DoomsDay.jar'; [IO.File]::Copy($plain,$x); $r=Inspect-TestFile $x; Assert-True ($r.Finding.Verdict -eq 'REVIEW' -and $r.Finding.Family -eq 'Unknown') }
Test-Case 'Corrupt archive counted as unreadable' { Set-TestDatabase; $x=Join-Path $testDirectory 'corrupt.jar'; [IO.File]::WriteAllBytes($x,[byte[]](80,75,3,4,0,0)); $r=Inspect-TestFile $x; Assert-True ($r.State.CorruptedUnreadable -eq 1 -and $r.State.FilesFullyScanned -eq 0) }
Test-Case 'Malformed class is incomplete, not fully scanned' { Set-TestDatabase; $x=New-TestArchive 'bad-class.jar' 0 @{ 'a.class'=[byte[]](0xCA,0xFE,0xBA,0xBE,0) }; $r=Inspect-TestFile $x; Assert-True ($r.Finding.Verdict -eq 'INCONCLUSIVE' -and $r.State.FilesFullyScanned -eq 0) }
Test-Case 'ZIP bomb safety produces incomplete result' { Set-TestDatabase; $x=New-TestArchive 'ratio.jar' 0 @{ 'zeros.bin'=(New-Object byte[] 2000000) }; $r=Inspect-TestFile $x; Assert-True ($r.State.CorruptedUnreadable -gt 0 -and $r.State.FilesFullyScanned -eq 0) }
Test-Case 'Recursion cutoff is not silently complete' { Set-TestDatabase; $x=$plain; for ($n=0;$n -lt 5;$n++) { $x=New-TestArchive "depth$n.jar" 0 @{ 'nested.zip'=[IO.File]::ReadAllBytes($x) } }; $r=Inspect-TestFile $x; Assert-True ($r.State.FilesSkipped -gt 0 -and $r.State.FilesFullyScanned -eq 0) }
Test-Case 'All content signatures scanned on forward-only ZIP entry' { Set-TestDatabase @((New-TestSignature String 'first-unique-marker'),(New-TestSignature String 'last-unique-marker')); $x=New-TestArchive 'multi.jar' 0 @{ 'r.bin'=[Text.Encoding]::UTF8.GetBytes('last-unique-marker - first-unique-marker') }; $r=Inspect-TestFile $x; Assert-True ($r.Finding.Evidence.Count -eq 2) }
Test-Case 'Signature across 64KiB chunk boundary' { $s=New-TestSignature String 'boundary-marker'; $data=[Text.Encoding]::UTF8.GetBytes(('x'*65530)+'boundary-marker'); $m=[IO.MemoryStream]::new($data); try { $r=Read-ContentInspection $m @($s); Assert-True ($r.Matches.Count -eq 1) } finally { $m.Dispose() } }
Test-Case 'Signature across optimized 1MiB read boundary' { $s=New-TestSignature String 'boundary-marker'; $data=[Text.Encoding]::UTF8.GetBytes(('x'*1048570)+'boundary-marker'); $m=[IO.MemoryStream]::new($data); try { $r=Read-ContentInspection $m @($s); Assert-True ($r.Matches.Count -eq 1 -and $r.Length -eq $data.Length) } finally { $m.Dispose() } }
Test-Case 'Empty stream remains valid with adaptive buffer' { $m=[IO.MemoryStream]::new(); try { $r=Read-ContentInspection -Stream $m -MaximumBytes 0; Assert-True ($r.Length -eq 0 -and $r.SHA256 -eq 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855') } finally { $m.Dispose() } }
Test-Case 'Quoted JVM args and agent options' { $j=Get-JvmArguments 'javaw.exe "-javaagent:C:\Some Folder\agent.jar=option" -agentpath:"C:\Some Folder\native.dll" -cp "C:\A B\a.jar;C:\b.jar"'; Assert-True ($j.JavaAgent[0] -eq 'C:\Some Folder\agent.jar=option' -and $j.AgentPath[0] -eq 'C:\Some Folder\native.dll' -and $j.ClassPath.Count -eq 1) }
Test-Case 'Missing candidate warning, no scan crash' { Set-TestDatabase; $r=Inspect-TestFile (Join-Path $testDirectory 'missing.jar'); Assert-True ($r.State.FilesSkipped -eq 1) }
Test-Case 'Static cleaner combination is REVIEW, not DoomsDay' { Set-TestDatabase; $x=Join-Path $testDirectory 'synthetic-tool.py'; [IO.File]::WriteAllText($x,'# fixture text only: javaw.exe WriteProcessMemory .oracle_jre_usage'); $r=Inspect-TestFile $x; Assert-True ($r.Finding.Verdict -eq 'REVIEW' -and $r.Finding.Family -eq 'Unknown') }
Test-Case 'Non-archive hash and context use one content inspection' {
    Set-TestDatabase
    function Get-CachedFileSha256 { throw 'Unexpected separate hash pass' }
    function Get-EvasionContextIndicators { throw 'Unexpected separate context pass' }
    $x=Join-Path $testDirectory 'one-pass.ps1'; [IO.File]::WriteAllText($x,'fixture javaw.exe WriteProcessMemory .oracle_jre_usage')
    $r=Inspect-TestFile $x
    Assert-True ($r.Finding.Verdict -eq 'REVIEW' -and $r.Finding.SHA256 -eq (Get-FileHash -LiteralPath $x).Hash)
}
Test-Case 'Null-safe report export and repeat scan' { Set-TestDatabase; $s=New-ScanState File; $script:ReportDirectory=Join-Path $testDirectory 'Reports'; $a=Export-ScanReport $s; $b=Export-ScanReport (New-ScanState File); Assert-True ((Test-Path $a.Json) -and (Test-Path $b.Text) -and $a.Json -ne $b.Json) }
Test-Case 'Empty signatures cannot report a clean system' { Set-TestDatabase; $s=New-ScanState File; Complete-ScanState $s; $output=Show-ScanComplete $s 6>&1 | Out-String; Assert-True ($output -match 'INCONCLUSIVE' -and $output -notmatch '\[NO EVIDENCE FOUND\]') }
Test-Case 'File content unchanged by inspection' { $before=Get-FileHash $plain; [void](Inspect-TestFile $plain); Assert-True ((Get-FileHash $plain).Hash -eq $before.Hash) }
Test-Case 'Scan timing and caches reset between complete scans' {
    Set-TestDatabase; $script:ReportDirectory=Join-Path $testDirectory 'Reports'
    $a=Invoke-ScanMode File $plain; $b=Invoke-ScanMode File $plain
    Assert-True ($a.Performance.ElapsedSeconds -ge 0 -and $b.Performance.ClassCacheMisses -ge 1 -and $null -eq $script:ScanClock -and $null -eq $script:FileInventory)
}
Test-Case 'Localized event XML fields are parsed by name' { $d=Get-EventXmlFields '<Event><EventData><Data Name="Image">C:\javaw.exe</Data><Data Name="TargetFilename">C:\payload.jar</Data></EventData></Event>'; Assert-True ($d.Image -eq 'C:\javaw.exe' -and $d.TargetFilename -eq 'C:\payload.jar') }
Test-Case 'XML external entities prohibited' { $blocked=$false; try { Get-EventXmlFields '<!DOCTYPE x [<!ENTITY x SYSTEM "file:///never-read">]><Event>&x;</Event>' } catch { $blocked=$true }; Assert-True $blocked }
Test-Case 'No basename-only evidence correlation' { Set-TestDatabase; $s=New-ScanState Full; $f=New-Finding -CurrentName 'client.jar' -FullPath 'C:\A\client.jar'; [void]$s.Findings.Add($f); [void]$s.Evidence.Add([pscustomobject]@{ Source='Test'; Path='C:\B\client.jar' }); Invoke-EvidenceCorrelation $s; Assert-True ($f.Evidence.Count -eq 0) }
Test-Case 'Exact-path context does not upgrade verdict' { Set-TestDatabase; $s=New-ScanState Full; $f=New-Finding -CurrentName 'client.jar' -FullPath 'C:\A\client.jar'; [void]$s.Findings.Add($f); [void]$s.Evidence.Add([pscustomobject]@{ Source='Test'; Path='C:\A\client.jar' }); Invoke-EvidenceCorrelation $s; Assert-True ($f.Evidence.Count -eq 1 -and $f.Verdict -eq 'INFO') }
Test-Case 'Distributed database contains no invented verified signatures' { Import-DoomsDaySignatures | Out-Null; $s=New-ScanState File; Assert-True ($s.SignatureCount -eq 3 -and $s.VerifiedSignatureCount -eq 0) }
Test-Case 'Parallel workers preserve serial findings, hashes and full class coverage' {
    Set-TestDatabase
    $files=@()
    for ($n=0;$n -lt 6;$n++) {
        $copy=Join-Path $testDirectory "parallel-$n.jar"
        [IO.File]::Copy((Join-Path $testDirectory 'large.jar'),$copy); $files+=$copy
    }
    $serial=New-ScanState File
    foreach ($file in $files) { Invoke-FileInspection -LiteralPath $file -State $serial -AlwaysRecord -QuietProgress | Out-Null }
    $parallel=New-ScanState File
    $before=@(Get-Runspace).Count
    Invoke-ParallelInspection -Files $files -State $parallel -WorkerLimit 4 -AlwaysRecord -CaptureDiagnostics | Out-Null
    Assert-True ($parallel.CandidateFiles -eq 6 -and $parallel.FilesFullyScanned -eq 6 -and $parallel.CorruptedUnreadable -eq 0)
    Assert-True ($parallel.Performance.ParallelJobs -eq 6 -and $parallel.Performance.Workers -eq 4 -and @(Get-Runspace).Count -eq $before)
    foreach ($finding in $parallel.Findings) {
        $reference=@($serial.Findings | Where-Object Path -eq $finding.Path)[0]
        Assert-True ($finding.SHA256 -eq $reference.SHA256 -and $finding.Verdict -eq $reference.Verdict -and $finding.ArchiveAnalysis.ClassesAnalyzed -eq 1847 -and $finding.ArchiveAnalysis.ClassShapeFingerprint -eq $reference.ArchiveAnalysis.ClassShapeFingerprint)
    }
    $overlap=$false
    foreach ($a in $parallel.Performance.WorkerDiagnostics) {
        foreach ($b in $parallel.Performance.WorkerDiagnostics) {
            if ($a.WorkerId -ne $b.WorkerId -and $a.StartedUtc -lt $b.FinishedUtc -and $b.StartedUtc -lt $a.FinishedUtc) { $overlap=$true }
        }
    }
    Assert-True $overlap 'No actual overlapping worker execution was observed.'
}
Test-Case 'Parallel verified detections retain independent verification and errors' {
    Set-TestDatabase @((New-TestSignature SHA256 (Get-CachedFileSha256 $plain)))
    $s=New-ScanState File
    $files=@($plain,(Join-Path $testDirectory 'performance.jar'),(Join-Path $testDirectory 'wallpaper.png'),(Join-Path $testDirectory 'corrupt.jar'),(Join-Path $testDirectory 'missing-parallel.jar'))
    Invoke-ParallelInspection -Files $files -State $s -WorkerLimit 2 -AlwaysRecord | Out-Null
    Assert-True ($s.CandidateFiles -eq 5 -and $s.FilesFullyScanned -eq 3 -and $s.CorruptedUnreadable -eq 1 -and $s.FilesSkipped -eq 1)
    Assert-True (@($s.Findings | Where-Object { $_.Verdict -eq 'DETECTED' -and $_.VerificationStatus -eq 'VERIFIED' }).Count -eq 3)
}
Test-Case 'Parallel clean-hash conflict is never detected' {
    $hash=Get-CachedFileSha256 $plain
    Set-TestDatabase @((New-TestSignature SHA256 $hash)) @([pscustomobject]@{ SHA256=$hash })
    $s=New-ScanState File
    Invoke-ParallelInspection -Files @($plain,(Join-Path $testDirectory 'performance.jar')) -State $s -WorkerLimit 2 -AlwaysRecord | Out-Null
    Assert-True ($s.Findings.Count -eq 2 -and @($s.Findings | Where-Object VerificationStatus -ne 'CONFLICTING').Count -eq 0 -and @($s.Findings | Where-Object Verdict -eq 'DETECTED').Count -eq 0)
}
Test-Case 'Parallel cancellation disposes every runspace and reports incomplete source' {
    Set-TestDatabase
    $files=@(0..5 | ForEach-Object { Join-Path $testDirectory "parallel-$_.jar" })
    $before=@(Get-Runspace).Count; $s=New-ScanState File
    $cancel=[Threading.CancellationTokenSource]::new(); $cancel.CancelAfter(400)
    $cancelled=$false
    try { Invoke-ParallelInspection -Files $files -State $s -WorkerLimit 2 -CancellationToken $cancel.Token | Out-Null }
    catch { $cancelled=$true }
    finally { $cancel.Dispose() }
    Assert-True ($cancelled -and $null -eq $s.CompletedUtc -and $s.UnavailableSources.Count -gt 0 -and @(Get-Runspace).Count -eq $before)
}
Test-Case 'Parallel repeated scan starts with a fresh isolated signature snapshot' {
    Set-TestDatabase; $s=New-ScanState File
    Invoke-ParallelInspection -Files @($plain,$plain) -State $s -WorkerLimit 2 -AlwaysRecord | Out-Null
    Assert-True ($s.CandidateFiles -eq 1 -and $s.Findings.Count -eq 1 -and $s.Findings[0].Verdict -eq 'INFO')
}
Test-Case 'Worker initialization failure cannot silently complete the scan' {
    Set-TestDatabase; $s=New-ScanState File; $before=@(Get-Runspace).Count
    $originalPath=$script:ScannerScriptPath; $failed=$false
    try {
        $script:ScannerScriptPath='no-scanner-functions-for-this-failure-test'
        Invoke-ParallelInspection -Files @($plain) -State $s -WorkerLimit 1 | Out-Null
    } catch { $failed=$true }
    finally { $script:ScannerScriptPath=$originalPath }
    Assert-True ($failed -and $s.FilesFullyScanned -eq 0 -and $s.UnavailableSources.Count -gt 0 -and @(Get-Runspace).Count -eq $before)
}
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    Test-Case 'Pure PowerShell console API bindings work on this runtime' {
        $api=Get-ConsoleNativeApi
        Assert-True ($null -ne $api.GetMethod('GetStdHandle') -and $null -ne $api.GetMethod('SetConsoleMode'))
        $guard=Enter-ScanConsoleMode
        try { Assert-True ([string]::IsNullOrEmpty($guard.Warning)) $guard.Warning }
        finally { Exit-ScanConsoleMode $guard }
        Assert-True (-not $guard.Changed)
    }
    Test-Case 'NTFS ADS payload independently verified' {
        Set-TestDatabase @((New-TestSignature SHA256 (Get-CachedFileSha256 $plain)))
        $hostPath=Join-Path $testDirectory 'notes.txt'; [IO.File]::WriteAllText($hostPath,'benign fixture')
        if ($PSVersionTable.PSVersion.Major -ge 6) { Set-Content -LiteralPath $hostPath -Stream payload -AsByteStream -Value ([IO.File]::ReadAllBytes($plain)) }
        else { Set-Content -LiteralPath $hostPath -Stream payload -Encoding Byte -Value ([IO.File]::ReadAllBytes($plain)) }
        $info=Get-Item -LiteralPath $hostPath -Stream payload
        $s=New-ScanState ADS; $f=Inspect-AdsPayload $hostPath $info $s
        Assert-True ($f.Verdict -eq 'DETECTED' -and $f.VerificationStatus -eq 'VERIFIED' -and $f.Path -eq ($hostPath+':payload'))
    }
    Test-Case 'Normal Zone.Identifier is not a family finding' {
        Set-TestDatabase
        $hostPath=Join-Path $testDirectory 'download.txt'; [IO.File]::WriteAllText($hostPath,'benign fixture')
        Set-Content -LiteralPath $hostPath -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example.invalid/file"
        $z=Get-ZoneIdentifier $hostPath; Assert-True ($z.ZoneId -eq 3 -and $z.HostUrl -eq 'https://example.invalid/file')
    }
    Test-Case 'ADS uses existing inventory without another directory walk' {
        Set-TestDatabase
        function Get-ReadOnlyFiles { throw 'Unexpected second directory walk' }
        $hostPath=Join-Path $testDirectory 'inventory.txt'; [IO.File]::WriteAllText($hostPath,'benign fixture')
        Set-Content -LiteralPath $hostPath -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example.invalid/file"
        $s=New-ScanState ADS; Invoke-AdsScan -State $s -FileInventory @($hostPath)
        Assert-True ($s.Findings.Count -eq 0 -and $s.CorruptedUnreadable -eq 0 -and @($s.Evidence | Where-Object Source -eq 'Zone.Identifier').Count -eq 1)
    }
    Test-Case 'Native ADS content matches UTF16 signatures without per-byte loop' {
        $sig=New-TestSignature String 'unique-native-ads-fixture' 'fixture' $false; Set-TestDatabase @($sig)
        $hostPath=Join-Path $testDirectory 'native-ads.txt'; [IO.File]::WriteAllText($hostPath,'benign')
        $data=[Text.Encoding]::Unicode.GetBytes('MZ unique-native-ads-fixture')
        if ($PSVersionTable.PSVersion.Major -ge 6) { Set-Content -LiteralPath $hostPath -Stream payload -AsByteStream -Value $data }
        else { Set-Content -LiteralPath $hostPath -Stream payload -Encoding Byte -Value $data }
        $s=New-ScanState ADS; $f=Inspect-AdsPayload $hostPath (Get-Item -LiteralPath $hostPath -Stream payload) $s
        Assert-True ($f.Evidence.Count -eq 1 -and $f.Verdict -ne 'DETECTED')
    }
    Test-Case 'Parallel ADS retains verified payloads, normal metadata and inaccessible hosts' {
        Set-TestDatabase @((New-TestSignature SHA256 (Get-CachedFileSha256 $plain)))
        $s=New-ScanState ADS
        $files=@((Join-Path $testDirectory 'notes.txt'),(Join-Path $testDirectory 'inventory.txt'),(Join-Path $testDirectory 'missing-ads-host.txt'))
        $errors=Invoke-ParallelInspection -Files $files -State $s -TaskMode ADS -WorkerLimit 2
        Assert-True ($errors -eq 1 -and $s.FilesSkipped -eq 1 -and $s.AdsFindings -eq 1 -and $s.Findings[0].Verdict -eq 'DETECTED')
        Assert-True (@($s.Evidence | Where-Object Source -eq 'Zone.Identifier').Count -eq 1)
    }
} else {
    [void]$testResults.Add([pscustomobject]@{ Test='NTFS ADS integration'; Result='NOT RUN'; Error='Windows/NTFS required' })
}
function New-PrefetchFixture {
    param([int]$Version=30,[int]$ReferenceCount=1,[string]$VolumePath='\VOLUME{fixture-volume}',[string]$ReferencePath='\VOLUME{fixture-volume}\Users\ATLAS\renamed.png')
    $prefix=[byte[]]::new(304)
    [BitConverter]::GetBytes([uint32]$Version).CopyTo($prefix,0)
    [Text.Encoding]::ASCII.GetBytes('SCCA').CopyTo($prefix,4)
    [Text.Encoding]::Unicode.GetBytes('JAVAW.EXE').CopyTo($prefix,16)
    [BitConverter]::GetBytes([uint32]304).CopyTo($prefix,84)
    [BitConverter]::GetBytes([uint32]304).CopyTo($prefix,100)
    [BitConverter]::GetBytes([DateTime]::UtcNow.ToFileTimeUtc()).CopyTo($prefix,128)
    [BitConverter]::GetBytes([uint32]7).CopyTo($prefix,208)
    $references=[Text.StringBuilder]::new()
    for ($i=0; $i -lt $ReferenceCount; $i++) { [void]$references.Append($ReferencePath); [void]$references.Append([char]0) }
    $names=[Text.Encoding]::Unicode.GetBytes($references.ToString())
    $pathBytes=[Text.Encoding]::Unicode.GetBytes($VolumePath)
    $entrySize=if ($Version -eq 26) { 104 } else { 96 }
    $volume=[byte[]]::new($entrySize+$pathBytes.Length)
    [BitConverter]::GetBytes([uint32]$entrySize).CopyTo($volume,0)
    [BitConverter]::GetBytes([uint32]$VolumePath.Length).CopyTo($volume,4)
    [BitConverter]::GetBytes([uint32]305419896).CopyTo($volume,16)
    $pathBytes.CopyTo($volume,$entrySize)
    [BitConverter]::GetBytes([uint32]($prefix.Length+$names.Length+$volume.Length)).CopyTo($prefix,12)
    [BitConverter]::GetBytes([uint32]$names.Length).CopyTo($prefix,104)
    [BitConverter]::GetBytes([uint32]($prefix.Length+$names.Length)).CopyTo($prefix,108)
    [BitConverter]::GetBytes([uint32]1).CopyTo($prefix,112)
    [BitConverter]::GetBytes([uint32]$volume.Length).CopyTo($prefix,116)
    return ,([byte[]]($prefix+$names+$volume))
}

Test-Case 'Explicit detailed output retains full paths for review findings' {
    Set-TestDatabase
    $s=New-ScanState Fast
    [void]$s.Findings.Add((New-Finding -CurrentName 'DoomsDay.jar' -FullPath 'C:\fixture\full-path\DoomsDay.jar' -Verdict REVIEW -Status UNKNOWN -DetectionReasons @('Filename-only fixture.')))
    Complete-ScanState $s
    $output=Show-ScanComplete $s -Detailed 6>&1 | Out-String
    Assert-True ($output.Contains('C:\fixture\full-path\DoomsDay.jar'))
}

Test-Case 'Default result is exactly detected plus full path without metadata or tables' {
    Set-TestDatabase @((New-TestSignature SHA256 ('A'*64)))
    $s=New-ScanState Fast
    [void]$s.Findings.Add((New-Finding -Family DoomsDay -CurrentName 'renamed.jar' -FullPath 'C:\fixture\renamed.jar' -Verdict DETECTED -VerificationStatus VERIFIED -SHA256 ('A'*64) -Confidence 100 -DetectionReasons @('Synthetic confirmed result.')))
    for ($i=0; $i -lt 50; $i++) { [void]$s.Findings.Add((New-Finding -CurrentName "info-$i.dll" -FullPath "C:\fixture\info-$i.dll" -Verdict INFO)) }
    $s.Findings.Add($s.Findings[0]) | Out-Null
    $lines=@(Show-ScanComplete $s 6>&1 | ForEach-Object { $_.ToString() })
    Assert-True ($lines.Count -eq 2 -and $lines[0] -ceq 'DOOMSDAY DETECTED' -and $lines[1] -ceq 'File: C:\fixture\renamed.jar')
    Assert-True ($s.Findings.Count -eq 52) 'Presentation must not remove evidence from the report.'
}

Test-Case 'Compact output cannot promote unverified, conflicting or other-family results' {
    Set-TestDatabase @((New-TestSignature SHA256 ('A'*64)))
    foreach ($case in @(@('SUSPICIOUS','UNVERIFIED','DoomsDay'),@('HIGH CONFIDENCE','PROBABLE','DoomsDay'),@('DETECTED','PENDING','DoomsDay'),@('DETECTED','CONFLICTING','DoomsDay'),@('DETECTED','VERIFIED','Other'))) {
        $s=New-ScanState Fast
        [void]$s.Findings.Add((New-Finding -Family $case[2] -FullPath 'C:\fixture\unverified.jar' -Verdict $case[0] -VerificationStatus $case[1] -Confidence 100))
        $lines=@(Show-ScanComplete $s 6>&1 | ForEach-Object { $_.ToString() })
        Assert-True ($lines.Count -eq 1 -and $lines[0] -notmatch 'DOOMSDAY DETECTED|unverified.jar')
    }
}

Test-Case 'Compact partial coverage is not presented as a clean result' {
    Set-TestDatabase @((New-TestSignature SHA256 ('A'*64)))
    $s=New-ScanState Fast; $s.FilesSkipped=1
    $lines=@(Show-ScanComplete $s 6>&1 | ForEach-Object { $_.ToString() })
    Assert-True ($lines.Count -eq 1 -and $lines[0] -like 'INCONCLUSIVE*')
    [void]$s.Findings.Add((New-Finding -Family DoomsDay -FullPath 'C:\fixture\verified.jar' -Verdict DETECTED -VerificationStatus VERIFIED))
    $lines=@(Show-ScanComplete $s 6>&1 | ForEach-Object { $_.ToString() })
    Assert-True ($lines.Count -eq 3 -and $lines[0] -ceq 'DOOMSDAY DETECTED' -and $lines[2] -like 'INCONCLUSIVE*')
}

Test-Case 'Quiet report export still writes all findings and evidence without report-path chatter' {
    Set-TestDatabase
    $s=New-ScanState Fast
    [void]$s.Findings.Add((New-Finding -FullPath 'C:\fixture\review.jar' -Verdict REVIEW -Evidence @([pscustomobject]@{ Source='fixture'; Detail='preserved' })))
    $oldReportDirectory=$script:ReportDirectory
    $script:ReportDirectory=Join-Path $testDirectory 'QuietReports'
    try {
        $output=@(Export-ScanReport $s -Quiet 6>&1)
        Assert-True ($output.Count -eq 1 -and $output[0].PSObject.Properties['Json'])
        $report=Get-Content -LiteralPath $output[0].Json -Raw | ConvertFrom-Json
        Assert-True ($report.Findings.Count -eq 1 -and $report.Findings[0].Evidence[0].Detail -eq 'preserved')
        Assert-True ((Get-Content -LiteralPath $output[0].Text -Raw).Contains('C:\fixture\review.jar'))
    } finally { $script:ReportDirectory=$oldReportDirectory }
}

Test-Case 'Prefetch supported layouts extract Unicode paths, volumes and run count' {
    $unicodeName='\VOLUME{fixture-volume}\Users\'+[char]0x00D6+'MER ATLAS\renamed.png'
    foreach ($version in @(26,30,31)) {
        $r=Read-PrefetchRecord (New-PrefetchFixture -Version $version -ReferencePath $unicodeName)
        Assert-True ($r.Version -eq $version -and $r.References[0] -eq $unicodeName -and $r.Volumes[0].Serial -eq '12345678' -and $r.RunCount -eq 7 -and $r.LastRunTimesUtc.Count -eq 1)
    }
}
Test-Case 'Prefetch variant 2 uses the correct run-count offset' {
    $bytes=New-PrefetchFixture -Version 31
    [BitConverter]::GetBytes([uint32]296).CopyTo($bytes,84)
    [BitConverter]::GetBytes([uint32]11).CopyTo($bytes,200)
    Assert-True ((Read-PrefetchRecord $bytes).RunCount -eq 11)
}
Test-Case 'Prefetch filenames are not truncated at 1000 entries' {
    $r=Read-PrefetchRecord (New-PrefetchFixture -ReferenceCount 1847)
    Assert-True ($r.References.Count -eq 1847)
}
Test-Case 'Prefetch invalid bounds and oversized MAM never allocate unchecked output' {
    $invalid=New-PrefetchFixture
    [BitConverter]::GetBytes([uint32]2147483647).CopyTo($invalid,104)
    $failed=$false; try { Read-PrefetchRecord $invalid | Out-Null } catch { $failed=$true }; Assert-True $failed
    $invalid=[byte[]](77,65,77,4,255,255,255,127,1)
    $failed=$false; try { Expand-PrefetchBytes $invalid | Out-Null } catch { $failed=$true }; Assert-True $failed
}
Test-Case 'Prefetch volume mapping never guesses C or ambiguous serials' {
    $r=Read-PrefetchRecord (New-PrefetchFixture)
    $volumes=@([pscustomobject]@{ Root='D:\'; Serial='12345678' })
    Assert-True ((Resolve-PrefetchReference $r.References[0] $r.Volumes $volumes) -eq 'D:\Users\ATLAS\renamed.png')
    Assert-True ($null -eq (Resolve-PrefetchReference $r.References[0] $r.Volumes @()))
    $volumes += [pscustomobject]@{ Root='C:\'; Serial='12345678' }
    Assert-True ($null -eq (Resolve-PrefetchReference $r.References[0] $r.Volumes $volumes))
    Assert-True ($null -eq (Resolve-PrefetchReference '\\server\share\payload.jar' @() $volumes))
}
Test-Case 'Fast profile inspects every class byte without unnecessary constant-pool work' {
    Set-TestDatabase @((New-TestSignature String 'fixture-only-marker-7fe56cd1' 'fixture' $false))
    $large=New-TestArchive 'fast-large.jar' 1847 @{ 'last/payload.dat'=[Text.Encoding]::UTF8.GetBytes('fixture-only-marker-7fe56cd1') }
    $script:AnalysisProfile='Signatures'
    try {
        $r=Inspect-TestFile $large
        Assert-True ($r.State.FilesFullyScanned -eq 1 -and $r.Finding.ArchiveAnalysis.ClassesAnalyzed -eq 1847 -and $r.Finding.Evidence.Count -eq 1)
        Assert-True ($r.Finding.ArchiveAnalysis.ClassShapeFingerprint -eq '' -and $r.Finding.Verdict -ne 'DETECTED')
    } finally { $script:AnalysisProfile='Detailed' }
}
Test-Case 'Fast automatically parses class names when installed signatures need them' {
    Set-TestDatabase @((New-TestSignature Class 'fixture.C0' 'fixture' $false))
    $script:AnalysisProfile='Signatures'
    try {
        $r=Inspect-TestFile $plain
        Assert-True ($r.Finding.Evidence.Count -eq 1 -and $r.Finding.ArchiveAnalysis.ClassParsing -eq 'Detailed')
    } finally { $script:AnalysisProfile='Detailed' }
}
Test-Case 'Fast independent verification still rejects malformed classes' {
    $file=New-TestArchive 'fast-malformed.jar' 0 @{ 'broken.class'=[byte[]](0xCA,0xFE,0xBA,0xBE) }
    Set-TestDatabase @((New-TestSignature SHA256 (Get-CachedFileSha256 $file)))
    $script:AnalysisProfile='Signatures'
    try {
        $r=Inspect-TestFile $file
        Assert-True ($r.Finding.Verdict -eq 'INCONCLUSIVE' -and $r.Finding.VerificationStatus -eq 'CONFLICTING')
    } finally { $script:AnalysisProfile='Detailed' }
}
Test-Case 'Fast parallel profile is transferred to workers without changing verification rules' {
    Set-TestDatabase @((New-TestSignature SHA256 (Get-CachedFileSha256 $plain)))
    $script:AnalysisProfile='Signatures'
    try {
        $s=New-ScanState Fast
        Invoke-ParallelInspection -Files @($plain) -State $s -WorkerLimit 2 | Out-Null
        Assert-True ($s.Findings.Count -eq 1 -and $s.Findings[0].Verdict -eq 'DETECTED' -and $s.Findings[0].VerificationStatus -eq 'VERIFIED')
        Assert-True ($s.Evidence[0].ClassParsing -like 'All class bytes*')
    } finally { $script:AnalysisProfile='Detailed' }
}
Test-Case 'Fast has no broad-directory or USN fallback when evidence is absent' {
    Set-TestDatabase
    function Get-FastLocalVolumes { param($State); return @() }
    function Get-FastRuntimeCandidates { param($State,$Candidates,$Hosts,$ModRoots,$CurrentVolumes); Add-SourceStatus $State 'Java' $true 'No running Java' }
    function Get-FastPrefetchCandidates { param($State,$Candidates,$Hosts,$CurrentVolumes); Add-SourceStatus $State 'Prefetch' $false 'Unavailable' }
    function Get-MinecraftLocations { return @() }
    function Get-DefaultAdsRoots { throw 'Unexpected broad roots' }
    function Get-UsnJournalEvidence { throw 'Unexpected USN read' }
    function Get-ReadOnlyFiles { throw 'Unexpected broad traversal' }
    function Export-ScanReport { param($State) }
    $s=Invoke-ScanMode Fast
    Assert-True ($s.AnalysisProfile -eq 'Signatures' -and $script:AnalysisProfile -eq 'Detailed' -and $s.CandidateFiles -eq 0 -and $s.UnavailableSources.Count -gt 0)
}

if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    function Compress-PrefetchFixture {
        param([byte[]]$Bytes,[switch]$Checksum)
        # Test-only Windows compression binding creates synthetic, non-executable data.
        $name=[Reflection.AssemblyName]::new('RevealFixture_'+[guid]::NewGuid().ToString('N'))
        $a=[Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($name,[Reflection.Emit.AssemblyBuilderAccess]::Run)
        $t=$a.DefineDynamicModule($name.Name).DefineType('FixtureCompression',[Reflection.TypeAttributes]::Public)
        $m=$t.DefinePInvokeMethod('RtlCompressBuffer',(Join-Path ([Environment]::SystemDirectory) 'ntdll.dll'),'RtlCompressBuffer',([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl),[Reflection.CallingConventions]::Standard,[uint32],[Type[]]@([uint16],[IntPtr],[uint32],[IntPtr],[uint32],[uint32],[uint32].MakeByRefType(),[IntPtr]),[Runtime.InteropServices.CallingConvention]::Winapi,[Runtime.InteropServices.CharSet]::Ansi)
        $m.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig); $compressor=$t.CreateType()
        $api=Get-PrefetchNativeApi
        [uint32]$ws=0; [uint32]$fragment=0
        Assert-True ($api::RtlGetCompressionWorkSpaceSize(4,[ref]$ws,[ref]$fragment) -eq 0)
        $source=[IntPtr]::Zero; $destination=[IntPtr]::Zero; $workspace=[IntPtr]::Zero
        try {
            $source=[Runtime.InteropServices.Marshal]::AllocHGlobal($Bytes.Length)
            $destination=[Runtime.InteropServices.Marshal]::AllocHGlobal($Bytes.Length*2+4096)
            $workspace=[Runtime.InteropServices.Marshal]::AllocHGlobal([int]$ws)
            [Runtime.InteropServices.Marshal]::Copy($Bytes,0,$source,$Bytes.Length)
            [uint32]$written=0
            $status=$compressor::RtlCompressBuffer(4,$source,[uint32]$Bytes.Length,$destination,[uint32]($Bytes.Length*2+4096),4096,[ref]$written,$workspace)
            Assert-True ($status -eq 0) ('Synthetic compression failed: '+$status)
            $headerSize=if ($Checksum) { 12 } else { 8 }
            $result=[byte[]]::new($headerSize+$written)
            [byte[]](77,65,77,4) | ForEach-Object -Begin { $i=0 } -Process { $result[$i++]=$_ }
            [BitConverter]::GetBytes([uint32]$Bytes.Length).CopyTo($result,4)
            [Runtime.InteropServices.Marshal]::Copy($destination,$result,$headerSize,[int]$written)
            if ($Checksum) { $result[3]=132; [BitConverter]::GetBytes([uint32]$api::RtlComputeCrc32(0,$result,[uint32]$result.Length)).CopyTo($result,8) }
            return ,$result
        } finally { foreach ($p in @($source,$destination,$workspace)) { if ($p -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($p) } } }
    }
    Test-Case 'Windows MAM decompression round-trip with and without checksum' {
        $plainPf=New-PrefetchFixture -ReferenceCount 7
        foreach ($crc in @($false,$true)) {
            $packed=Compress-PrefetchFixture $plainPf -Checksum:$crc
            $expanded=Expand-PrefetchBytes $packed
            Assert-True ([Convert]::ToBase64String($expanded) -ceq [Convert]::ToBase64String($plainPf))
            Assert-True ((Read-PrefetchRecord $packed).References.Count -eq 7)
        }
        $packed[8]=$packed[8] -bxor 1
        $failed=$false; try { Expand-PrefetchBytes $packed | Out-Null } catch { $failed=$true }; Assert-True $failed
    }
    Test-Case 'Fast Prefetch collector sees renamed tiny JARs with more than 30 classes' {
        Set-TestDatabase
        $dir=Join-Path $testDirectory 'pf'; [void][IO.Directory]::CreateDirectory($dir)
        $jar=New-TestArchive 'prefetch-renamed.png' 35
        $localRoot=[IO.Path]::GetPathRoot($jar)
        $r=New-PrefetchFixture -ReferencePath $jar
        [IO.File]::WriteAllBytes((Join-Path $dir 'JAVAW.EXE-12345678.pf'),(Compress-PrefetchFixture $r))
        $s=New-ScanState Fast; $c=[Collections.Generic.HashSet[string]]::new(); $h=[Collections.Generic.HashSet[string]]::new()
        Get-FastPrefetchCandidates $s $c $h @([pscustomobject]@{ Root=$localRoot; Serial='12345678' }) $dir
        Assert-True ($c.Count -eq 1 -and $c.Contains($jar) -and $s.FilesSkipped -eq 0 -and $s.UnavailableSources.Count -eq 0)
    }
    Test-Case 'Fast missing reference is REVIEW and not DELETED or DETECTED' {
        Set-TestDatabase
        $missing=Join-Path $testDirectory 'DoomsDay-missing.jar'
        $s=New-ScanState Fast; $c=[Collections.Generic.HashSet[string]]::new(); $h=[Collections.Generic.HashSet[string]]::new()
        Add-FastCandidate $missing 'Java Prefetch reference' $s $c $h @([pscustomobject]@{ Root=[IO.Path]::GetPathRoot($missing); Serial='12345678' })
        Assert-True ($s.Findings.Count -eq 1 -and $s.Findings[0].Verdict -eq 'REVIEW' -and $s.Findings[0].Status -eq 'UNKNOWN' -and $c.Count -eq 0)
    }
    Test-Case 'Fast candidate collection does not exclude files above 15 MiB' {
        Set-TestDatabase
        $file=Join-Path $testDirectory 'large-candidate.bin'
        $stream=[IO.File]::Create($file); try { $stream.SetLength(16MB) } finally { $stream.Dispose() }
        $s=New-ScanState Fast; $c=[Collections.Generic.HashSet[string]]::new(); $h=[Collections.Generic.HashSet[string]]::new()
        Add-FastCandidate $file 'Java Prefetch reference' $s $c $h @([pscustomobject]@{ Root=[IO.Path]::GetPathRoot($file); Serial='12345678' })
        Assert-True ($c.Contains($file) -and $s.FilesSkipped -eq 0)
    }
} else { [void]$testResults.Add([pscustomobject]@{ Test='Windows MAM and targeted collectors'; Result='NOT RUN'; Error='Windows required' }) }

$resultPath=Join-Path $testDirectory 'test-results.json'
[IO.File]::WriteAllText($resultPath,($testResults | ConvertTo-Json -Depth 5))
Write-Host "Test results: $resultPath"
Write-Host 'Synthetic tests measure engine behavior, NOT DoomsDay detection accuracy. Windows artifact collectors require Windows integration testing.'
if (@($testResults | Where-Object Result -eq 'FAIL').Count -gt 0) { throw 'Regression suite failed.' }
