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
Test-Case 'Empty source lists do not become null' { $s=New-ScanState File; Add-SourceStatus $s A $true; Add-SourceStatus $s B $false; Assert-True ($s.AnalyzedSources.Count -eq 1 -and $s.UnavailableSources.Count -eq 1) }
Test-Case 'No-signature clean JAR' { Set-TestDatabase; $r=Inspect-TestFile $plain; Assert-True ($r.Finding.Verdict -eq 'INFO' -and $r.State.FilesFullyScanned -eq 1) }
Test-Case 'Class binary parser' { $c=Read-JavaClassIndex (Get-TestClassBytes); Assert-True ($c.Name -eq 'fixture/Example' -and 'java/lang/Object' -in $c.References) }
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
Test-Case 'Quoted JVM args and agent options' { $j=Get-JvmArguments 'javaw.exe "-javaagent:C:\Some Folder\agent.jar=option" -agentpath:"C:\Some Folder\native.dll" -cp "C:\A B\a.jar;C:\b.jar"'; Assert-True ($j.JavaAgent[0] -eq 'C:\Some Folder\agent.jar=option' -and $j.AgentPath[0] -eq 'C:\Some Folder\native.dll' -and $j.ClassPath.Count -eq 1) }
Test-Case 'Missing candidate warning, no scan crash' { Set-TestDatabase; $r=Inspect-TestFile (Join-Path $testDirectory 'missing.jar'); Assert-True ($r.State.FilesSkipped -eq 1) }
Test-Case 'Static cleaner combination is REVIEW, not DoomsDay' { Set-TestDatabase; $x=Join-Path $testDirectory 'synthetic-tool.py'; [IO.File]::WriteAllText($x,'# fixture text only: javaw.exe WriteProcessMemory .oracle_jre_usage'); $r=Inspect-TestFile $x; Assert-True ($r.Finding.Verdict -eq 'REVIEW' -and $r.Finding.Family -eq 'Unknown') }
Test-Case 'Null-safe report export and repeat scan' { Set-TestDatabase; $s=New-ScanState File; $script:ReportDirectory=Join-Path $testDirectory 'Reports'; $a=Export-ScanReport $s; $b=Export-ScanReport (New-ScanState File); Assert-True ((Test-Path $a.Json) -and (Test-Path $b.Text) -and $a.Json -ne $b.Json) }
Test-Case 'Empty signatures cannot report a clean system' { Set-TestDatabase; $s=New-ScanState File; Complete-ScanState $s; $output=Show-ScanComplete $s 6>&1 | Out-String; Assert-True ($output -match 'INCONCLUSIVE' -and $output -notmatch '\[NO EVIDENCE FOUND\]') }
Test-Case 'File content unchanged by inspection' { $before=Get-FileHash $plain; [void](Inspect-TestFile $plain); Assert-True ((Get-FileHash $plain).Hash -eq $before.Hash) }
Test-Case 'Localized event XML fields are parsed by name' { $d=Get-EventXmlFields '<Event><EventData><Data Name="Image">C:\javaw.exe</Data><Data Name="TargetFilename">C:\payload.jar</Data></EventData></Event>'; Assert-True ($d.Image -eq 'C:\javaw.exe' -and $d.TargetFilename -eq 'C:\payload.jar') }
Test-Case 'XML external entities prohibited' { $blocked=$false; try { Get-EventXmlFields '<!DOCTYPE x [<!ENTITY x SYSTEM "file:///never-read">]><Event>&x;</Event>' } catch { $blocked=$true }; Assert-True $blocked }
Test-Case 'No basename-only evidence correlation' { Set-TestDatabase; $s=New-ScanState Full; $f=New-Finding -CurrentName 'client.jar' -FullPath 'C:\A\client.jar'; [void]$s.Findings.Add($f); [void]$s.Evidence.Add([pscustomobject]@{ Source='Test'; Path='C:\B\client.jar' }); Invoke-EvidenceCorrelation $s; Assert-True ($f.Evidence.Count -eq 0) }
Test-Case 'Exact-path context does not upgrade verdict' { Set-TestDatabase; $s=New-ScanState Full; $f=New-Finding -CurrentName 'client.jar' -FullPath 'C:\A\client.jar'; [void]$s.Findings.Add($f); [void]$s.Evidence.Add([pscustomobject]@{ Source='Test'; Path='C:\A\client.jar' }); Invoke-EvidenceCorrelation $s; Assert-True ($f.Evidence.Count -eq 1 -and $f.Verdict -eq 'INFO') }
Test-Case 'Distributed database contains no invented verified signatures' { Import-DoomsDaySignatures | Out-Null; $s=New-ScanState File; Assert-True ($s.SignatureCount -eq 3 -and $s.VerifiedSignatureCount -eq 0) }
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
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
} else {
    [void]$testResults.Add([pscustomobject]@{ Test='NTFS ADS integration'; Result='NOT RUN'; Error='Windows/NTFS required' })
}
$resultPath=Join-Path $testDirectory 'test-results.json'
[IO.File]::WriteAllText($resultPath,($testResults | ConvertTo-Json -Depth 5))
Write-Host "Test results: $resultPath"
Write-Host 'Synthetic tests measure engine behavior, NOT DoomsDay detection accuracy. Windows artifact collectors require Windows integration testing.'
if (@($testResults | Where-Object Result -eq 'FAIL').Count -gt 0) { throw 'Regression suite failed.' }
