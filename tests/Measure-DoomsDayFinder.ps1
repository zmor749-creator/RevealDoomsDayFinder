#requires -Version 5.1
[CmdletBinding()]
param([string]$ScannerPath=(Join-Path $PSScriptRoot '..\DoomsDayFinder.ps1'),[int]$ClassCount=300,[int]$ConstantsPerClass=1000,[ValidateSet('Detailed','Signatures')][string]$Profile='Detailed')
$ErrorActionPreference='Stop'
. $ScannerPath
$script:AnalysisProfile=$Profile
Import-DoomsDaySignatures | Out-Null
$root=Join-Path ([IO.Path]::GetTempPath()) ('RevealBenchmark-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
$path=Join-Path $root 'synthetic-large.jar'
$stream=[IO.File]::Create($path)
$zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$true)
try {
    for($i=0;$i -lt $ClassCount;$i++) {
        $bytes=[Collections.Generic.List[byte]]::new()
        $poolCount=$ConstantsPerClass+5
        $bytes.AddRange([byte[]](0xCA,0xFE,0xBA,0xBE,0,0,0,52,[byte]($poolCount -shr 8),[byte]($poolCount -band 255),1))
        $name=[Text.Encoding]::UTF8.GetBytes("fixture/C$i")
        $bytes.Add([byte]($name.Length -shr 8));$bytes.Add([byte]($name.Length -band 255));$bytes.AddRange($name)
        $bytes.AddRange([byte[]](7,0,1,1,0,16));$bytes.AddRange([Text.Encoding]::ASCII.GetBytes('java/lang/Object'));$bytes.AddRange([byte[]](7,0,3))
        for($j=0;$j -lt $ConstantsPerClass;$j++) {
            $constant=[Text.Encoding]::UTF8.GetBytes("constant-number-$j-fixture")
            $bytes.Add(1);$bytes.Add([byte]($constant.Length -shr 8));$bytes.Add([byte]($constant.Length -band 255));$bytes.AddRange($constant)
        }
        $bytes.AddRange([byte[]](0,33,0,2,0,4,0,0,0,0,0,0,0,0))
        $entry=$zip.CreateEntry("fixture/C$i.class").Open()
        try { $data=$bytes.ToArray();$entry.Write($data,0,$data.Length) } finally { $entry.Dispose() }
    }
} finally { $zip.Dispose();$stream.Dispose() }
$state=New-ScanState File
$timer=[Diagnostics.Stopwatch]::StartNew()
$first=Invoke-FileInspection -LiteralPath $path -State $state -AlwaysRecord -QuietProgress
$timer.Stop()
if($null -eq $first -or $first.ArchiveAnalysis.ClassesAnalyzed -ne $ClassCount) { throw 'Benchmark was not fully analyzed.' }
$repeat=Join-Path $root 'same-content-renamed.jar';[IO.File]::Copy($path,$repeat)
$repeatTimer=[Diagnostics.Stopwatch]::StartNew()
$second=Invoke-FileInspection -LiteralPath $repeat -State $state -AlwaysRecord -QuietProgress
$repeatTimer.Stop()
[pscustomobject]@{ Version=$script:ToolVersion; Profile=$Profile; Classes=$ClassCount; ConstantsPerClass=$ConstantsPerClass; FirstSeconds=[Math]::Round($timer.Elapsed.TotalSeconds,3); RepeatedContentSeconds=[Math]::Round($repeatTimer.Elapsed.TotalSeconds,3); ClassesAnalyzed=$second.ArchiveAnalysis.ClassesAnalyzed; ContentFingerprint=$first.ArchiveAnalysis.ContentFingerprint; ClassShapeFingerprint=$first.ArchiveAnalysis.ClassShapeFingerprint; Verdict=$first.Verdict; Root=$root } | ConvertTo-Json
