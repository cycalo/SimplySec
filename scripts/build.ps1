# Build the tester folder and zip:  dist\SimplySec-<version>-win64\  and  dist\SimplySec-<version>-win64.zip
#
# Usage (from any folder; Windows PowerShell 5.1 or PowerShell 7):
#   powershell -ExecutionPolicy Bypass -File scripts\build.ps1 [-SkipTests] [-DefenderScan]
#
# Both programs are published self-contained for win-x64 with ReadyToRun into one folder, so
# testers need nothing installed: SimplySec.exe (the app, and the daily-check task) and
# simplysec-cli.exe (the command line, and the administrator helper).
[CmdletBinding()]
param(
  [switch]$SkipTests,
  [switch]$DefenderScan
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Invoke-Checked([string]$what, [scriptblock]$block) {
  & $block
  if ($LASTEXITCODE -ne 0) { throw "$what failed with exit code $LASTEXITCODE" }
}

# Signing hook. Nothing is signed yet; with a certificate, sign each file here, for example:
#   & signtool.exe sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /sha1 <thumbprint> $file
function Invoke-Signing([string[]]$files) {
  Write-Host "Signing: skipped, no certificate configured ($($files.Count) files would be signed)."
}

$version = ([xml](Get-Content (Join-Path $root 'Directory.Build.props'))).Project.PropertyGroup.Version | Select-Object -First 1
if (-not $version) { throw 'No <Version> in Directory.Build.props' }
$name = "SimplySec-$version-win64"
$folder = Join-Path $root "dist\$name"
$zip = "$folder.zip"
Write-Host "Building $name"

if (-not $SkipTests) {
  foreach ($project in 'tests\SimplySec.Core.Tests', 'tests\SimplySec.Windows.Tests', 'tests\SimplySec.App.Tests') {
    Invoke-Checked "Tests in $project" { dotnet test --project $project -c Release }
  }
}

if (Test-Path $folder) { Remove-Item $folder -Recurse -Force }
foreach ($project in 'src\SimplySec.App\SimplySec.App.csproj', 'src\SimplySec.Cli\SimplySec.Cli.csproj') {
  Invoke-Checked "Publishing $project" {
    dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishReadyToRun=true -o $folder --nologo
  }
}

# Debug symbols stay out of the tester build.
Get-ChildItem $folder -Filter *.pdb | Remove-Item -Force
Copy-Item (Join-Path $root 'packaging\win64\README.txt') $folder -Force

foreach ($exe in 'SimplySec.exe', 'simplysec-cli.exe') {
  if (-not (Test-Path (Join-Path $folder $exe))) { throw "$exe is missing from $folder" }
}
$reported = (& (Join-Path $folder 'simplysec-cli.exe') --version | Out-String).Trim()
if ($reported -ne "SimplySec $version") { throw "simplysec-cli.exe --version said '$reported', expected 'SimplySec $version'" }

Invoke-Signing @(Get-ChildItem $folder -Include 'SimplySec*.exe', 'simplysec*.exe', 'SimplySec*.dll' -Recurse | ForEach-Object FullName)

if (Test-Path $zip) { Remove-Item $zip -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($folder, $zip, [System.IO.Compression.CompressionLevel]::Optimal, $false)

$hash = (Get-FileHash $zip -Algorithm SHA256).Hash
"$hash  $name.zip" | Set-Content "$zip.sha256" -Encoding ascii
$files = (Get-ChildItem $folder -Recurse -File).Count
$size = [math]::Round((Get-Item $zip).Length / 1MB, 1)
Write-Host "Done: $zip ($size MB, $files files)"
Write-Host "SHA-256: $hash"

if ($DefenderScan) {
  $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
  Write-Host 'Microsoft Defender scan of the zip:'
  & $mp -Scan -ScanType 3 -File $zip -DisableRemediation
  if ($LASTEXITCODE -ne 0) { throw "Microsoft Defender reported a problem (exit code $LASTEXITCODE)" }
}
Write-Host 'Note: the programs are not code-signed, so Windows SmartScreen warns on first run.'
