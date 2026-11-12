# Build the tester folder and zip:  dist\SimplySec-<version>-win64\  and  dist\SimplySec-<version>-win64.zip
#
# Usage (from any folder; Windows PowerShell 5.1 or PowerShell 7):
#   powershell -ExecutionPolicy Bypass -File scripts\build.ps1 [-SkipTests] [-DefenderScan]
#
# Both programs are published self-contained for win-x64 with ReadyToRun into one folder.
# The folder contains the .NET runtime, the WPF libraries, the Visual C++ runtime and
# SQLite, so a fresh Windows 10 (1809+) or Windows 11 PC does not need anything installed.
# SimplySec.exe is the app and the daily-check task. simplysec-cli.exe is the command line
# and the administrator helper.
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

# The .NET 10 desktop runtime links the Universal C runtime, which Windows 10 1809+ and
# Windows 11 already contain, and ships its own vcruntime140_cor3.dll. No separate
# .NET or Visual C++ install is required.
$bundled = @(
  'coreclr.dll', 'hostfxr.dll', 'hostpolicy.dll', 'clrjit.dll', 'System.Private.CoreLib.dll',
  'vcruntime140_cor3.dll',
  'PresentationFramework.dll', 'PresentationCore.dll', 'WindowsBase.dll', 'wpfgfx_cor3.dll',
  'DirectWriteForwarder.dll', 'System.Printing.dll',
  'e_sqlite3.dll'
)
foreach ($file in $bundled) {
  if (-not (Test-Path (Join-Path $folder $file))) {
    throw "$file is missing from $folder. This build would not run on a fresh Windows PC."
  }
}

function Assert-BundledRuntime([string]$baseName, [string[]]$frameworks) {
  $configPath = Join-Path $folder "$baseName.runtimeconfig.json"
  if (-not (Test-Path $configPath)) { throw "$baseName.runtimeconfig.json is missing from $folder" }
  $included = @((Get-Content $configPath -Raw | ConvertFrom-Json).runtimeOptions.includedFrameworks)
  $names = @($included | ForEach-Object { $_.name })
  foreach ($need in $frameworks) {
    if ($names -notcontains $need) {
      throw "$baseName does not include $need. A fresh Windows PC would have to install .NET."
    }
  }
}

# Hide this PC's installed .NET. A framework-dependent build fails here; a self-contained one does not.
function Invoke-WithoutInstalledRuntime([string]$exe, [string]$arguments) {
  $empty = Join-Path ([IO.Path]::GetTempPath()) ('simplysec-empty-dotnet-' + [guid]::NewGuid().ToString('n'))
  New-Item -ItemType Directory -Force -Path $empty | Out-Null
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe
  $psi.Arguments = $arguments
  $psi.WorkingDirectory = $folder
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $psi.EnvironmentVariables['DOTNET_ROOT'] = $empty
  $psi.EnvironmentVariables['DOTNET_MULTILEVEL_LOOKUP'] = '0'
  $psi.EnvironmentVariables['DOTNET_ROLL_FORWARD'] = 'Disable'
  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  [void]$proc.Start()
  $outTask = $proc.StandardOutput.ReadToEndAsync()
  $errTask = $proc.StandardError.ReadToEndAsync()
  if (-not $proc.WaitForExit(60000)) {
    try { $proc.Kill() } catch { }
    Remove-Item $empty -Recurse -Force -ErrorAction SilentlyContinue
    throw "$exe timed out"
  }
  $stdout = $outTask.Result.Trim()
  $stderr = $errTask.Result.Trim()
  Remove-Item $empty -Recurse -Force -ErrorAction SilentlyContinue
  if ($proc.ExitCode -ne 0) {
    throw "$exe $arguments failed with exit code $($proc.ExitCode). $stderr $stdout"
  }
  return $stdout
}

foreach ($check in @(
  @{ Exe = 'SimplySec.exe'; Frameworks = @('Microsoft.NETCore.App', 'Microsoft.WindowsDesktop.App') },
  @{ Exe = 'simplysec-cli.exe'; Frameworks = @('Microsoft.NETCore.App') }
)) {
  $exe = $check.Exe
  $base = [IO.Path]::GetFileNameWithoutExtension($exe)
  Assert-BundledRuntime $base $check.Frameworks
  $reported = Invoke-WithoutInstalledRuntime (Join-Path $folder $exe) '--version'
  if ($reported -ne "SimplySec $version") { throw "$exe --version said '$reported', expected 'SimplySec $version'" }
  Write-Host "$exe $reported (runtime bundled, machine-wide .NET hidden)"
}

Write-Host "Opening SimplySec.exe to confirm the window starts..."
$emptyGui = Join-Path ([IO.Path]::GetTempPath()) ('simplysec-empty-dotnet-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path $emptyGui | Out-Null
$gui = New-Object System.Diagnostics.ProcessStartInfo
$gui.FileName = Join-Path $folder 'SimplySec.exe'
$gui.WorkingDirectory = $folder
$gui.UseShellExecute = $false
$gui.EnvironmentVariables['DOTNET_ROOT'] = $emptyGui
$gui.EnvironmentVariables['DOTNET_MULTILEVEL_LOOKUP'] = '0'
$gui.EnvironmentVariables['DOTNET_ROLL_FORWARD'] = 'Disable'
$window = New-Object System.Diagnostics.Process
$window.StartInfo = $gui
[void]$window.Start()
$deadline = (Get-Date).AddSeconds(90)
try {
  do {
    Start-Sleep -Milliseconds 500
    $window.Refresh()
    if ($window.HasExited) { throw "SimplySec.exe exited before showing a window (exit $($window.ExitCode))" }
  } while ($window.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline)
  if ($window.MainWindowHandle -eq [IntPtr]::Zero) { throw "SimplySec.exe did not open a window within 90 seconds" }
  $window.Refresh()
  Write-Host "Window opened: $($window.MainWindowTitle)"
}
finally {
  if (-not $window.HasExited) {
    try { $window.Kill() } catch { }
    [void]$window.WaitForExit(10000)
  }
  Remove-Item $emptyGui -Recurse -Force -ErrorAction SilentlyContinue
}

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
