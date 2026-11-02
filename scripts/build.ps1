# Build the standalone SimplySec folder and zip:  dist\SimplySec-<version>-win64.zip
# Usage (from the repository root):  powershell -ExecutionPolicy Bypass -File scripts\build.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path $py)) { throw "Create the virtual environment first: py -3.11 -m venv .venv; .venv\Scripts\pip install -e .[dev]" }

$version = (& $py -c "import simplysec; print(simplysec.__version__)").Trim()
Write-Host "Building SimplySec $version"

& $py -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging\simplysec.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }

$folder = Join-Path $root 'dist\SimplySec'
foreach ($exe in 'SimplySec.exe', 'simplysec-cli.exe') {
  if (-not (Test-Path (Join-Path $folder $exe))) { throw "$exe is missing from $folder" }
}
Copy-Item (Join-Path $root 'README.md') $folder -Force

$zip = Join-Path $root "dist\SimplySec-$version-win64.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $folder '*') -DestinationPath $zip -CompressionLevel Optimal
$size = [math]::Round((Get-Item $zip).Length / 1MB, 1)
Write-Host "Done: $zip ($size MB)"
Write-Host "Note: the executables are not code-signed, so Windows SmartScreen will warn on first run."
