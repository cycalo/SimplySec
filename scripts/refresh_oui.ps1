# Rebuild src\SimplySec.Core\Resources\oui.csv.gz from the IEEE MA-L registry (device vendor names).
#
#   powershell -ExecutionPolicy Bypass -File scripts\refresh_oui.ps1                  # download from IEEE
#   powershell -ExecutionPolicy Bypass -File scripts\refresh_oui.ps1 path\to\oui.csv  # a file you downloaded
#
# The output keeps only the 6-hex-digit prefix and the organisation name (data only), sorted,
# gzip-compressed. Rebuild the solution afterwards: the file is an embedded resource.
param([string]$Source)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'src\SimplySec.Core\Resources\oui.csv.gz'

$csvPath = $Source
if (-not $csvPath) {
  $csvPath = Join-Path ([IO.Path]::GetTempPath()) 'simplysec-oui.csv'
  Invoke-WebRequest 'https://standards-oui.ieee.org/oui/oui.csv' -OutFile $csvPath -UseBasicParsing -UserAgent 'SimplySec OUI refresh' -TimeoutSec 120
}

Add-Type -AssemblyName Microsoft.VisualBasic
$parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($csvPath, [Text.Encoding]::UTF8)
$parser.SetDelimiters(',')
$parser.HasFieldsEnclosedInQuotes = $true
$header = $parser.ReadFields()
$a = [Array]::IndexOf($header, 'Assignment')
$o = [Array]::IndexOf($header, 'Organization Name')
if ($a -lt 0 -or $o -lt 0) { throw "unexpected file format (no 'Assignment' / 'Organization Name' column)" }

$rows = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([StringComparer]::Ordinal)
while (-not $parser.EndOfData) {
  $f = $parser.ReadFields()
  if ($f.Count -le [Math]::Max($a, $o)) { continue }
  $prefix = $f[$a].Trim().ToUpperInvariant()
  if ($prefix -cmatch '^[0-9A-F]{6}$') {
    $name = ($f[$o] -split '\s+' | Where-Object { $_ }) -join ' '
    if ($name.Length -gt 80) { $name = $name.Substring(0, 80) }
    $rows[$prefix] = $name
  }
}
$parser.Close()
if ($rows.Count -lt 10000) { throw "only $($rows.Count) entries; refusing to overwrite" }

$sb = New-Object Text.StringBuilder
foreach ($kv in $rows.GetEnumerator()) {
  $name = $kv.Value
  if ($name -match '[",\r\n]') { $name = '"' + $name.Replace('"', '""') + '"' }
  [void]$sb.Append($kv.Key).Append(',').Append($name).Append("`n")
}
$bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($sb.ToString())
$file = [IO.File]::Create($out)
try {
  $gz = New-Object IO.Compression.GZipStream($file, [IO.Compression.CompressionLevel]::Optimal)
  $gz.Write($bytes, 0, $bytes.Length)
  $gz.Dispose()
} finally { $file.Dispose() }
Write-Host "Wrote $($rows.Count) prefixes to $out ($([int]((Get-Item $out).Length / 1KB)) KB)"
