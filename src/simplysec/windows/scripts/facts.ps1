# SimplySec facts collector: one PowerShell call per scan, read-only.
#
# Prints a single JSON object. Every item is { status: ok | needs_admin | error, value, error }
# so a missing permission never looks like a "safe" answer. Only objects and numeric/enum
# values are returned: no localized text is parsed anywhere.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Fact([scriptblock]$Block) {
  try {
    $v = & $Block
    return [ordered]@{ status = 'ok'; value = $v }
  } catch {
    $e = $_.Exception
    $denied = ($e -is [System.UnauthorizedAccessException]) -or
              ($_.CategoryInfo.Category -eq 'PermissionDenied') -or
              ($e.HResult -eq -2147024891) -or
              ($e.Message -match '0x80070005')
    if ($denied) { return [ordered]@{ status = 'needs_admin'; error = $e.Message } }
    return [ordered]@{ status = 'error'; error = $e.Message }
  }
}

function RegValue([string]$Path, [string]$Name) {
  $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $item) { return $null }
  return $item.$Name
}

function IsoDate($d) {
  if ($null -eq $d) { return $null }
  try { return ([datetime]$d).ToUniversalTime().ToString('o') } catch { return $null }
}

$HKLM_TS   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$HKLM_RDP  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$POL_TS    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$HKLM_RA   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
$POL_SYS   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$LSA       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$POL_DNS   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$EXPL_HKLM = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$EXPL_HKCU = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$WU_UX     = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$NETBT     = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'

$facts = [ordered]@{}
$facts.collected = (Get-Date).ToUniversalTime().ToString('o')

$facts.system = Fact {
  $os = Get-CimInstance Win32_OperatingSystem
  $cs = Get-CimInstance Win32_ComputerSystem
  $enc = @(Get-CimInstance Win32_SystemEnclosure | ForEach-Object { $_.ChassisTypes } | Where-Object { $_ })
  $battery = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue).Count -gt 0
  [ordered]@{
    computer = $env:COMPUTERNAME
    os_caption = $os.Caption
    os_version = $os.Version
    os_build = $os.BuildNumber
    part_of_domain = [bool]$cs.PartOfDomain
    domain = $cs.Domain
    chassis = $enc
    has_battery = $battery
    system_drive = $env:SystemDrive
  }
}

$facts.network = Fact {
  $profiles = @(Get-NetConnectionProfile | ForEach-Object {
    [ordered]@{ index = [int]$_.InterfaceIndex; alias = $_.InterfaceAlias; name = $_.Name; category = [int]$_.NetworkCategory }
  })
  $adapters = @(Get-NetAdapter | ForEach-Object {
    [ordered]@{
      index = [int]$_.ifIndex; name = $_.Name; description = $_.InterfaceDescription
      mac = $_.MacAddress; up = ([int]$_.InterfaceOperationalStatus -eq 1)
      if_type = [int]$_.InterfaceType; medium = [int]$_.NdisPhysicalMedium
      virtual = [bool]$_.Virtual; hardware = [bool]$_.HardwareInterface
    }
  })
  $ip = @(Get-NetIPConfiguration | ForEach-Object {
    $gw = @()
    if ($_.IPv4DefaultGateway) { $gw += @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) }
    if ($_.IPv6DefaultGateway) { $gw += @($_.IPv6DefaultGateway | ForEach-Object { $_.NextHop }) }
    $dns = @()
    if ($_.DNSServer) { $dns += @($_.DNSServer | ForEach-Object { $_.ServerAddresses }) }
    [ordered]@{ index = [int]$_.InterfaceIndex; gateways = @($gw); dns = @($dns) }
  })
  $cfg = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
    $guid = $_.SettingID
    $stored = RegValue "$NETBT\Tcpip_$guid" 'NetbiosOptions'
    [ordered]@{
      index = [int]$_.InterfaceIndex; config_index = [int]$_.Index; description = $_.Description
      dhcp_server = $_.DHCPServer; netbios = $_.TcpipNetbiosOptions; netbios_stored = $stored
      guid = $guid
    }
  })
  [ordered]@{ profiles = $profiles; adapters = $adapters; ip = $ip; config = $cfg }
}

$facts.defender = Fact {
  $m = Get-MpComputerStatus
  [ordered]@{
    am_service = [bool]$m.AMServiceEnabled
    antivirus = [bool]$m.AntivirusEnabled
    realtime = [bool]$m.RealTimeProtectionEnabled
    tamper = [bool]$m.IsTamperProtected
    signature_age_days = [int]$m.AntivirusSignatureAge
    signature_updated = IsoDate $m.AntivirusSignatureLastUpdated
    running_mode = [string]$m.AMRunningMode
  }
}

$facts.defender_prefs = Fact {
  $p = Get-MpPreference
  [ordered]@{ controlled_folder_access = [int]$p.EnableControlledFolderAccess }
}

$facts.antivirus = Fact {
  @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
    [ordered]@{ name = $_.displayName; state = [int]$_.productState; exe = $_.pathToSignedProductExe }
  })
}

$facts.smb = Fact {
  $c = Get-SmbServerConfiguration
  [ordered]@{ smb1 = [bool]$c.EnableSMB1Protocol; smb2 = [bool]$c.EnableSMB2Protocol; signing_required = [bool]$c.RequireSecuritySignature }
}

$facts.shares = Fact {
  @(Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object {
    $share = $_
    $access = @(Get-SmbShareAccess -Name $share.Name | ForEach-Object {
      $sid = $null
      try { $sid = (New-Object System.Security.Principal.NTAccount($_.AccountName)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
      [ordered]@{ account = $_.AccountName; sid = $sid; right = [int]$_.AccessRight; allow = ([int]$_.AccessControlType -eq 0) }
    })
    [ordered]@{ name = $share.Name; path = $share.Path; access = $access }
  })
}

$facts.updates = Fact {
  $defenderKbs = @('KB2267602', 'KB4052623', 'KB5007651', 'KB915597')
  $lastHistory = $null
  try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $count = $searcher.GetTotalHistoryCount()
    if ($count -gt 0) {
      foreach ($h in $searcher.QueryHistory(0, [Math]::Min($count, 300))) {
        if ($h.Operation -ne 1 -or ($h.ResultCode -ne 2 -and $h.ResultCode -ne 3)) { continue }
        $m = [regex]::Match([string]$h.Title, 'KB\d{6,7}')
        if (-not $m.Success -or $defenderKbs -contains $m.Value) { continue }
        if ($null -eq $lastHistory -or $h.Date -gt $lastHistory) { $lastHistory = $h.Date }
      }
    }
  } catch {}
  $qfe = Get-CimInstance Win32_QuickFixEngineering | Where-Object { $_.InstalledOn } |
    Sort-Object InstalledOn -Descending | Select-Object -First 1
  $pause = [ordered]@{
    updates = RegValue $WU_UX 'PauseUpdatesExpiryTime'
    quality = RegValue $WU_UX 'PauseQualityUpdatesEndTime'
    feature = RegValue $WU_UX 'PauseFeatureUpdatesEndTime'
  }
  $reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
  [ordered]@{
    last_history_install = IsoDate $lastHistory
    last_hotfix = if ($qfe) { IsoDate $qfe.InstalledOn } else { $null }
    last_hotfix_id = if ($qfe) { $qfe.HotFixID } else { $null }
    pause = $pause
    reboot_pending = [bool]$reboot
  }
}

$facts.uac = Fact {
  [ordered]@{
    enable_lua = RegValue $POL_SYS 'EnableLUA'
    consent_admin = RegValue $POL_SYS 'ConsentPromptBehaviorAdmin'
    secure_desktop = RegValue $POL_SYS 'PromptOnSecureDesktop'
  }
}

$facts.accounts = Fact {
  $users = @(Get-LocalUser | ForEach-Object {
    [ordered]@{ name = $_.Name; sid = $_.SID.Value; enabled = [bool]$_.Enabled; password_required = [bool]$_.PasswordRequired }
  })
  [ordered]@{ users = $users; limit_blank_password_use = RegValue $LSA 'LimitBlankPasswordUse' }
}

$facts.rdp = Fact {
  [ordered]@{
    deny = RegValue $HKLM_TS 'fDenyTSConnections'
    deny_policy = RegValue $POL_TS 'fDenyTSConnections'
    nla = RegValue $HKLM_RDP 'UserAuthentication'
    nla_policy = RegValue $POL_TS 'UserAuthentication'
    port = RegValue $HKLM_RDP 'PortNumber'
    remote_assistance = RegValue $HKLM_RA 'fAllowToGetHelp'
    remote_assistance_policy = RegValue $POL_TS 'fAllowToGetHelp'
  }
}

$facts.llmnr = Fact { [ordered]@{ enable_multicast_policy = RegValue $POL_DNS 'EnableMulticast' } }

$facts.autorun = Fact {
  [ordered]@{
    hklm = RegValue $EXPL_HKLM 'NoDriveTypeAutoRun'
    hkcu = RegValue $EXPL_HKCU 'NoDriveTypeAutoRun'
    no_autorun_hklm = RegValue $EXPL_HKLM 'NoAutorun'
  }
}

$facts.bitlocker = Fact {
  $shell = New-Object -ComObject Shell.Application
  $drive = $env:SystemDrive
  $value = $shell.NameSpace(17).ParseName($drive).ExtendedProperty('System.Volume.BitLockerProtection')
  [ordered]@{ drive = $drive; protection = $value }
}

$facts.firewall_policy = Fact {
  $base = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
  $out = [ordered]@{}
  foreach ($p in 'DomainProfile', 'PrivateProfile', 'PublicProfile', 'StandardProfile') {
    $out[$p] = [ordered]@{
      enable = RegValue "$base\$p" 'EnableFirewall'
      inbound = RegValue "$base\$p" 'DefaultInboundAction'
    }
  }
  $out
}

$facts | ConvertTo-Json -Depth 8 -Compress
