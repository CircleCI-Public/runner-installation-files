#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Uninstalls CircleCI Runner set up by the unified Windows install script, whether it was
  installed as a Windows service or with autologon.

.DESCRIPTION
  Every step checks for what it removes and carries on if it is missing, so the script is safe
  to re-run and to use after a partial install. It tries to remove both the service and the
  autologon setup every time, so it cleans up whichever mode was used, even if that is not known.
  The lock screen, screensaver and sleep settings are only restored if an autologon setup is found,
  so a service install, which never changed them, leaves them as they were.

.PARAMETER Username
  The local user the runner runs as. Must match what the install script used.

.PARAMETER InstallDir
  The runner install directory. Must match what the install script used.
#>
param(
  [string]$Username = "circleci",
  [string]$InstallDir = "$env:ProgramFiles\CircleCI"
)

$ErrorActionPreference = "Stop"

# The service and the first logon task are named as the install script names them, with -Service and
# -Autologon. The session keeper task is legacy RDP only, listed so old installs clean up.
$serviceName = "CircleCIRunner"
$logonTaskNames = @("CircleCI Runner Agent", "CircleCI Runner Agent session keeper")
$userDescription = "Created by the CircleCI Runner installer"

$failures = @()
$profileCleanupPending = $false
function Invoke-Step($description, [scriptblock]$action) {
  Write-Host $description
  try { & $action }
  catch {
    Write-Warning "Failed: $description - $_"
    $script:failures += $description
  }
}

# InstallDir is removed recursively, so refuse anything that is not clearly a dedicated directory
$resolvedInstallDir = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
$protectedPaths = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:USERPROFILE, $env:SystemDrive) |
  Where-Object { $_ } |
  ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\') }
if ([string]::IsNullOrWhiteSpace($InstallDir) -or
    [System.IO.Path]::GetPathRoot($resolvedInstallDir).TrimEnd('\') -eq $resolvedInstallDir -or
    $protectedPaths -contains $resolvedInstallDir) {
  throw "Refusing to remove '$InstallDir': it is empty, a drive root or a system directory"
}

# Deletes an LSA secret. Passing a null value to LsaStorePrivateData removes it.
function Remove-LsaSecret($name) {
  if (-not ("CircleCI.LsaSecret" -as [type])) {
    Add-Type -Namespace CircleCI -Name LsaSecret -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)]
public struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
[StructLayout(LayoutKind.Sequential)]
public struct LSA_OBJECT_ATTRIBUTES {
  public int Length; public IntPtr RootDirectory; public IntPtr ObjectName;
  public int Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
}
[DllImport("advapi32.dll")] public static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attrs, uint access, out IntPtr handle);
[DllImport("advapi32.dll")] public static extern uint LsaStorePrivateData(IntPtr handle, ref LSA_UNICODE_STRING keyName, IntPtr privateData);
[DllImport("advapi32.dll")] public static extern uint LsaClose(IntPtr handle);
[DllImport("advapi32.dll")] public static extern int LsaNtStatusToWinError(uint status);
'@
  }
  $attrs = New-Object CircleCI.LsaSecret+LSA_OBJECT_ATTRIBUTES
  $attrs.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($attrs)
  $handle = [IntPtr]::Zero
  $POLICY_CREATE_SECRET = 0x00000020
  $status = [CircleCI.LsaSecret]::LsaOpenPolicy([IntPtr]::Zero, [ref]$attrs, $POLICY_CREATE_SECRET, [ref]$handle)
  if ($status -ne 0) { throw "LsaOpenPolicy failed: $([CircleCI.LsaSecret]::LsaNtStatusToWinError($status))" }
  $buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($name)
  try {
    $key = New-Object CircleCI.LsaSecret+LSA_UNICODE_STRING
    $key.Length = [uint16]($name.Length * 2)
    $key.MaximumLength = [uint16](($name.Length + 1) * 2)
    $key.Buffer = $buffer
    $status = [CircleCI.LsaSecret]::LsaStorePrivateData($handle, [ref]$key, [IntPtr]::Zero)
    # STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034) means there was no secret to remove. It is written in
    # decimal because PowerShell reads the 0xC0000034 literal as a negative Int32, which never equals
    # the unsigned status.
    $STATUS_OBJECT_NAME_NOT_FOUND = [uint32]3221225524
    if ($status -ne 0 -and $status -ne $STATUS_OBJECT_NAME_NOT_FOUND) {
      throw "LsaStorePrivateData failed: $([CircleCI.LsaSecret]::LsaNtStatusToWinError($status))"
    }
  }
  finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
    [void][CircleCI.LsaSecret]::LsaClose($handle)
  }
}

# Removes the "Log on as a service" right the install script grants to the service account
function Revoke-ServiceLogonRight([System.Security.Principal.SecurityIdentifier]$sid) {
  if (-not ("CircleCI.LsaRights" -as [type])) {
    Add-Type -Namespace CircleCI -Name LsaRights -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)]
public struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
[StructLayout(LayoutKind.Sequential)]
public struct LSA_OBJECT_ATTRIBUTES {
  public int Length; public IntPtr RootDirectory; public IntPtr ObjectName;
  public int Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
}
[DllImport("advapi32.dll")] public static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attrs, uint access, out IntPtr handle);
[DllImport("advapi32.dll")] public static extern uint LsaRemoveAccountRights(IntPtr handle, IntPtr sid, [MarshalAs(UnmanagedType.U1)] bool allRights, ref LSA_UNICODE_STRING rights, uint count);
[DllImport("advapi32.dll")] public static extern uint LsaClose(IntPtr handle);
[DllImport("advapi32.dll")] public static extern int LsaNtStatusToWinError(uint status);
'@
  }
  $right = "SeServiceLogonRight"
  $attrs = New-Object CircleCI.LsaRights+LSA_OBJECT_ATTRIBUTES
  $attrs.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($attrs)
  $handle = [IntPtr]::Zero
  $POLICY_CREATE_ACCOUNT_AND_LOOKUP_NAMES = 0x00000810  # POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES
  $status = [CircleCI.LsaRights]::LsaOpenPolicy([IntPtr]::Zero, [ref]$attrs, $POLICY_CREATE_ACCOUNT_AND_LOOKUP_NAMES, [ref]$handle)
  if ($status -ne 0) { throw "LsaOpenPolicy failed: $([CircleCI.LsaRights]::LsaNtStatusToWinError($status))" }

  $sidBytes = New-Object byte[] $sid.BinaryLength
  $sid.GetBinaryForm($sidBytes, 0)
  $sidBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sidBytes.Length)
  $nameBuffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($right)
  try {
    [System.Runtime.InteropServices.Marshal]::Copy($sidBytes, 0, $sidBuffer, $sidBytes.Length)
    $name = New-Object CircleCI.LsaRights+LSA_UNICODE_STRING
    $name.Length = [uint16]($right.Length * 2)
    $name.MaximumLength = [uint16](($right.Length + 1) * 2)
    $name.Buffer = $nameBuffer
    $status = [CircleCI.LsaRights]::LsaRemoveAccountRights($handle, $sidBuffer, $false, [ref]$name, 1)
    # STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034) means the user never had the right. It is written in
    # decimal for the reason given in Remove-LsaSecret.
    if ($status -ne 0 -and $status -ne [uint32]3221225524) {
      throw "LsaRemoveAccountRights failed: $([CircleCI.LsaRights]::LsaNtStatusToWinError($status))"
    }
  }
  finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($nameBuffer)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($sidBuffer)
    [void][CircleCI.LsaRights]::LsaClose($handle)
  }
}

# Registers a task that removes a user profile by its SID at the next startup, once Windows has let go of
# it, and then removes itself. If the profile is still loaded then, or cannot be removed, the task stays
# for the next startup. The commands are given encoded, so no quoting can break them.
function Register-ProfileCleanup([string]$sid) {
  $taskName = "CircleCI Runner Profile Cleanup $sid"
  $commands = @"
`$profile = Get-CimInstance Win32_UserProfile | Where-Object { `$_.SID -eq '$sid' }
if (`$profile) {
  if (`$profile.Loaded) { exit 1 }
  Remove-CimInstance -InputObject `$profile
}
Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false
"@
  $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commands))
  $action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
  $trigger = New-ScheduledTaskTrigger -AtStartup
  # Wait a minute after startup, so the services the commands need are running
  $trigger.Delay = "PT1M"
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
  [void](Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force)
}

Write-Host "Uninstalling CircleCI Runner (user: $Username, install dir: $resolvedInstallDir)"

# Whether autologon was set up, found before the steps below remove it. DefaultUserName alone is not
# enough, because Windows also keeps the last user there.
$winlogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$winlogonValues = Get-ItemProperty -Path $winlogonKey -ErrorAction SilentlyContinue
$autologonFound = [bool](Get-ScheduledTask -TaskName $logonTaskNames[0] -ErrorAction SilentlyContinue) -or
  ($winlogonValues.AutoAdminLogon -eq "1" -and $winlogonValues.DefaultUserName -eq $Username)

# Service mode. This runs whichever mode was installed, and does nothing if there is no service.
Invoke-Step "Stop and deregister the $serviceName Windows service" {
  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  if ($service) {
    if ($service.Status -ne "Stopped") {
      # The agent finishes its tasks before it stops. If it will not stop, carry on and deregister
      # the service, and the step below stops the process.
      try {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(60))
      }
      catch { Write-Warning "  The service did not stop cleanly, its process is stopped below: $_" }
    }
    sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete exited with $LASTEXITCODE" }
  }
  else { Write-Host "  Service not found, skipping" }
}

# Autologon mode
Invoke-Step "Stop and unregister the runner scheduled tasks" {
  foreach ($taskName in $logonTaskNames) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
      Stop-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue
      Unregister-ScheduledTask -InputObject $task -Confirm:$false
    }
    else { Write-Host "  Task '$taskName' not found, skipping" }
  }
}

Invoke-Step "Stop any runner processes still running from $resolvedInstallDir" {
  Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path.StartsWith("$resolvedInstallDir\", [System.StringComparison]::OrdinalIgnoreCase) } |
    Stop-Process -Force
}

Invoke-Step "Remove the autologon LSA secret and Winlogon values" {
  $winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
  # Only touch the secret and the values if autologon points at the runner user, so an unrelated
  # autologon, including its stored password, is left alone
  if ((Get-ItemProperty -Path $winlogon -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName -eq $Username) {
    Remove-LsaSecret "DefaultPassword"
    foreach ($value in "AutoAdminLogon", "DefaultUserName", "DefaultDomainName", "DefaultPassword", "AutoLogonCount") {
      Remove-ItemProperty -Path $winlogon -Name $value -ErrorAction SilentlyContinue
    }
  }
  else { Write-Host "  Autologon is not set up for $Username, leaving Winlogon values alone" }
}

Invoke-Step "Remove credentials saved by the legacy RDP flow" {
  cmdkey.exe /delete:TERMSRV/localhost | Out-Null
}

# -Autologon stops the session locking or sleeping. It sets these policy values, and zero (never)
# display and sleep timeouts with powercfg.
Invoke-Step "Restore lock screen, screensaver and sleep settings" {
  if (-not $autologonFound) {
    Write-Host "  No autologon setup found, leaving the lock screen, screensaver and sleep settings alone"
    return
  }
  foreach ($policyKey in "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop",
                         "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization") {
    foreach ($value in "ScreenSaveActive", "ScreenSaverIsSecure", "NoLockScreen") {
      Remove-ItemProperty -Path $policyKey -Name $value -ErrorAction SilentlyContinue
    }
  }
  # The original values aren't recorded, so restore the Windows defaults
  powercfg.exe /change monitor-timeout-ac 10
  powercfg.exe /change monitor-timeout-dc 5
  powercfg.exe /change standby-timeout-ac 30
  powercfg.exe /change standby-timeout-dc 15
}

Invoke-Step "Log off $Username" {
  # query.exe reports "no user" on stderr. Windows PowerShell 5.1 turns that into a terminating error
  # under "Stop", even with 2>$null, so run it with errors non-terminating and keep only stdout.
  $previousPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $sessions = @(query.exe user $Username 2>&1 | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
  }
  finally { $ErrorActionPreference = $previousPreference }
  if ($sessions) {
    foreach ($line in ($sessions | Select-Object -Skip 1)) {
      $id = ($line.Trim() -split '\s+') | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
      if ($id) { logoff.exe $id }
    }
  }
  else { Write-Host "  No session for $Username, skipping" }
}

# Only remove the user if the install script created it, which it marks in the account description.
Invoke-Step "Remove user $Username and its profile" {
  $user = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
  if (-not $user) { Write-Host "  User not found, skipping"; return }
  if ($user.Description -ne $userDescription) {
    Write-Host "  User was not created by the install script, leaving it in place"
    return
  }
  # A failure here is not worth keeping the user for
  try { Revoke-ServiceLogonRight $user.SID }
  catch { Write-Warning "  Could not remove the Log on as a service right: $_" }

  # The installer created this user, so whatever still runs as it belongs to the runner or its jobs. A
  # profile cannot be removed while it is loaded, which a running process keeps it.
  $account = "$env:COMPUTERNAME\$Username"
  Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
    Where-Object { $_.UserName -eq $account } |
    Stop-Process -Force -ErrorAction SilentlyContinue

  $sid = $user.SID.Value
  $profile = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }
  # Windows keeps a profile loaded for a moment after its last process stops
  for ($i = 0; $i -lt 30 -and $profile -and $profile.Loaded; $i++) {
    Start-Sleep -Seconds 1
    $profile = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }
  }
  # Windows keeps the profile of a user that ran a service loaded after the service stops, with nothing
  # using it, until the machine restarts. The user can be removed anyway, but the profile cannot be
  # removed until it is unloaded, so a task removes it at the next startup. A reinstall before then
  # works, and gets a profile folder with the machine name added to its name.
  if ($profile -and $profile.Loaded) {
    Remove-LocalUser -Name $Username
    try { Register-ProfileCleanup $sid }
    catch {
      throw ("The user was removed, but a task to remove its profile folder at the next startup could " +
        "not be registered. After a restart, remove the profile folder by hand: $_")
    }
    $script:profileCleanupPending = $true
    Write-Host "  The profile of $Username is still loaded, which Windows only releases at a restart."
    Write-Host "  The user is removed, and its profile folder will be removed at the next startup."
    return
  }
  if ($profile) { Remove-CimInstance -InputObject $profile }
  Remove-LocalUser -Name $Username
}

Invoke-Step "Delete the install directory: $resolvedInstallDir" {
  if (Test-Path -LiteralPath $resolvedInstallDir) {
    Remove-Item -LiteralPath $resolvedInstallDir -Force -Recurse
  }
  else { Write-Host "  Directory not found, skipping" }
}

Write-Host ""
if ($failures.Count -gt 0) {
  Write-Warning "CircleCI Runner uninstall finished with $($failures.Count) failed step(s):"
  $failures | ForEach-Object { Write-Warning "  - $_" }
  exit 1
}
Write-Host "CircleCI Runner uninstalled"
if ($profileCleanupPending) {
  Write-Host "The runner user's profile folder is removed at the next startup, so restart this machine at some point."
}
