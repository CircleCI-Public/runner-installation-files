#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Uninstalls CircleCI Runner set up by the unified Windows install script, whether it was
  installed as a Windows service or with autologon.

.DESCRIPTION
  Every step checks for what it removes and carries on if it is missing, so the script is safe
  to re-run and to use after a partial install.

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

# Names follow the legacy script and the ONPREM-2636 prototype (service "CircleCIRunner", logon task
# "CircleCI Runner Agent"). The session keeper task is legacy RDP only, listed so old installs clean up.
# TODO(ONP-644/ONP-645): confirm against the unified install script once it is written.
$serviceName = "CircleCIRunner"
$logonTaskNames = @("CircleCI Runner Agent", "CircleCI Runner Agent session keeper")
$userDescription = "Created by the CircleCI Runner installer"

$failures = @()
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

Write-Host "Uninstalling CircleCI Runner (user: $Username, install dir: $resolvedInstallDir)"

# Service mode
Invoke-Step "Stop and deregister the $serviceName Windows service" {
  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  if ($service) {
    if ($service.Status -ne "Stopped") { Stop-Service -Name $serviceName -Force }
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

# ONP-644 stops the session locking or sleeping (screensaver, display timeout, sleep).
# TODO(ONP-644): confirm the exact registry values and powercfg calls the install script uses
Invoke-Step "Restore lock screen, screensaver and sleep settings" {
  foreach ($policyKey in "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop",
                         "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization") {
    foreach ($value in "ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut", "NoLockScreen") {
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
# TODO(ONP-644/ONP-645): the install script must create the user with this exact description.
Invoke-Step "Remove user $Username and its profile" {
  $user = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
  if (-not $user) { Write-Host "  User not found, skipping"; return }
  if ($user.Description -ne $userDescription) {
    Write-Host "  User was not created by the install script, leaving it in place"
    return
  }
  $profile = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $user.SID.Value }
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
