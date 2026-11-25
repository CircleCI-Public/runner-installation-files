#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs CircleCI Runner and its dependencies on Windows (Desktop or Server, AMD64 or ARM64).

.DESCRIPTION
  Installs Git and Gzip, downloads the runner binary for this machine's architecture, creates the
  local user that runs CircleCI tasks, and writes a runner config that only Administrators and that
  user can read. Without a run mode switch it stops there and does not start the runner.

  With -Service it also registers the runner as a Windows service that runs as that user, starts at
  boot after the other services, restarts if it fails, and starts it. The service needs a runner
  release that can run as a Windows service.

  With -Autologon it instead sets this machine to sign in as that user at startup, and registers a
  scheduled task that starts the runner at that sign-in, so the runner has a desktop session. It also
  stops the session from locking or sleeping. The sign-in happens at the next restart, so restart the
  machine to start the runner. -Service and -Autologon cannot be used together.

.PARAMETER RunnerToken
  The runner authentication token.

.PARAMETER RunnerName
  The name of this runner instance.

.PARAMETER ApiUrl
  The runner API URL. Set this to the hostname of your server installation, for example
  https://circleci.example.com. Leave it unset to use CircleCI cloud.

.PARAMETER Username
  The local user that runs CircleCI tasks. Pass the same value to the uninstall script.

.PARAMETER Service
  Run the runner as a Windows service.

.PARAMETER Autologon
  Sign in as the runner user at startup and run the runner in that session. Autologon is one setting
  for the whole machine, so the install stops if the machine already signs in as someone else.

.PARAMETER AgentBinaryPath
  Install this runner binary, a circleci-runner.exe for this machine's architecture, instead of
  downloading the released one. For example, a build that has not been released yet. Nothing checks
  that it is the right binary. Git and Gzip are still installed from the internet.
#>
[CmdletBinding(DefaultParameterSetName = "InstallOnly")]
param(
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RunnerToken,
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RunnerName,
  [string]$ApiUrl,
  [ValidateNotNullOrEmpty()][string]$Username = "circleci",
  [Parameter(ParameterSetName = "Service")][switch]$Service,
  [Parameter(ParameterSetName = "Autologon")][switch]$Autologon,
  [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$AgentBinaryPath
)

# Returns a uniformly random integer in [0, $max) from a cryptographic generator. Get-Random is not
# cryptographically secure, and RandomNumberGenerator.GetInt32 is missing from Windows PowerShell 5.1.
function Get-SecureRandomInt([int]$max) {
  $limit = [uint64]4294967296 - ([uint64]4294967296 % $max)  # reject values that would bias the modulo
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $bytes = New-Object byte[] 4
    while ($true) {
      $rng.GetBytes($bytes)
      $value = [uint64][BitConverter]::ToUInt32($bytes, 0)
      if ($value -lt $limit) { return [int]($value % $max) }
    }
  }
  finally { $rng.Dispose() }
}

function Random-Password($length, $minNonAlpha) {
  $alpha = [char]65..[char]90 + [char]97..[char]122
  $numeric  =  [char]48..[char]57
  # :;<=>?@!#$%&()*+,-./[\]^_`
  $symbols = [char]58..[char]64 + @([char]33) + [char]35..[char]38 + [char]40..[char]47 + [char]91..[char]96

  $nonAlpha = $numeric + $symbols
  $charSet = $alpha + $nonAlpha

  $pwdList = @()
  For ($i = 0; $i -lt $minNonAlpha; $i++) {
    $pwdList += $nonAlpha[(Get-SecureRandomInt $nonAlpha.Count)]
  }
  For ($i = 0; $i -lt ($length - $minNonAlpha); $i++) {
    $pwdList += $charSet[(Get-SecureRandomInt $charSet.Count)]
  }

  # Fisher-Yates shuffle
  For ($i = $pwdList.Count - 1; $i -gt 0; $i--) {
    $j = Get-SecureRandomInt ($i + 1)
    $pwdList[$i], $pwdList[$j] = $pwdList[$j], $pwdList[$i]
  }

  # a bug on Server 2016 joins as stringified integers unles we cast to [char[]]
  ([char[]] $pwdList) -join ""
}

# Returns the machine's native architecture as named in the release manifest. The machine-wide
# PROCESSOR_ARCHITECTURE is read from the registry because $env:PROCESSOR_ARCHITECTURE reports AMD64
# in an emulated x64 shell on an ARM64 machine.
function Get-NativeArchitecture {
  $arch = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PROCESSOR_ARCHITECTURE).PROCESSOR_ARCHITECTURE
  switch ($arch) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "Unsupported processor architecture: $arch" }
  }
}

# Quotes a value as a YAML double-quoted string
function ConvertTo-YamlString($value) {
  '"' + ($value -replace '\\', '\\' -replace '"', '\"') + '"'
}

# Grants a user the "Log on as a service" right. A service account needs it, and creating the service
# does not grant it, so the service fails to start with a logon failure (error 1069) without it.
function Grant-ServiceLogonRight([System.Security.Principal.SecurityIdentifier]$sid) {
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
[DllImport("advapi32.dll")] public static extern uint LsaAddAccountRights(IntPtr handle, IntPtr sid, ref LSA_UNICODE_STRING rights, uint count);
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
    $status = [CircleCI.LsaRights]::LsaAddAccountRights($handle, $sidBuffer, [ref]$name, 1)
    if ($status -ne 0) { throw "LsaAddAccountRights failed: $([CircleCI.LsaRights]::LsaNtStatusToWinError($status))" }
  }
  finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($nameBuffer)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($sidBuffer)
    [void][CircleCI.LsaRights]::LsaClose($handle)
  }
}

# Stores an LSA secret. Windows reads the "DefaultPassword" secret for autologon, so the password does
# not have to be left in plain text in the registry.
function Set-LsaSecret([string]$name, [string]$value) {
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
[DllImport("advapi32.dll")] public static extern uint LsaStorePrivateData(IntPtr handle, ref LSA_UNICODE_STRING keyName, ref LSA_UNICODE_STRING privateData);
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

  $nameBuffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($name)
  $valueBuffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($value)
  try {
    $key = New-Object CircleCI.LsaSecret+LSA_UNICODE_STRING
    $key.Length = [uint16]($name.Length * 2)
    $key.MaximumLength = [uint16](($name.Length + 1) * 2)
    $key.Buffer = $nameBuffer
    $secret = New-Object CircleCI.LsaSecret+LSA_UNICODE_STRING
    $secret.Length = [uint16]($value.Length * 2)
    $secret.MaximumLength = [uint16](($value.Length + 1) * 2)
    $secret.Buffer = $valueBuffer
    $status = [CircleCI.LsaSecret]::LsaStorePrivateData($handle, [ref]$key, [ref]$secret)
    if ($status -ne 0) { throw "LsaStorePrivateData failed: $([CircleCI.LsaSecret]::LsaNtStatusToWinError($status))" }
  }
  finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($nameBuffer)
    # This one holds the password, so it is overwritten with zeros before it is freed
    [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($valueBuffer)
    [void][CircleCI.LsaSecret]::LsaClose($handle)
  }
}

$ErrorActionPreference = "Stop"

# The runner rejects any other characters in its name
if ($RunnerName -notmatch '^[A-Za-z0-9.()_ -]+$') {
  throw "RunnerName must contain only letters, numbers, .()_-, and spaces"
}

# A relative path is resolved here, because the script changes directory before it uses the path
if ($AgentBinaryPath) { $AgentBinaryPath = (Resolve-Path -LiteralPath $AgentBinaryPath).ProviderPath }

$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Autologon is one setting for the whole machine, so stop before changing anything if it is already in
# use for someone else. DefaultUserName alone is not autologon, because Windows also keeps the last user there.
if ($Autologon) {
  $current = Get-ItemProperty -Path $winlogon
  if ($current.AutoAdminLogon -eq "1" -and $current.DefaultUserName -ne $Username) {
    throw ("This machine is already set to sign in as $($current.DefaultUserName) at startup. " +
      "Autologon is one setting for the whole machine, so -Autologon would replace it. " +
      "Remove that autologon first, or use -Service instead.")
  }
}

$arch = Get-NativeArchitecture
$installDirPath = "$env:ProgramFiles\CircleCI"
# The uninstall script only removes the user if it finds this description, so keep the two in sync
$userDescription = "Created by the CircleCI Runner installer"
# The uninstall script removes the service and the logon task by these names
$serviceName = "CircleCIRunner"
$logonTaskName = "CircleCI Runner Agent"

Write-Host "Detected native architecture: $arch"

# Install Chocolatey
Write-Host "Installing Chocolatey as a prerequisite"
Invoke-Expression ((Invoke-WebRequest "https://chocolatey.org/install.ps1" -UseBasicParsing).Content)
Write-Host ""

# Install Git
Write-Host "Installing Git, which is required to run CircleCI jobs"
choco install -y git --params "/GitAndUnixToolsOnPath"
Write-Host ""

# Install Gzip
Write-Host "Installing Gzip, which is required to run CircleCI jobs"
choco install -y gzip
Write-Host ""

Write-Host "Installing CircleCI Runner Agent to $installDirPath"

# mkdir
[void](New-Item "$installDirPath" -ItemType Directory -Force)
Push-Location "$installDirPath"

if ($AgentBinaryPath) {
  # The binary the caller gave is installed in place of the released one
  Write-Host "Installing the CircleCI Runner Agent binary at $AgentBinaryPath"
  $agentFile = "circleci-runner"
  Copy-Item -LiteralPath $AgentBinaryPath -Destination "$installDirPath\$agentFile.exe" -Force
}
else {
  # Download CircleCI runner agent binary
  $manifestDist = "https://circleci-binary-releases.s3.amazonaws.com/circleci-runner/manifest.json"
  Write-Host "Determining current version of CircleCI Runner Agent"
  $windowsManifest = (Invoke-RestMethod -Uri "$manifestDist").releases.current.windows.$arch
  if (-not $windowsManifest) {
    throw "No CircleCI Runner Agent release is available for windows/$arch"
  }
  Write-Host "Downloading and verifying CircleCI Runner Agent binary"
  $downloadUrl = $windowsManifest.url
  $agentHash = $windowsManifest.sha256
  Write-Host "Download URL: $downloadUrl"
  Write-Host "SHA256 hash: $agentHash"
  $tarFile = $downloadUrl.split("/")[-1]
  $agentFile = $tarFile.split("_")[0]
  Write-Host "Downloading CircleCI Runner Agent binary archive: $tarFile"
  Invoke-WebRequest "$downloadUrl" -OutFile "$tarFile" -UseBasicParsing
  Write-Host "Verifying CircleCI Runner Agent binary download"
  if ((Get-FileHash "$tarFile" -Algorithm SHA256).Hash.ToLower() -ne $agentHash.ToLower()) {
      throw "Invalid checksum for CircleCI Runner Agent binary, please try download again"
  }
  tar -xvf "$tarFile"
  Remove-Item "$tarFile"
}

# NT credentials to use
Write-Host "Generating a random password"
$passwd = Random-Password 42 10
$passwdSecure = $(ConvertTo-SecureString -String $passwd -AsPlainText -Force)

# Create a user with the generated password. This fails if the user already exists, so a user that
# is present afterwards was always created here.
Write-Host "Creating a new administrator user to run CircleCI tasks"
$user = New-LocalUser $username -Password $passwdSecure -PasswordNeverExpires -Description $userDescription

# Make the user an administrator
Add-LocalGroupMember Administrators $user

# Write the config, with the token, to a file only Administrators and the runner user can read.
# The file is locked down before the token is written to it.
Write-Host "Writing the config file for CircleCI Runner Agent"
$configPath = "$installDirPath\runner-agent-config.yaml"
[void](New-Item $configPath -ItemType File -Force)
# S-1-5-32-544 is the Administrators group, referenced by SID so this works on any system language
icacls.exe $configPath /inheritance:r /grant:r "*S-1-5-32-544:(F)" "${username}:(R)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to restrict access to $configPath (icacls exited with $LASTEXITCODE)" }

# An unset ApiUrl leaves a blank line, which YAML ignores
$apiUrlLine = if ($ApiUrl) { "  url: $(ConvertTo-YamlString $ApiUrl)" } else { "" }
@"
api:
  auth_token: $(ConvertTo-YamlString $RunnerToken)
$apiUrlLine
runner:
  name: $(ConvertTo-YamlString $RunnerName)
  mode: continuous
  task_agent_directory: $installDirPath\Agents
  working_directory: $installDirPath\Workdir
  cleanup_working_directory: true
logging:
  file: $installDirPath\circleci-runner.log
"@ -replace "([^`r])`n", "`$1`r`n" | Out-File $configPath -Encoding ascii

Pop-Location
Write-Host ""
Write-Host "CircleCI Runner Agent installed to $installDirPath"
Write-Host ""

if ($Service) {
  Write-Host "Registering CircleCI Runner Agent as the $serviceName Windows service, running as $Username"
  try {
    $agentPath = "$installDirPath\$agentFile.exe"
    if (-not (Test-Path -LiteralPath $agentPath)) { throw "$agentPath was not found" }

    Grant-ServiceLogonRight $user.SID

    # The password goes in as a credential, so it is never on a command line
    $cred = New-Object System.Management.Automation.PSCredential (".\$Username", $passwdSecure)
    [void](New-Service -Name $serviceName -DisplayName "CircleCI Runner Agent" `
      -Description "CircleCI self-hosted runner agent" -StartupType Automatic -Credential $cred `
      -BinaryPathName "`"$agentPath`" machine --config `"$configPath`"")

    # New-Service in Windows PowerShell 5.1 cannot set a delayed start or recovery actions
    sc.exe config $serviceName start= delayed-auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to set a delayed start (sc.exe exited with $LASTEXITCODE)" }
    # Restart after 5 seconds, up to 3 times in a row, clearing the count after a day without failures
    sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to set the recovery actions (sc.exe exited with $LASTEXITCODE)" }
    # Also run the recovery actions when the service stops with a non-zero exit code, not only on a crash
    sc.exe failureflag $serviceName 1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to set the recovery flag (sc.exe exited with $LASTEXITCODE)" }

    Write-Host "Starting the $serviceName Windows service"
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
  }
  catch {
    throw ("Failed to set up the $serviceName Windows service: $_`n" +
      "Run Uninstall-CircleCIRunner-Unified.ps1 to clean up before trying again. If the service did not " +
      "start, check that this runner release can run as a Windows service.")
  }
  Write-Host "CircleCI Runner Agent is running as the $serviceName Windows service"
  Write-Host ""
}

if ($Autologon) {
  Write-Host "Setting this machine to sign in as $Username at startup and start the runner at that sign-in"
  try {
    $agentPath = "$installDirPath\$agentFile.exe"
    if (-not (Test-Path -LiteralPath $agentPath)) { throw "$agentPath was not found" }

    # The password is set before autologon is turned on, so there is never autologon without one. It is
    # kept as an LSA secret, so any plain text DefaultPassword value, and a count that would end autologon
    # after a few sign-ins, are removed.
    Set-LsaSecret "DefaultPassword" $passwd
    Remove-ItemProperty -Path $winlogon -Name DefaultPassword, AutoLogonCount -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $winlogon -Name DefaultUserName -Value $Username -Type String
    Set-ItemProperty -Path $winlogon -Name DefaultDomainName -Value $env:COMPUTERNAME -Type String
    Set-ItemProperty -Path $winlogon -Name AutoAdminLogon -Value "1" -Type String

    # Start the runner whenever the user signs in. The run level is Highest so the session has the user's
    # full administrator token, which an ordinary sign-in does not give. The task has no time limit, is not
    # stopped on battery, and runs at normal priority (4 to 6 are normal, the default of 7 is below normal).
    #
    # The task also repeats every minute and ignores a new start while the runner is up, so a runner that
    # exits for any reason is started again within a minute. Task Scheduler's own restart on failure does
    # not do that: it does not restart a runner that was killed, and leaves the task ready with an exit
    # code of -1. It stays on for a task that fails to start. The repetition lasts ten years from each
    # sign-in, which is endless in practice, and does not stop a runner that is running at the end of it.
    $account = "$env:COMPUTERNAME\$Username"
    $action = New-ScheduledTaskAction -Execute $agentPath -Argument "machine --config `"$configPath`"" `
      -WorkingDirectory $installDirPath
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $account
    $repeat = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) `
      -RepetitionDuration (New-TimeSpan -Days 3650)
    $trigger.Repetition = $repeat.Repetition
    $trigger.Repetition.StopAtDurationEnd = $false
    $principal = New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
      -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
      -MultipleInstances IgnoreNew -Priority 4
    [void](Register-ScheduledTask -TaskName $logonTaskName -Action $action -Trigger $trigger `
      -Principal $principal -Settings $settings -Force)

    # Keep the session available for UI tests: the display and the machine never turn off or sleep, and
    # there is no screensaver or lock screen. A zero timeout means never. The policy keys are created
    # only if they are missing, because New-Item -Force on a key that exists is not safe for its values.
    foreach ($setting in "monitor-timeout-ac", "monitor-timeout-dc", "standby-timeout-ac", "standby-timeout-dc") {
      powercfg.exe /change $setting 0
      if ($LASTEXITCODE -ne 0) { throw "Failed to set $setting (powercfg.exe exited with $LASTEXITCODE)" }
    }
    $desktopPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
    if (-not (Test-Path -LiteralPath $desktopPolicy)) { [void](New-Item -Path $desktopPolicy -Force) }
    Set-ItemProperty -Path $desktopPolicy -Name ScreenSaveActive -Value "0" -Type String
    Set-ItemProperty -Path $desktopPolicy -Name ScreenSaverIsSecure -Value "0" -Type String
    $personalizationPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    if (-not (Test-Path -LiteralPath $personalizationPolicy)) { [void](New-Item -Path $personalizationPolicy -Force) }
    Set-ItemProperty -Path $personalizationPolicy -Name NoLockScreen -Value 1 -Type DWord
  }
  catch {
    throw ("Failed to set up autologon: $_`n" +
      "Run Uninstall-CircleCIRunner-Unified.ps1 to clean up before trying again.")
  }
  Write-Host "This machine is set to sign in as $Username at startup, and the runner starts at that sign-in."
  Write-Host "Restart this machine to start the runner."
  Write-Host ""
}
