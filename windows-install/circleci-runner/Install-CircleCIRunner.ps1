param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Service", "Autologon", "RDP")]
    [string]$RunMode = ""
)

function Random-Password($length, $minNonAlpha) {
  $alpha = [char]65..[char]90 + [char]97..[char]122
  $numeric  =  [char]48..[char]57
  # :;<=>?@!#$%&()*+,-./[\]^_`
  $symbols = [char]58..[char]64 + @([char]33) + [char]35..[char]38 + [char]40..[char]47 + [char]91..[char]96

  $nonAlpha = $numeric + $symbols
  $charSet = $alpha + $nonAlpha

  $pwdList = @()
  For ($i = 0; $i -lt $minNonAlpha; $i++) {
    $pwdList += $nonAlpha | Get-Random
  }
  For ($i = 0; $i -lt ($length - $minNonAlpha); $i++) {
    $pwdList += $charSet | Get-Random
  }

  $pwdList = $pwdList | Sort-Object { Get-Random }

  # a bug on Server 2016 joins as stringified integers unles we cast to [char[]]
  ([char[]] $pwdList) -join ""
}

$ErrorActionPreference = "Stop"

$platform = "windows/amd64"
$installDirPath = "$env:ProgramFiles\CircleCI"

if ($RunMode -eq "") {
    Write-Host ""
    Write-Host "Select runner mode:"
    Write-Host ""
    Write-Host "  1) Service"
    Write-Host "     Runs as a Windows service in Session 0 (background)"
    Write-Host "     Best for CLI tools, Docker, headless builds"
    Write-Host "     No UI access - cannot run GUI applications or UI tests"
    Write-Host ""
    Write-Host "  2) Autologon"
    Write-Host "     Auto-login on boot with full interactive desktop session"
    Write-Host "     Best for UI automation, Selenium, GUI testing on Windows Desktop"
    Write-Host "     Warning: Password stored in registry (readable by administrators)"
    Write-Host ""
    Write-Host "  3) RDP (classic mode)"
    Write-Host "     Maintains RDP session to localhost for UI access"
    Write-Host "     Best for Windows Server with multi-session support"
    Write-Host "     Does not work on Windows Desktop due to single-session limitation"
    Write-Host ""

    do {
        $choice = Read-Host "Enter choice (1-3)"
        switch ($choice) {
            "1" { $RunMode = "Service" }
            "2" { $RunMode = "Autologon" }
            "3" { $RunMode = "RDP" }
            default { Write-Host "Invalid choice. Please enter 1, 2, or 3." }
        }
    } while ($RunMode -eq "")
    Write-Host ""
}

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

# Download CircleCI runner agent binary
$manifestDist = "https://circleci-binary-releases.s3.amazonaws.com/circleci-runner/manifest.json"
Write-Host "Determining current version of CircleCI Runner Agent"
$windowsManifest = (Invoke-RestMethod -Uri "$manifestDist").releases.current.windows.amd64
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

# NT credentials to use
Write-Host "Generating a random password"
$username = "circleci"
$passwd = Random-Password 42 10
$passwdSecure = $(ConvertTo-SecureString -String $passwd -AsPlainText -Force)
$cred = New-Object System.Management.Automation.PSCredential ($username, $passwdSecure)

# Create a user with the generated password
Write-Host "Creating a new administrator user to run CircleCI tasks"
$user = New-LocalUser $username -Password $passwdSecure -PasswordNeverExpires

# Make the user an administrator
Add-LocalGroupMember Administrators $user

if ($RunMode -eq "RDP") {
    # Save the credential to Credential Manager for sans-prompt MSTSC
    # First for the current user, and later for the runner user
    Write-Host "Saving the password to Credential Manager"
    Start-Process cmdkey.exe -ArgumentList ("/add:TERMSRV/localhost", "/user:$username", "/pass:$passwd")
    Start-Process cmdkey.exe -ArgumentList ("/add:TERMSRV/localhost", "/user:$username", "/pass:$passwd") -Credential $cred

    Write-Host "Configuring Remote Desktop Client"

    [void](reg.exe ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "/v" "AllowSavedCredentialsWhenNTLMOnly" /t REG_DWORD /d 0x1 /f)
    [void](reg.exe ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "/v" "ConcatenateDefaults_AllowSavedNTLMOnly" /t REG_DWORD /d 0x1 /f)
    [void](reg.exe ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly" /v "1" /t REG_SZ /d "TERMSRV/localhost" /f)
    gpupdate.exe /force

    # Configure MSTSC to suppress interactive prompts on RDP connection to localhost
    Start-Process reg.exe -ArgumentList ("ADD", '"HKCU\Software\Microsoft\Terminal Server Client"', "/v", "AuthenticationLevelOverride", "/t", "REG_DWORD", "/d", "0x0", "/f") -Credential $cred

    # Stop starting Server Manager at logon
    Start-Process reg.exe -ArgumentList ("ADD", '"HKCU\Software\Microsoft\ServerManager"', "/v", "DoNotOpenServerManagerAtLogon", "/t", "REG_DWORD", "/d", "0x1", "/f") -Credential $cred
}
elseif ($RunMode -eq "Autologon") {
    Write-Host "Configuring automatic logon"
    [void](reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoAdminLogon" /t REG_SZ /d "1" /f)
    [void](reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DefaultUserName" /t REG_SZ /d "$username" /f)
    [void](reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DefaultPassword" /t REG_SZ /d "$passwd" /f)
}

if ($RunMode -eq "Service") {
    Write-Host "Configuring CircleCI Runner Agent as Windows service"

    # Create service wrapper script
    $serviceWrapperPath = "$installDirPath\run-service.ps1"
    @"
`$ErrorActionPreference = "Continue"
Set-Location "$installDirPath"

while (`$true) {
    try {
        & "$installDirPath\$agentFile" machine --config "$installDirPath\runner-agent-config.yaml"
    } catch {
        Write-Host "Runner exited: `$_"
    }
    Start-Sleep -Seconds 5
}
"@ | Out-File $serviceWrapperPath -Encoding ascii

    $serviceName = "CircleCIRunner"
    $binaryPath = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File `"$serviceWrapperPath`""

    sc.exe create $serviceName binPath= $binaryPath start= auto DisplayName= "CircleCI Runner Agent"
    sc.exe description $serviceName "CircleCI self-hosted runner agent"
    sc.exe config $serviceName obj= ".\$username" password= $passwd
}
else {
    # Configure scheduled tasks to run launch-agent
    Write-Host "Registering CircleCI Runner Agent tasks to Task Scheduler"
    $commonTaskSettings = New-ScheduledTaskSettingsSet -Compatibility Vista -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan)

    # RDP mode uses single-task with logoff, others use continuous mode without logoff
    if ($RunMode -eq "RDP") {
        [void](Register-ScheduledTask -Force -TaskName "CircleCI Runner Agent" -User $username -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument "-Command `"& `"`"$installDirPath\$agentFile`"`"`"`" machine --config `"`"$installDirPath\runner-agent-config.yaml`"`"`"; & logoff.exe (Get-Process -Id `$PID).SessionID`"") -Settings $commonTaskSettings -Trigger (New-ScheduledTaskTrigger -AtLogon -User $username) -RunLevel Highest)

        $keeperTask = Register-ScheduledTask -Force -TaskName "CircleCI Runner Agent session keeper" -User $username -Password $passwd -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument "-Command `"while (`$true) { if ((query session $username).Length -eq 0) { mstsc.exe /v:localhost; Start-Sleep 5 } Start-Sleep 1 }`"") -Settings $commonTaskSettings -Trigger (New-ScheduledTaskTrigger -AtStartup)
    }
    else {
        # Autologon mode - continuous runner, no logoff
        [void](Register-ScheduledTask -Force -TaskName "CircleCI Runner Agent" -User $username -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument "-Command `"& `"`"$installDirPath\$agentFile`"`"`"`" machine --config `"`"$installDirPath\runner-agent-config.yaml`"`"`"`"") -Settings $commonTaskSettings -Trigger (New-ScheduledTaskTrigger -AtLogon -User $username) -RunLevel Highest)
    }
}

# Preparing config template
Write-Host "Preparing a config template for CircleCI Runner Agent"

# Set mode based on runner mode (RDP uses single-task, others use continuous)
$runnerMode = if ($RunMode -eq "RDP") { "single-task" } else { "continuous" }

@"
api:
  auth_token: "" # FIXME: Specify your runner token
  # On server, set url to the hostname of your server installation. For example,
  # url: https://circleci.example.com
runner:
  name: "" # FIXME: Specify the name of this runner instance
  mode: $runnerMode
  task_agent_directory: $installDirPath\Agents
  working_directory: $installDirPath\Workdir
  cleanup_working_directory: true
logging:
  file: $installDirPath\circleci-runner.log
"@ -replace "([^`r])`n", "`$1`r`n" | Out-File runner-agent-config.yaml -Encoding ascii

# Open runner-agent-config.yaml for edit
Write-Host "Opening the config file for CircleCI Runner Agent in Notepad"
Write-Host ""
Write-Host "Please edit the file accordingly and close Notepad"
(Start-Process notepad.exe -ArgumentList ("`"$installDirPath\runner-agent-config.yaml`"") -PassThru).WaitForExit()
Write-Host ""

Write-Host "Starting CircleCI Runner Agent"
Pop-Location

if ($RunMode -eq "Service") {
    Start-Service CircleCIRunner
    Write-Host ""
    Write-Host "CircleCI Runner Agent installed and started as a service"
    Write-Host "Note: Service runs in Session 0 with no UI access"
}
elseif ($RunMode -eq "RDP") {
    Start-ScheduledTask -InputObject $keeperTask
    Write-Host ""
    Write-Host "CircleCI Runner Agent installed with RDP session keeper"
}
else {
    Write-Host ""
    Write-Host "CircleCI Runner Agent installed with autologon"
    Write-Host "The runner will start automatically when the system boots"
    Write-Host "Restart the system to activate"
}
Write-Host ""
