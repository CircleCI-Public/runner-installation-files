#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs CircleCI Runner and its dependencies on Windows (Desktop or Server, AMD64 or ARM64).

.DESCRIPTION
  Installs Git and Gzip, downloads the runner binary for this machine's architecture, creates the
  local user that runs CircleCI tasks, and writes a runner config that only Administrators and that
  user can read. It does not set the runner up to start; that is added per run mode.

.PARAMETER RunnerToken
  The runner authentication token.

.PARAMETER RunnerName
  The name of this runner instance.

.PARAMETER ApiUrl
  The runner API URL. Set this to the hostname of your server installation, for example
  https://circleci.example.com. Leave it unset to use CircleCI cloud.

.PARAMETER Username
  The local user that runs CircleCI tasks. Pass the same value to the uninstall script.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RunnerToken,
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RunnerName,
  [string]$ApiUrl,
  [ValidateNotNullOrEmpty()][string]$Username = "circleci"
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

$ErrorActionPreference = "Stop"

# The runner rejects any other characters in its name
if ($RunnerName -notmatch '^[A-Za-z0-9.()_ -]+$') {
  throw "RunnerName must contain only letters, numbers, .()_-, and spaces"
}

$arch = Get-NativeArchitecture
$installDirPath = "$env:ProgramFiles\CircleCI"
# The uninstall script only removes the user if it finds this description, so keep the two in sync
$userDescription = "Created by the CircleCI Runner installer"

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
