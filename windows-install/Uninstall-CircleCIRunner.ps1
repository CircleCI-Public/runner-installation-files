$installDirPath = "$env:ProgramFiles\CircleCI"
$username = "circleci"

Write-Host "Unregister Scheduled Tasks"
Unregister-ScheduledTask -TaskName "CircleCI Launch Agent session keeper" -Confirm:$false
Unregister-ScheduledTask -TaskName "CircleCI Launch Agent"  -Confirm:$false

Write-Host "Delete credential from Credential Manager"
cmdkey.exe /delete:TERMSRV/localhost

Write-Host "Log off user"
$session = (((query user $username) -split "\n")[1] -split '\s+')[3]
if ($session) { logoff.exe $session }
else { Write-Host "$username user NOT FOUND" }

Write-Host "Remove user $username"
Remove-LocalUser -Name $username

Write-Host "Delete installDir: $installDirPath"
Remove-Item -LiteralPath $installDirPath -Force -Recurse
