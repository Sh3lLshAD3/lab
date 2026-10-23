$ErrorActionPreference = 'Stop'
try {
  if (!(Get-Command wsl.exe -ErrorAction SilentlyContinue)) { throw 'WSL is unavailable. Enable Windows Subsystem for Linux in Windows Features and restart.' }
  $Distros = (& wsl.exe --list --quiet 2>$null) -replace "`0", ''
  if (!($Distros -match '^Ubuntu$')) {
    Write-Output '[RUNNING] Installing WSL and Ubuntu. Windows may request administrator access.'
    & wsl.exe --install -d Ubuntu --no-launch
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3010) { throw 'WSL bootstrap failed. Review the Windows error above; administrator access or enabled virtualization may be required.' }
    Write-Output '[ACTION REQUIRED] Restart Windows if requested. Open Ubuntu once and create its Linux username and password. Then reopen the lab and choose WSL Setup again.'
    exit 10
  }
  $Script = Join-Path $PSScriptRoot 'install-linux.sh'
  $LinuxScript = (& wsl.exe -d Ubuntu -- wslpath -a $Script).Trim()
  if ($LASTEXITCODE -ne 0) { throw 'Open Ubuntu once and complete first-run username/password setup, then retry.' }
  Write-Output '[RUNNING] Ubuntu tool setup'
  $Tools = Join-Path (Split-Path $PSScriptRoot -Parent) 'data'
  New-Item -ItemType Directory -Force $Tools | Out-Null
  $PidPath = (& wsl.exe -d Ubuntu -- wslpath -a (Join-Path $Tools 'wsl-setup.pid')).Trim()
  & wsl.exe -d Ubuntu -u root -- env "LAB_SELECTED_TOOLS=$env:LAB_SELECTED_TOOLS" "LAB_UPDATE_TOOLS=$env:LAB_UPDATE_TOOLS" setsid bash -c 'echo $$ > "$1"; exec bash "$2"' 'lab-setup' $PidPath $LinuxScript
  if ($LASTEXITCODE -ne 0) { throw 'Ubuntu tool setup failed. Read the preceding logs.' }
  Write-Output '[COMPLETE] WSL tool installation finished'
} catch { Write-Output "[FAILED] $_"; exit 1 }
