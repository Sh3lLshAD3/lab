$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path $PSScriptRoot -Parent
$ToolsRoot = Join-Path $env:ProgramData 'PentestLab\Tools'
$Admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$Admin) { Write-Output '[ACTION REQUIRED] Open the launcher terminal as Administrator for system-wide tool installation. Normal scans can run without elevation.'; exit 10 }
New-Item -ItemType Directory -Force (Join-Path $ToolsRoot 'bin') | Out-Null
function Refresh-Path {
  $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
}
function Install-Package($Command, $Id) {
  Refresh-Path
  if (!(Get-Command $Command -ErrorAction SilentlyContinue)) {
    Write-Output "[RUNNING] $Id"
    if (!(Get-Command winget -ErrorAction SilentlyContinue)) { throw 'Install Microsoft App Installer (winget), then rerun Setup.' }
    & winget install --id $Id --exact --accept-source-agreements --accept-package-agreements --disable-interactivity
    if ($LASTEXITCODE -ne 0) { throw "winget failed for $Id. Installer may require elevation or a restart." }
    Refresh-Path
    if (!(Get-Command $Command -ErrorAction SilentlyContinue)) { throw "Restart the lab app so the new $Command installation is visible, then rerun Setup." }
  }
  Write-Output "[DONE] $Id"
}
try {
  Install-Package 'git' 'Git.Git'
  $Selected = @()
  if ($env:LAB_SELECTED_TOOLS) { $Selected = $env:LAB_SELECTED_TOOLS.Split(',') } else { $Selected = @('subfinder','httpx','waybackurls','dalfox','ffuf','arjun','sqlmap','nuclei','nikto','katana','dnsrecon','nmap','dnsx','naabu','photon','theHarvester') }
  $GoTools = @('subfinder','httpx','waybackurls','dalfox','ffuf','nuclei','katana','dnsx','naabu')
  if (@($Selected | Where-Object { $GoTools -contains $_ }).Count -gt 0) { Install-Package 'go' 'GoLang.Go' }
  if ($Selected -contains 'nikto' -or $Selected.Count -eq 0) { Install-Package 'perl' 'StrawberryPerl.StrawberryPerl' }
  & $env:LAB_PYTHON -u (Join-Path $PSScriptRoot 'install_tools.py')
  if ($LASTEXITCODE -ne 0) { throw 'Some selected tools failed verification. Inspect the inventory and log.' }
  Write-Output '[COMPLETE] Selected tool installation finished' 
} catch {
  Write-Output "[FAILED] $_"
  exit 1
}
