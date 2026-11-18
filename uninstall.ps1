# ARASAKA HOLO // desinstalador Windows
# powershell -ExecutionPolicy Bypass -File uninstall.ps1
$App  = 'arasaka-holo'
$Data = Join-Path $env:LOCALAPPDATA $App
$Bin  = Join-Path $Data 'bin'
foreach ($l in @((Join-Path ([Environment]::GetFolderPath('Programs')) 'Arasaka Holo.lnk'),
                 (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Arasaka Holo.lnk'))) {
    if (Test-Path $l) { Remove-Item -Force $l }
}
$up = [Environment]::GetEnvironmentVariable('Path', 'User')
[Environment]::SetEnvironmentVariable('Path', (($up -split ';' | Where-Object { $_ -and $_ -ne $Bin }) -join ';'), 'User')
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $Data
Write-Host " ■ ARASAKA HOLO REMOVIDO (sua chave em %APPDATA%\arasaka-holo foi mantida: sem ela voce perde o nick)" -ForegroundColor Red
