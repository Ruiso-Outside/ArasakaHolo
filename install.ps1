# ============================================================
#   ARASAKA HOLO // instalador Windows
#   Uso: clique duas vezes em install.bat
#        (ou: powershell -ExecutionPolicy Bypass -File install.ps1)
# ============================================================
$ErrorActionPreference = 'Stop'
$App  = 'arasaka-holo'
$Dir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Data = Join-Path $env:LOCALAPPDATA $App
$Bin  = Join-Path $Data 'bin'
$script:n = 1
function Step($t) { Write-Host ""; Write-Host "[$script:n] $t" -ForegroundColor Red; $script:n++ }
function Ok($t)   { Write-Host "     ■ $t" -ForegroundColor Gray }

Write-Host ""
Write-Host "   A R A S A K A   H O L O" -ForegroundColor Red
Write-Host "   Chat com privacidade maxima" -ForegroundColor DarkGray
if (-not (Test-Path (Join-Path $Dir 'arasaka_holo\app.py'))) { throw "Arquivos do app nao encontrados em $Dir" }

Step "Python"
$py = $null
foreach ($c in @('py', 'python', 'python3')) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike '*WindowsApps*') { $py = $cmd.Source; break }
}
if (-not $py) {
    winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    $py = (Get-Command py -ErrorAction SilentlyContinue).Source
    if (-not $py) { throw "Instale o Python 3.9+ (python.org) e rode de novo." }
}
Ok ("Python " + (& $py -c "import sys; print('%d.%d' % sys.version_info[:2])"))

Step "Ambiente Python (Qt + libsodium + websockets)"
New-Item -ItemType Directory -Force -Path $Data, $Bin | Out-Null
$vpy = Join-Path $Data 'venv\Scripts\python.exe'
if (-not (Test-Path $vpy)) { & $py -m venv (Join-Path $Data 'venv') }
& $vpy -m pip install -q --upgrade pip 2>$null | Out-Null
& $vpy -m pip install -q --upgrade "PySide6-Essentials>=6.5" "pynacl>=1.5" "websockets>=14"
if ($LASTEXITCODE -ne 0) { throw "falha ao instalar as dependencias" }
Ok "dependencias instaladas"
# call e compartilhamento de tela: opcionais (o chat funciona sem elas)
$ErrorActionPreference = 'Continue'
& $vpy -m pip install -q --upgrade "aiortc>=1.10" "sounddevice>=0.4.6" "mss>=10" "numpy>=1.26"
if ($LASTEXITCODE -eq 0) { Ok "call e compartilhamento de tela" }
else { Write-Host "     !! calls desligadas: precisam do Python 3.10 ou mais novo (o chat funciona normal)" -ForegroundColor Yellow }
$ErrorActionPreference = 'Stop'

Step "Arquivos do app"
$appDir = Join-Path $Data 'app'
if (Test-Path $appDir) { Remove-Item -Recurse -Force $appDir }
New-Item -ItemType Directory -Force -Path $appDir | Out-Null
Copy-Item -Recurse (Join-Path $Dir 'arasaka_holo') $appDir
Get-ChildItem -Recurse -Directory -Filter '__pycache__' $appDir | Remove-Item -Recurse -Force
$pyw = Join-Path $Data 'venv\Scripts\pythonw.exe'
$launch = Join-Path $Data 'launch.pyw'
Set-Content -Encoding UTF8 -Path $launch -Value @"
import sys
sys.path.insert(0, r"$appDir")
from arasaka_holo.__main__ import main
sys.exit(main())
"@
Set-Content -Encoding ASCII -Path (Join-Path $Bin "$App.cmd") -Value "@echo off`r`nstart `"`" `"$pyw`" `"$launch`" %*"
Set-Content -Encoding ASCII -Path (Join-Path $Bin "$App-server.cmd") -Value "@echo off`r`nset `"PYTHONPATH=$appDir`"`r`n`"$vpy`" -m arasaka_holo.server %*"
$ico = Join-Path $Data "$App.ico"
& $vpy -c "import sys; from PySide6.QtGui import QGuiApplication, QIcon; a=QGuiApplication(sys.argv); QIcon(sys.argv[1]).pixmap(256,256).save(sys.argv[2])" (Join-Path $appDir 'arasaka_holo\assets\arasaka-holo.svg') $ico 2>$null

$up = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not ($up -split ';' | Where-Object { $_ -eq $Bin })) {
    [Environment]::SetEnvironmentVariable('Path', ($up.TrimEnd(';') + ';' + $Bin), 'User')
    Ok "comandos 'arasaka-holo' e 'arasaka-holo-server' no PATH (abra um novo terminal)"
}
$ws = New-Object -ComObject WScript.Shell
foreach ($lnk in @((Join-Path ([Environment]::GetFolderPath('Programs')) 'Arasaka Holo.lnk'),
                   (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Arasaka Holo.lnk'))) {
    $s = $ws.CreateShortcut($lnk)
    $s.TargetPath = $pyw
    $s.Arguments = "`"$launch`""
    $s.WorkingDirectory = $env:USERPROFILE
    if (Test-Path $ico) { $s.IconLocation = $ico }
    $s.Description = 'Arasaka Holo - chat privado'
    $s.Save()
}
Ok "atalhos no Menu Iniciar e na Area de Trabalho"
Write-Host ""
Write-Host " ■ INSTALACAO CONCLUIDA" -ForegroundColor Red
Write-Host "   Seu nick eterno:" -NoNewline
& $vpy -c "import sys; sys.path.insert(0, r'$appDir'); from arasaka_holo.identity import load_identity; i=load_identity(); print(' ' + i.nick)"
Write-Host ""
