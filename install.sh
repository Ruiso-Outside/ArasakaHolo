#!/usr/bin/env bash
# ============================================================
#   ARASAKA HOLO // instalador Linux (Zorin / Ubuntu / Debian)
#
#   Uso:  ./install.sh [opcoes]        (NAO rode com sudo)
#     --servidor    tambem instala o servidor como servico (systemd --user, porta 7077)
#     --so-servidor instala apenas o servidor (para VPS, sem interface)
#     -y            nao pede confirmacao
# ============================================================
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ID=arasaka-holo
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/$APP_ID"
BIN="$HOME/.local/bin"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"
SERVER=0 GUI=1 YES=0
for a in "$@"; do
  case "$a" in
    --servidor) SERVER=1 ;;
    --so-servidor) SERVER=1; GUI=0 ;;
    -y|--yes) YES=1 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "Opcao desconhecida: $a"; exit 1 ;;
  esac
done
R=$'\e[38;2;227;18;31m'; RH=$'\e[38;2;255;59;71m'; W=$'\e[38;2;236;236;240m'; G=$'\e[38;2;120;120;130m'
B=$'\e[1m'; N=$'\e[0m'
STEP=0
step() { STEP=$((STEP + 1)); printf '\n%s%s[%02d]%s %s%s%s\n' "$R" "$B" "$STEP" "$N" "$W$B" "$*" "$N"; }
ok()   { printf '     %s■%s %s\n' "$R" "$N" "$*"; }
warn() { printf '     %s!! %s%s\n' "$RH" "$*" "$N"; }
die()  { printf '\n%s!! %s%s\n' "$RH" "$*" "$N"; exit 1; }

printf '\n%s%s   A R A S A K A   H O L O%s\n   %sChat com privacidade maxima%s\n' "$R" "$B" "$N" "$G" "$N"
[ "$EUID" -eq 0 ] && die "Rode como seu usuario normal (sem sudo): ./install.sh"
[ -f "$DIR/arasaka_holo/server.py" ] || die "Arquivos do app nao encontrados em $DIR"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "Precisa de Python 3.9+"
if [ "$YES" -eq 0 ]; then
  printf '\n   Vai instalar:'
  [ "$GUI" -eq 1 ] && printf ' o chat (Python + Qt)'
  [ "$SERVER" -eq 1 ] && printf ' + o servidor como servico'
  printf '.\n   %sContinuar? [s/N] %s' "$W" "$N"
  read -r r
  case "$r" in s|S|y|Y|sim|SIM) ;; *) echo "Cancelado."; exit 0 ;; esac
fi

step "Pacotes do sistema"
PKGS=(python3-venv python3-pip)
[ "$GUI" -eq 1 ] && PKGS+=(libxcb-cursor0 libxkbcommon-x11-0 libxcb-icccm4 libxcb-keysyms1 libxcb-image0
                           libxcb-render-util0 libxcb-xinerama0 libxcb-shape0 libegl1 libportaudio2)
MISSING=()
for p in "${PKGS[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || MISSING+=("$p"); done
if [ ${#MISSING[@]} -gt 0 ]; then
  sudo -v || die "sudo necessario"
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${MISSING[@]}" || warn "alguns pacotes falharam"
fi
ok "pronto"

step "Ambiente Python"
mkdir -p "$DATA" "$BIN"
[ -x "$DATA/venv/bin/python" ] || python3 -m venv "$DATA/venv" || die "falha ao criar o venv"
"$DATA/venv/bin/python" -m pip install -q --upgrade pip >/dev/null 2>&1
DEPS=("pynacl>=1.5" "websockets>=14" certifi)
[ "$GUI" -eq 1 ] && DEPS+=("PySide6-Essentials>=6.5")
"$DATA/venv/bin/python" -m pip install -q --upgrade "${DEPS[@]}" || die "falha ao instalar dependencias"
ok "libsodium (PyNaCl), websockets$( [ "$GUI" -eq 1 ] && echo ', PySide6')"

if [ "$GUI" -eq 1 ]; then   # opcionais: o chat funciona sem elas
  if "$DATA/venv/bin/python" -m pip install -q --upgrade "aiortc>=1.10" "sounddevice>=0.4.6" "mss>=10" "numpy>=1.26"; then
    ok "call e compartilhamento de tela"
  else
    warn "calls desligadas: precisam do Python 3.10 ou mais novo (o chat funciona normal)"
  fi
fi

step "Arquivos"
rm -rf "$DATA/app"
mkdir -p "$DATA/app"
cp -r "$DIR/arasaka_holo" "$DATA/app/"
find "$DATA/app" -name '__pycache__' -prune -exec rm -rf {} +
cat > "$BIN/$APP_ID-server" <<EOF
#!/bin/sh
export PYTHONPATH="$DATA/app"
exec "$DATA/venv/bin/python" -m arasaka_holo.server "\$@"
EOF
chmod +x "$BIN/$APP_ID-server"
ok "servidor: $BIN/$APP_ID-server"
if [ "$GUI" -eq 1 ]; then
  cat > "$BIN/$APP_ID" <<EOF
#!/bin/sh
export PYTHONPATH="$DATA/app"
exec "$DATA/venv/bin/python" -m arasaka_holo "\$@"
EOF
  chmod +x "$BIN/$APP_ID"
  mkdir -p "$APPS" "$ICONS"
  cp "$DIR/arasaka_holo/assets/arasaka-holo.svg" "$ICONS/$APP_ID.svg"
  # Tema de ícones Arasaka (ArasakaZorin): ele tem um ícone "arasaka", e a Área de Trabalho do Zorin (que busca
  # pelo prefixo do nome) mostraria esse logo no lugar deste. Uma camada do tema na pasta pessoal resolve, sem senha.
  for th in /usr/share/icons/Arasaka "$HOME/.icons/Arasaka"; do
    if [ -f "$th/index.theme" ]; then
      UT="${XDG_DATA_HOME:-$HOME/.local/share}/icons/Arasaka"
      mkdir -p "$UT/scalable/apps"
      [ -f "$UT/index.theme" ] || cp "$th/index.theme" "$UT/index.theme"
      cp "$DIR/arasaka_holo/assets/arasaka-holo.svg" "$UT/scalable/apps/$APP_ID.svg"
      break
    fi
  done
  cat > "$APPS/$APP_ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Arasaka Holo
GenericName=Chat Privado
Comment=Chat cifrado ponta a ponta, sem conta e sem login
Exec="$BIN/$APP_ID"
Icon=$APP_ID
Terminal=false
Categories=Network;Chat;InstantMessaging;
Keywords=chat;privacy;encrypted;e2e;arasaka;holo;
StartupWMClass=arasaka-holo
EOF
  update-desktop-database -q "$APPS" 2>/dev/null
  ok "atalho no menu: Arasaka Holo"
fi

if [ "$SERVER" -eq 1 ]; then
  step "Servidor como servico (systemd --user)"
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/$APP_ID-server.service" <<EOF
[Unit]
Description=ARASAKA HOLO relay cego (sem logs)
After=network-online.target

[Service]
ExecStart=$BIN/$APP_ID-server --host 0.0.0.0 --port 7077
Restart=on-failure
# sem registro de saida: nada de logs
StandardOutput=null
StandardError=null

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload && systemctl --user enable --now "$APP_ID-server.service" \
    && ok "servico ativo na porta 7077" || warn "nao consegui ativar o servico"
  loginctl enable-linger "$USER" 2>/dev/null && ok "o servidor continua rodando mesmo deslogado"
  command -v ufw >/dev/null && sudo ufw status 2>/dev/null | grep -q active && \
    sudo ufw allow 7077/tcp >/dev/null && ok "firewall: porta 7077 liberada"
fi

printf '\n%s%s ■ INSTALACAO CONCLUIDA%s\n' "$R" "$B" "$N"
if [ "$GUI" -eq 1 ]; then
  printf '   %sSeu nick eterno: %s' "$W" "$N"
  PYTHONPATH="$DATA/app" "$DATA/venv/bin/python" -m arasaka_holo --nick
fi
printf '\n'
