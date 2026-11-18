#!/usr/bin/env bash
# ARASAKA HOLO // desinstalador Linux
# A sua chave (~/.config/arasaka-holo/identity.key) e mantida: sem ela voce perde o nick.
APP_ID=arasaka-holo
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/$APP_ID"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
if systemctl --user list-unit-files "$APP_ID-server.service" >/dev/null 2>&1; then
  systemctl --user disable --now "$APP_ID-server.service" 2>/dev/null
  rm -f "$HOME/.config/systemd/user/$APP_ID-server.service"
fi
rm -f "$HOME/.local/bin/$APP_ID" "$HOME/.local/bin/$APP_ID-server" "$APPS/$APP_ID.desktop" \
      "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps/$APP_ID.svg"
rm -rf "$DATA"
update-desktop-database -q "$APPS" 2>/dev/null
printf '\e[38;2;227;18;31m ■ ARASAKA HOLO REMOVIDO\e[0m (chave mantida em ~/.config/arasaka-holo)\n'
