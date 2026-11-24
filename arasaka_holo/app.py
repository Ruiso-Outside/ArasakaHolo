"""
ARASAKA HOLO // chat (interface PySide6).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import socket
import sys
import threading
import time
import traceback
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QObject, QRectF, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QKeySequence, QPainter, QPen, QShortcut
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout, QFrame,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
                               QMessageBox, QPlainTextEdit, QScrollArea, QSizePolicy, QStackedWidget, QVBoxLayout,
                               QWidget, QInputDialog)

from . import calls, crypto, diag, identity
from . import fx
from .callui import CallManager, clean_ice
from .kit import (FONTS, LINE, MUTED, RED, BaseDialog, CutFrame, HudHeader, Indicator, button, label, load_fonts,
                  logo_pixmap, spaced, stylesheet)
from .identity import valid_nick
from .net import HoloClient, normalize_url

APP_NAME = "ARASAKA HOLO"
VERSION = "1.3.0"
ASSETS = Path(__file__).resolve().parent / "assets"
DEFAULT_SERVER = "https://piphin.online/"  # rede oficial (relay por HTTP no piphin.online)
LOCAL_SERVER = "ws://127.0.0.1:7077"      # servidor rodando neste PC (CONFIG > INICIAR SERVIDOR)
TTLS = [("sem autodestruicao", 0), ("autodestruir: 30 s", 30), ("autodestruir: 5 min", 300),
        ("autodestruir: 1 h", 3600)]
NICK_COLORS = ["#ff2e40", "#ececf0", "#ff9e64", "#ff6b9c", "#ffb86b", "#8fc1c4", "#c879ff", "#9fd8b0"]

EXTRA_QSS = """
QFrame#side { background: #030304; border-right: 1px solid #1a0507; }
QFrame#members { background: #050506; border-left: 1px solid #16161a; }
QListWidget#chans { background: transparent; border: none; }
QListWidget#chans::item { padding: 8px 10px; border-left: 3px solid transparent; color: #8c8c96; }
QListWidget#chans::item:selected { background: rgba(227,18,31,0.18); border-left: 3px solid #e3121f; color: #ffffff; }
QListWidget#chans::item:hover { background: rgba(227,18,31,0.08); color: #ffffff; }
QPlainTextEdit#composer { background: #050506; border: 1px solid #2a2a31; padding: 8px; }
QPlainTextEdit#composer:focus { border-color: #e3121f; }
QFrame#msg_me { background: #160609; border-left: 3px solid #e3121f; }
QFrame#msg_other { background: #0d0d10; border-left: 3px solid #2a2a31; }
QFrame#msg_warn { background: #1d0a00; border-left: 3px solid #ffb347; }
QSlider::groove:horizontal { height: 4px; background: #2a2a31; }
QSlider::sub-page:horizontal { background: #e3121f; }
QSlider::handle:horizontal { width: 10px; margin: -6px 0; background: #ececf0; border: 1px solid #e3121f; }
QSlider::handle:horizontal:hover { background: #ff2436; }
QFrame#errbar { background: #1d0a00; border-bottom: 1px solid #ffb347; }
QFrame#callbar { background: #140407; border-bottom: 1px solid #5a080e; }
QFrame#topbar { background: #050506; border-bottom: 1px solid #1a0507; }
"""


def nick_color(nick: str) -> str:
    h = hashlib.blake2b(nick.encode(), digest_size=2).digest()
    return NICK_COLORS[h[0] % len(NICK_COLORS)]


def esc(t: str) -> str:
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def lan_ips() -> list[str]:
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    return sorted(i for i in ips if not i.startswith("127."))


def is_plain(url: str) -> bool:
    """Endereco sem TLS fora da propria rede: o servidor continua cego, mas a rede ve nicks e horarios."""
    if url.lower().startswith(("https://", "wss://")):
        return False
    try:
        host = urlsplit(url).hostname or ""
        return not ipaddress.ip_address(host).is_private
    except ValueError:
        return host not in ("localhost", "")


def strong_password() -> str:
    abc = "abcdefghjkmnpqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(abc) for _ in range(5)) for _ in range(4))


class Bridge(QObject):
    event = Signal(object)


class Task(QThread):
    done = Signal(object)

    def __init__(self, fn, *a):
        super().__init__()
        self.fn, self.a = fn, a

    def run(self):
        try:
            self.done.emit(self.fn(*self.a))
        except Exception as e:  # noqa: BLE001
            self.done.emit(e)


# ================================================================ estado local
class Store:
    """Configuracoes + chaves publicas fixadas (TOFU local). Nada de mensagens."""

    def __init__(self):
        self.dir = identity.config_dir()
        self.path = self.dir / "settings.json"
        self.data = {"server": DEFAULT_SERVER, "ttl": 0, "remember_rooms": False, "rooms": [], "pins": {},
                     "accept_calls": "known", "hide_ip": False, "mic": "", "speaker": "",
                     "volumes": {}, "vol_master": 100, "vol_mic": 100}
        try:
            self.data.update(json.loads(self.path.read_text(encoding="utf-8")))
        except Exception:
            pass
        if not isinstance(self.data.get("pins"), dict):
            self.data["pins"] = {}
        if self.data.get("server") == "wss://piphin.online/":   # padrao da 1.0.1: a rede oficial agora e por HTTP
            self.data["server"] = DEFAULT_SERVER

    def save(self):
        identity._write_private(self.path, json.dumps(self.data, indent=1))

    def pin(self, nick: str, pk: str) -> str:
        """'new' | 'ok' | 'changed'"""
        pins = self.data.setdefault("pins", {})
        old = pins.get(nick)
        if old is None:
            pins[nick] = pk
            self.save()
            return "new"
        return "ok" if old == pk else "changed"

    def repin(self, nick: str, pk: str):
        self.data["pins"][nick] = pk
        self.save()


# ================================================================ widgets
class IdentityCard(QWidget):
    def __init__(self, ident: identity.Identity):
        super().__init__()
        self.ident = ident
        self.setFixedHeight(150)
        self.logo = logo_pixmap(34)

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w = self.width()
        p.drawPixmap(18, 16, self.logo)
        f = QFont(FONTS["brand"])
        f.setPixelSize(20)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 4)
        p.setFont(f)
        p.setPen(QColor(236, 236, 240))
        p.drawText(QRectF(62, 14, w, 22), Qt.AlignLeft | Qt.AlignVCenter, "ARASAKA")
        f2 = QFont(FONTS["ui"])
        f2.setPixelSize(11)
        f2.setBold(True)
        f2.setLetterSpacing(QFont.AbsoluteSpacing, 3)
        p.setFont(f2)
        p.setPen(RED)
        p.drawText(QRectF(63, 36, w - 70, 16), Qt.AlignLeft | Qt.AlignVCenter, "HOLO // SECURE COMMS")
        p.fillRect(QRectF(14, 64, w - 28, 74), QColor(18, 5, 7))
        p.setPen(QPen(QColor(90, 8, 14), 1))
        p.drawRect(QRectF(14, 64, w - 28, 74))
        p.fillRect(QRectF(14, 64, 3, 74), RED)
        f3 = QFont(FONTS["ui"])
        f3.setPixelSize(10)
        f3.setBold(True)
        f3.setLetterSpacing(QFont.AbsoluteSpacing, 3)
        p.setFont(f3)
        p.setPen(MUTED)
        p.drawText(QRectF(26, 68, w, 16), Qt.AlignLeft | Qt.AlignVCenter, "SEU NICK ETERNO")
        f4 = QFont(FONTS["ui"])
        f4.setPixelSize(18)
        f4.setBold(True)
        f4.setLetterSpacing(QFont.AbsoluteSpacing, 1.5)
        p.setFont(f4)
        p.setPen(QColor(255, 255, 255))
        p.drawText(QRectF(26, 84, w - 40, 26), Qt.AlignLeft | Qt.AlignVCenter, self.ident.nick)
        f5 = QFont(FONTS["mono"])
        f5.setPixelSize(10)
        p.setFont(f5)
        p.setPen(QColor(140, 60, 66))
        p.drawText(QRectF(26, 110, w - 40, 22), Qt.AlignLeft | Qt.AlignVCenter, "CHAVE " + self.ident.fp)


class MessageWidget(QFrame):
    expired = Signal(object)

    def __init__(self, body: dict, mine: bool, status: str):
        super().__init__()
        self.setObjectName("msg_warn" if status == "changed" else "msg_me" if mine else "msg_other")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 8, 14, 10)
        lay.setSpacing(3)
        head = QHBoxLayout()
        head.setSpacing(8)
        n = QLabel(esc(body["n"]))
        n.setStyleSheet(f"color: {nick_color(body['n'])}; font-weight: 700;")
        spaced(n, 1)
        head.addWidget(n)
        badge = {"ok": ("✔ verificado", "#8c8c96"), "new": ("✔ chave fixada", "#8c8c96"),
                 "pending": ("… verificando", "#55555e"),
                 "changed": ("⚠ CHAVE DIFERENTE DA CONHECIDA", "#ffb347"),
                 "mismatch": ("⚠ ASSINATURA NAO CONFERE COM O NICK", "#ff2e40")}.get(status, ("", "#55555e"))
        self.badge = QLabel(badge[0])
        self.badge.setStyleSheet(f"color: {badge[1]}; font-size: 11px;")
        head.addWidget(self.badge)
        if not crypto.Replay.on_time(body):
            late = QLabel("⚠ hora fora do normal (relogio errado ou mensagem repetida)")
            late.setStyleSheet("color: #ffb347; font-size: 11px;")
            head.addWidget(late)
        head.addStretch()
        self.ttl_lbl = QLabel("")
        self.ttl_lbl.setStyleSheet("color: #ff6b7a; font-size: 11px;")
        head.addWidget(self.ttl_lbl)
        t = QLabel(time.strftime("%H:%M", time.localtime(body.get("ts", time.time()))))
        t.setStyleSheet("color: #55555e; font-size: 11px;")
        head.addWidget(t)
        lay.addLayout(head)
        txt = QLabel(esc(body["t"]).replace("\n", "<br>"))
        txt.setTextFormat(Qt.RichText)
        txt.setWordWrap(True)
        txt.setTextInteractionFlags(Qt.TextSelectableByMouse)
        txt.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        txt.setStyleSheet("color: #e6e6ea; font-size: 15px;")
        lay.addWidget(txt)
        self.deadline = 0.0
        ttl = int(body.get("ttl") or 0)
        if ttl > 0:
            self.deadline = time.time() + ttl
            self.timer = QTimer(self)
            self.timer.timeout.connect(self._tick)
            self.timer.start(1000)
            self._tick()

    def set_status(self, status: str):
        if status in ("ok", "new"):
            self.badge.setText("✔ verificado")
            self.badge.setStyleSheet("color: #8c8c96; font-size: 11px;")
        elif status == "changed":
            self.badge.setText("⚠ CHAVE DIFERENTE DA CONHECIDA")
            self.badge.setStyleSheet("color: #ffb347; font-size: 11px;")
        elif status == "mismatch":
            self.badge.setText("⚠ ASSINATURA NAO CONFERE COM O NICK")
            self.badge.setStyleSheet("color: #ff2e40; font-size: 11px;")

    def _tick(self):
        left = int(self.deadline - time.time())
        if left <= 0:
            self.timer.stop()
            self.expired.emit(self)
            return
        self.ttl_lbl.setText(f"⌛ {left // 60}:{left % 60:02d}" if left >= 60 else f"⌛ {left}s")


class ChatView(QScrollArea):
    MAX = 400

    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner = QWidget()
        inner.setObjectName("page")
        self.lay = QVBoxLayout(inner)
        self.lay.setContentsMargins(24, 16, 24, 16)
        self.lay.setSpacing(8)
        self.lay.addStretch()
        self.setWidget(inner)

    def _append(self, w: QWidget):
        self.lay.addWidget(w)
        while self.lay.count() - 1 > self.MAX:
            old = self.lay.takeAt(1).widget()
            if old:
                old.deleteLater()
        QTimer.singleShot(30, lambda: self.verticalScrollBar().setValue(self.verticalScrollBar().maximum()))

    def add_message(self, body: dict, mine: bool, status: str) -> MessageWidget:
        w = MessageWidget(body, mine, status)
        w.expired.connect(self._expire)
        self._append(w)
        return w

    def add_system(self, text: str, color: str = "#55555e"):
        lb = QLabel(f"— {esc(text)} —")
        lb.setAlignment(Qt.AlignCenter)
        lb.setWordWrap(True)
        lb.setStyleSheet(f"color: {color}; font-size: 12px; padding: 4px;")
        self._append(lb)

    def _expire(self, w):
        w.setVisible(False)
        w.deleteLater()

    def clear_all(self):
        while self.lay.count() > 1:
            it = self.lay.takeAt(1)
            if it.widget():
                it.widget().deleteLater()


class Channel:
    def __init__(self, kind: str, title: str, key: bytes | None = None, peer: str = "", peer_pk: str = "",
                 locked: bool = False):
        self.kind, self.title, self.key, self.peer, self.peer_pk, self.locked = kind, title, key, peer, peer_pk, locked
        self.rid = crypto.room_id(key) if key else ""
        self.view = ChatView()
        self.members: set[str] = set()
        self.changed_pk = ""          # chave nova, ainda nao aceita, de um contato que tinha outra
        self.unread = 0
        self.item: QListWidgetItem | None = None

    @property
    def cid(self) -> str:
        return ("room:" + self.rid) if self.kind == "room" else ("dm:" + self.peer)


# ================================================================ dialogos
class JoinDialog(BaseDialog):
    def __init__(self, parent):
        super().__init__(parent, "ENTRAR EM SALA", "Criptografia ponta a ponta com chave derivada da senha")
        f = QFormLayout()
        self.name = QLineEdit("lobby")
        f.addRow(label("SALA", "muted", 2, bold=True), self.name)
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.setPlaceholderText("opcional")
        row = QHBoxLayout()
        row.addWidget(self.pw, 1)
        row.addWidget(button("GERAR", None, self.generate, "Cria uma senha forte e copia"))
        f.addRow(label("SENHA", "muted", 2, bold=True), row)
        self.lay.addLayout(f)
        self.hint = label("", "red", 0.3, 12, wrap=True)
        self.pw.textChanged.connect(self.check)
        self.lay.addWidget(self.hint)
        self.lay.addWidget(label("Sem senha, a sala e publica: quem souber o nome consegue ler. Com senha, so quem "
                                 "tiver a senha le, e nem o servidor sabe o nome da sala.", "muted", 0.3, wrap=True))
        self.add_buttons("ENTRAR")

    def generate(self):
        pw = strong_password()
        self.pw.setEchoMode(QLineEdit.Normal)
        self.pw.setText(pw)
        QApplication.clipboard().setText(pw)
        self.hint.setText("Senha copiada: mande para os outros por um meio seguro.")

    def check(self, t: str):
        self.hint.setText("Senha curta: quem controla o servidor consegue testar senhas comuns. Use 12 caracteres ou "
                          "mais, ou clique em GERAR." if 0 < len(t) < 12 else "")


class DmDialog(BaseDialog):
    def __init__(self, parent):
        super().__init__(parent, "MENSAGEM DIRETA", "So o destinatario consegue ler")
        self.nick = QLineEdit()
        self.nick.setPlaceholderText("ex.: KuroiRonin-7F3A")
        self.lay.addWidget(self.nick)
        self.lay.addWidget(label("Confira a impressao digital da chave com a pessoa por outro meio na primeira vez. "
                                 "Ela aparece no painel da direita.", "muted", 0.3, wrap=True))
        self.add_buttons("ABRIR CONVERSA")


class SettingsDialog(BaseDialog):
    def __init__(self, win: "MainWindow"):
        super().__init__(win, "CONFIGURACOES", "Servidor, identidade e privacidade")
        self.win = win
        self.setMinimumWidth(980)
        cols, left, right = QHBoxLayout(), QVBoxLayout(), QVBoxLayout()
        cols.setSpacing(16)
        cols.addLayout(left, 1)
        cols.addLayout(right, 1)
        self.lay.addLayout(cols)
        s = win.store.data
        f = QFormLayout()
        f.setSpacing(10)
        self.server = QLineEdit(s["server"])
        self.server.setPlaceholderText("ws://ip:7077  ou  wss://dominio")
        f.addRow(label("SERVIDOR", "muted", 2, bold=True), self.server)
        self.remember = QCheckBox("Lembrar as salas (salva nome e senha em disco)")
        self.remember.setChecked(bool(s.get("remember_rooms")))
        f.addRow("", self.remember)
        left.addLayout(f)
        host = CutFrame(cut=10)
        hl = QVBoxLayout(host)
        hl.setContentsMargins(16, 12, 16, 12)
        hl.addWidget(label("HOSPEDAR SERVIDOR NESTE PC", "section", 3))
        ips = lan_ips()
        hl.addWidget(label("Roda o relay cego aqui (porta 7077). Na mesma rede, seus amigos usam:  " +
                           ("  ·  ".join(f"ws://{i}:7077" for i in ips) or "ws://SEU-IP:7077"), "muted", 0.3,
                           wrap=True))
        row = QHBoxLayout()
        self.host_btn = button("PARAR SERVIDOR" if win.hosting else "INICIAR SERVIDOR",
                               "danger" if win.hosting else "primary", self.toggle_host)
        row.addWidget(self.host_btn)
        row.addStretch()
        hl.addLayout(row)
        left.addWidget(host)
        left.addStretch()
        cf = CutFrame(cut=10)
        kl = QVBoxLayout(cf)
        kl.setContentsMargins(16, 12, 16, 12)
        kl.addWidget(label("CALLS", "section", 3))
        kf = QFormLayout()
        mics, outs = calls.audio_devices() if calls.available() else ([], [])
        self.mic, self.spk = QComboBox(), QComboBox()
        for box, names, cur in ((self.mic, mics, s.get("mic", "")), (self.spk, outs, s.get("speaker", ""))):
            box.addItem("padrao do sistema", "")
            for n in names:
                box.addItem(n, n)
            box.setCurrentIndex(max(0, box.findData(cur)))
            box.setMinimumContentsLength(20)
            box.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        kf.addRow(label("MICROFONE", "muted", 2, bold=True), self.mic)
        kf.addRow(label("SAIDA", "muted", 2, bold=True), self.spk)
        self.accept_calls = QComboBox()
        for t, v in (("contatos que eu ja conheco", "known"), ("qualquer pessoa", "all"), ("ninguem", "none")):
            self.accept_calls.addItem(t, v)
        self.accept_calls.setCurrentIndex(max(0, self.accept_calls.findData(s.get("accept_calls", "known"))))
        kf.addRow(label("RECEBER DE", "muted", 2, bold=True), self.accept_calls)
        kl.addLayout(kf)
        self.hide_ip = QCheckBox("Esconder meu IP nas calls (precisa de TURN no servidor)")
        self.hide_ip.setChecked(bool(s.get("hide_ip")))
        kl.addWidget(self.hide_ip)
        if not calls.available():
            kl.addWidget(label("Calls desligadas: faltam dependencias. Rode o instalador de novo.", "red", 0.3, wrap=True))
        right.addWidget(cf)
        idf = CutFrame(cut=10)
        il = QVBoxLayout(idf)
        il.setContentsMargins(16, 12, 16, 12)
        il.addWidget(label("IDENTIDADE", "section", 3))
        il.addWidget(label(f"{win.ident.nick}  ·  origem: {win.ident.source}", None, 0.5, bold=True))
        il.addWidget(label("O nick nasceu do MAC da placa de rede (o MAC nunca sai do computador) e fica salvo aqui. A "
                           "posse dele e provada pela sua chave: faca um backup para usar o nick em outro PC ou depois "
                           "de reinstalar.",
                           "muted", 0.3, wrap=True))
        r2 = QHBoxLayout()
        r2.addWidget(button("EXPORTAR CHAVE", None, self.export))
        r2.addWidget(button("IMPORTAR CHAVE", None, self.import_))
        r2.addStretch()
        il.addLayout(r2)
        right.addWidget(idf)
        right.addStretch()
        row = QHBoxLayout()
        row.addWidget(button("DIAGNOSTICAR CONEXAO", None, win.diagnose))
        row.addStretch()
        left.insertLayout(left.count() - 1, row)
        self.add_buttons("SALVAR")

    def toggle_host(self):
        self.win.toggle_host()
        self.host_btn.setText("PARAR SERVIDOR" if self.win.hosting else "INICIAR SERVIDOR")

    def export(self):
        export_key(self, self.win)

    def import_(self):
        p, _ = QFileDialog.getOpenFileName(self, "Importar chave", str(Path.home()), "Identidade HOLO (*.holo)")
        if p:
            try:
                text = Path(p).read_text(encoding="utf-8")
                pw = None
                if identity.backup_needs_password(text):
                    pw, ok = QInputDialog.getText(self, "Importar chave", "Senha do backup:", QLineEdit.Password)
                    if not ok:
                        return
                identity.import_identity(text, pw)
                QMessageBox.information(self, "Importado", "Chave importada. Reabra o HOLO para usar esse nick.\n"
                                        "A chave anterior foi guardada na pasta de configuracao.")
            except Exception as e:  # noqa: BLE001
                QMessageBox.warning(self, "Erro", str(e))


def export_key(parent, win) -> bool:
    """Backup da chave com senha. Devolve True se salvou (e marca o backup como feito)."""
    pw, ok = QInputDialog.getText(parent, "Backup da chave", "Crie uma senha para o backup (minimo 8 caracteres).\n"
                                  "Sem ela ninguem abre o arquivo, nem voce: anote num lugar seguro.", QLineEdit.Password)
    if not ok:
        return False
    if len(pw) < 8:
        QMessageBox.warning(parent, "Backup da chave", "A senha precisa ter pelo menos 8 caracteres.")
        return False
    pw2, ok = QInputDialog.getText(parent, "Backup da chave", "Digite a senha de novo:", QLineEdit.Password)
    if not ok:
        return False
    if pw2 != pw:
        QMessageBox.warning(parent, "Backup da chave", "As senhas nao conferem.")
        return False
    p, _ = QFileDialog.getSaveFileName(parent, "Salvar backup da chave", str(Path.home() / f"{win.ident.nick}.holo"),
                                       "Identidade HOLO (*.holo)")
    if not p:
        return False
    Path(p).write_text(win.ident.export(pw), encoding="utf-8")
    win.store.data["key_backup"] = time.strftime("%Y-%m-%d")
    win.store.save()
    QMessageBox.information(parent, "Backup salvo", "Guarde o arquivo e a senha em lugares diferentes (ex.: pendrive e "
                                                    "gerenciador de senhas). Com eles voce recupera o nick em outro sistema.")
    return True


class DiagDialog(BaseDialog):
    """Testa a conexao passo a passo e deixa copiar o relatorio (sem nick, IP ou chave)."""
    step = Signal(object)

    def __init__(self, win: "MainWindow"):
        super().__init__(win, "DIAGNOSTICO", "Testa o caminho ate o servidor, passo a passo")
        self.setMinimumWidth(720)
        self.win, self.report, self.lines = win, "", []
        self.out = label("testando...", None, 0.3, 13, wrap=True)
        self.out.setTextFormat(Qt.RichText)
        self.out.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.out.setMinimumHeight(260)
        self.out.setAlignment(Qt.AlignTop)
        self.lay.addWidget(self.out)
        row = QHBoxLayout()
        row.addStretch()
        self.copy_btn = button("COPIAR RELATORIO", "primary", self.copy)
        self.copy_btn.setEnabled(False)
        row.addWidget(self.copy_btn)
        row.addWidget(button("FECHAR", None, self.accept))
        self.lay.addLayout(row)
        self.step.connect(self.on_step)
        url = win.store.data["server"]
        self.task = Task(diag.run, url, lambda *a: self.step.emit(a), VERSION)
        self.task.done.connect(self.on_done)
        win.tasks.append(self.task)                # a janela pode fechar antes do teste acabar
        self.task.start()

    def on_step(self, s):
        ok, name, info = s
        mark, color = {True: ("✔", "#3ddc84"), False: ("✖", "#ff5560")}.get(ok, ("!", "#ffb347"))
        self.lines.append(f'<p style="margin:4px 0"><span style="color:{color}">{mark} <b>{esc(name)}</b></span> '
                          f'<span style="color:#c8c8d0">{esc(info)}</span></p>')
        self.out.setText("".join(self.lines))

    def on_done(self, r):
        self.report = f"erro no diagnostico: {r}" if isinstance(r, Exception) else r
        if isinstance(r, Exception):
            self.on_step((False, "diagnostico", str(r)))
        if self.win.last_error:
            self.report += "\nultimo erro no app: " + self.win.last_error
        self.copy_btn.setEnabled(True)

    def copy(self):
        QApplication.clipboard().setText(self.report)
        self.copy_btn.setText("COPIADO")


# ================================================================ janela
class MainWindow(QMainWindow):
    def __init__(self, ident: identity.Identity, store: Store):
        super().__init__()
        self.ident, self.store = ident, store
        self.channels: dict[str, Channel] = {}
        self.current: Channel | None = None
        self.directory: dict[str, str | None] = {}       # nick -> pk (respostas whois)
        self.pending_verify: dict[str, list] = {}
        self.pending_dm: dict[str, Channel] = {}
        self.tasks: list[Task] = []
        self.replay = crypto.Replay()
        self.last_error = ""                             # por que nao conectou (fica na tela ate conectar)
        self.ice: list[dict] = []                        # STUN/TURN informados pelo servidor
        self.calls = CallManager(self)
        self.hosting = False
        self.host_stop = None
        self.host_loop = None
        self.setWindowTitle(f"{APP_NAME} — {ident.nick}")
        self.setWindowIcon(QIcon(str(ASSETS / "arasaka-holo.svg")))
        self.resize(1260, 820)
        self.setMinimumSize(980, 620)

        root = QWidget()
        root.setObjectName("root")
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        # ---------------------------------------------------- lateral
        side = QFrame()
        side.setObjectName("side")
        side.setFixedWidth(270)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 10)
        sl.setSpacing(4)
        sl.addWidget(IdentityCard(ident))
        st = QHBoxLayout()
        st.setContentsMargins(16, 0, 16, 0)
        self.ind = Indicator(False)
        st.addWidget(self.ind)
        self.state_lbl = label("CONECTANDO...", "muted", 2, 11, True)
        st.addWidget(self.state_lbl, 1)
        sl.addLayout(st)
        sl.addSpacing(8)
        rh = QHBoxLayout()
        rh.setContentsMargins(16, 0, 10, 0)
        rh.addWidget(label("SALAS", "section", 3), 1)
        b = button("+", "ghost", self.join_dialog, "Entrar em sala (Ctrl+J)")
        b.setFixedWidth(34)
        rh.addWidget(b)
        sl.addLayout(rh)
        self.rooms_list = QListWidget()
        self.rooms_list.setObjectName("chans")
        self.rooms_list.itemClicked.connect(self.select_item)
        sl.addWidget(self.rooms_list, 2)
        dh = QHBoxLayout()
        dh.setContentsMargins(16, 0, 10, 0)
        dh.addWidget(label("DIRETAS", "section", 3), 1)
        b = button("+", "ghost", self.dm_dialog, "Nova mensagem direta (Ctrl+D)")
        b.setFixedWidth(34)
        dh.addWidget(b)
        sl.addLayout(dh)
        self.dm_list = QListWidget()
        self.dm_list.setObjectName("chans")
        self.dm_list.itemClicked.connect(self.select_item)
        sl.addWidget(self.dm_list, 1)
        foot = QHBoxLayout()
        foot.setContentsMargins(12, 0, 12, 0)
        foot.addWidget(button("CONFIG", "ghost", self.settings_dialog))
        foot.addStretch()
        foot.addWidget(button("PANICO", "danger", self.panic, "Apaga tudo da tela e sai das salas (Ctrl+Shift+X)"))
        sl.addLayout(foot)
        h.addWidget(side)

        # ---------------------------------------------------- centro
        center = QWidget()
        cl = QVBoxLayout(center)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        top = QFrame()
        top.setObjectName("topbar")
        tl = QHBoxLayout(top)
        tl.setContentsMargins(22, 12, 22, 12)
        self.title = label("", None, 3, 18, True)
        tl.addWidget(self.title)
        self.lock = label("", "red", 2, 11, True)
        tl.addWidget(self.lock)
        tl.addStretch()
        self.e2e = label("■ PONTA A PONTA  ·  SEM HISTORICO", "muted", 2, 11, True)
        tl.addWidget(self.e2e)
        tl.addSpacing(10)
        self.call_btn = button("CALL", "primary", self.calls.call, "Call de voz com compartilhamento de tela (Ctrl+K)")
        self.call_btn.setVisible(False)
        tl.addWidget(self.call_btn)
        cl.addWidget(top)
        self.err_bar = QFrame()
        self.err_bar.setObjectName("errbar")
        el = QHBoxLayout(self.err_bar)
        el.setContentsMargins(22, 8, 22, 8)
        self.err_lbl = label("", None, 0.3, 13, wrap=True)
        self.err_lbl.setStyleSheet("color: #ffb347;")
        self.err_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        el.addWidget(self.err_lbl, 1)
        el.addWidget(button("DIAGNOSTICAR", None, self.diagnose, "Testa a conexao passo a passo"))
        el.addWidget(button("TENTAR DE NOVO", "primary", self.connect_server))
        self.err_bar.hide()
        cl.addWidget(self.err_bar)
        cl.addWidget(self.calls.bar)
        self.stack = QStackedWidget()
        self.welcome = self.build_welcome()
        self.stack.addWidget(self.welcome)
        cl.addWidget(self.stack, 1)
        comp = QFrame()
        comp.setObjectName("topbar")
        col = QVBoxLayout(comp)
        col.setContentsMargins(22, 10, 22, 12)
        self.input = QPlainTextEdit()
        self.input.setObjectName("composer")
        self.input.setPlaceholderText("mensagem cifrada...  (Enter envia · Shift+Enter quebra linha)")
        self.input.setFixedHeight(76)
        self.input.installEventFilter(self)
        col.addWidget(self.input)
        row = QHBoxLayout()
        self.ttl = QComboBox()
        for t, v in TTLS:
            self.ttl.addItem(t, v)
        self.ttl.setCurrentIndex(max(0, [v for _t, v in TTLS].index(store.data.get("ttl", 0))
                                     if store.data.get("ttl", 0) in [v for _t, v in TTLS] else 0))
        self.ttl.currentIndexChanged.connect(lambda _i: self._save_ttl())
        row.addWidget(self.ttl)
        row.addStretch()
        self.counter = label("", "dim", 0.5, 11)
        row.addWidget(self.counter)
        self.send_btn = button("ENVIAR  ▶", "primary", self.send)
        row.addWidget(self.send_btn)
        col.addLayout(row)
        self.input.textChanged.connect(lambda: self.counter.setText(
            f"{len(self.input.toPlainText())}/{crypto.MAX_TEXT}"))
        cl.addWidget(comp)
        self.composer = comp
        h.addWidget(center, 1)

        # ---------------------------------------------------- membros / contato
        mem = QFrame()
        mem.setObjectName("members")
        mem.setFixedWidth(240)
        ml = QVBoxLayout(mem)
        ml.setContentsMargins(14, 14, 14, 14)
        self.side_title = label("ONLINE", "section", 3)
        ml.addWidget(self.side_title)
        self.members = QListWidget()
        self.members.setObjectName("chans")
        self.members.itemDoubleClicked.connect(lambda it: self.open_dm(it.data(Qt.UserRole)))
        ml.addWidget(self.members, 1)
        self.peer_info = label("", "muted", 0.3, 12, wrap=True)
        ml.addWidget(self.peer_info)
        ml.addWidget(label("Duplo clique num nick abre uma mensagem direta.", "dim", 0.3, 11, wrap=True))
        h.addWidget(mem)
        self.setCentralWidget(root)
        self.composer.setEnabled(False)

        QShortcut(QKeySequence("Ctrl+J"), self, self.join_dialog)
        QShortcut(QKeySequence("Ctrl+D"), self, self.dm_dialog)
        QShortcut(QKeySequence("Ctrl+Shift+X"), self, self.panic)
        QShortcut(QKeySequence("Ctrl+K"), self, self.calls.call)
        QShortcut(QKeySequence("Ctrl+M"), self, self.calls.toggle_mute)

        # ---------------------------------------------------- rede
        self.bridge = Bridge()
        self.bridge.event.connect(self.on_event)
        self.client: HoloClient | None = None
        self.connect_server()
        if store.data.get("remember_rooms"):
            for r in store.data.get("rooms", []):
                self.join_room(r["name"], r.get("pw", ""))

    # ------------------------------------------------------------ ui util
    def build_welcome(self) -> QWidget:
        w = QWidget()
        w.setObjectName("page")
        l = QVBoxLayout(w)
        l.setContentsMargins(60, 40, 60, 40)
        l.addStretch()
        lg = QLabel()
        lg.setPixmap(logo_pixmap(110))
        lg.setAlignment(Qt.AlignCenter)
        l.addWidget(lg)
        t = label("CANAL SEGURO", None, 6, 26, True)
        t.setAlignment(Qt.AlignCenter)
        l.addWidget(t)
        for line in ["Sem conta. Sem login. Sem e-mail. Sem telefone.",
                     f"Voce e  {self.ident.nick}  para sempre neste computador.",
                     "Mensagens cifradas no seu PC: o servidor so repassa blobs e nao guarda nada.",
                     "Quem estiver offline nao recebe: nao existe historico em lugar nenhum."]:
            x = label(line, "muted", 0.5, 14)
            x.setAlignment(Qt.AlignCenter)
            l.addWidget(x)
        l.addSpacing(14)
        r = QHBoxLayout()
        r.addStretch()
        r.addWidget(button("ENTRAR NO LOBBY", "primary", lambda: self.join_room("lobby", "")))
        r.addWidget(button("SALA PRIVADA", None, self.join_dialog))
        r.addWidget(button("MENSAGEM DIRETA", None, self.dm_dialog))
        r.addStretch()
        l.addLayout(r)
        l.addStretch()
        return w

    def toast(self, text: str, color="#ff2e40"):
        if self.current:
            self.current.view.add_system(text, color)
        else:
            self.statusBar().showMessage(text, 5000)

    def _save_ttl(self):
        self.store.data["ttl"] = self.ttl.currentData()
        self.store.save()

    def eventFilter(self, obj, e):
        if obj is self.input and e.type() == e.Type.KeyPress and e.key() in (Qt.Key_Return, Qt.Key_Enter) \
                and not e.modifiers() & Qt.ShiftModifier:
            self.send()
            return True
        return False

    # ------------------------------------------------------------ conexao
    def show_error(self, text: str):
        self.last_error = text
        self.err_lbl.setText("SEM CONEXAO: " + text if text else "")
        self.err_bar.setVisible(bool(text))

    def diagnose(self):
        DiagDialog(self).exec()

    def connect_server(self):
        old, self.client = self.client, None
        if old:                                  # encerrar pode esperar a rede: fora da interface
            threading.Thread(target=old.stop, daemon=True, name="holo-net-stop").start()

        def emit(ev):                            # avisos atrasados da conexao antiga nao contam
            if self.client is client:
                self.bridge.event.emit(ev)
        client = HoloClient(self.store.data["server"], self.ident, emit)
        self.client = client
        for ch in self.channels.values():
            if ch.kind == "room":
                self.client.rooms.add(ch.rid)
        self.client.start()

    def on_event(self, m: dict):
        op = m.get("op")
        if isinstance(op, str) and op.startswith("call_"):
            return self.calls.on_event(m)
        if op == "_state":
            st = m["state"]
            self.ind.set_ok(st == "online")
            txt = {"connecting": "CONECTANDO...", "login": "ENTRANDO...", "online": "ONLINE", "offline": "OFFLINE · RECONECTANDO",
                   "stopped": "DESCONECTADO"}.get(st, st.upper())
            self.state_lbl.setText(txt)
            self.state_lbl.setToolTip(m.get("error", "") or m.get("url", ""))
            # o motivo fica na barra ate conectar, e aparece uma vez na conversa aberta
            err = m.get("error", "")
            if st == "offline" and err:
                if err != self.last_error and self.current:
                    self.toast("sem conexao: " + err)
                self.show_error(err)
            elif st == "online":
                self.show_error("")
        elif op == "welcome":
            plain = is_plain(self.store.data["server"])
            self.state_lbl.setText(f"ONLINE · {m.get('online', 1)} NICK(S)" + (" · SEM TLS" if plain else ""))
            self.state_lbl.setToolTip(self.store.data["server"] + ("\nSem TLS: a rede no caminho ve nicks e horarios "
                                                                   "(nao o conteudo)." if plain else ""))
            self.ice = clean_ice(m.get("ice"))
            for nick in self.pending_verify:              # perguntas que se perderam na queda da conexao
                self.client.send({"op": "whois", "nick": nick})
            if m.get("new"):
                self.toast(f"nick {self.ident.nick} registrado e vinculado a sua chave", "#ececf0")
            if m.get("motd"):
                self.toast("servidor: " + m["motd"], "#8c8c96")
        elif op == "error":
            code = m.get("code")
            if code in ("nick_taken", "bad_auth", "bad_sig", "pow", "too_many", "challenge", "tls", "server"):
                self.show_error(str(m.get("msg") or code))
            if code == "nick_taken":
                QMessageBox.critical(self, "NICK JA VINCULADO",
                                     f"O nick {self.ident.nick} ja foi registrado neste servidor com outra chave.\n\n"
                                     "Se e voce (reinstalou o sistema), importe o backup da chave em CONFIG.\n"
                                     "Se nao, outra pessoa reivindicou esse nick primeiro.")
            elif code == "offline":
                ch = self.channels.get("dm:" + m.get("to", "")) or self.current
                if ch:
                    ch.view.add_system(m.get("msg", "offline"), "#ffb347")
            else:
                self.toast(m.get("msg", code or "erro"))
        elif op == "joined":
            ch = self.room_by_rid(m["room"])
            if ch:
                ch.members = {n for n in m.get("members", []) if valid_nick(n)}
                self.refresh_members()
        elif op == "presence":
            ch = self.room_by_rid(m["room"])
            if ch and valid_nick(m.get("nick")):
                (ch.members.add if m["on"] else ch.members.discard)(m["nick"])
                if not m["on"]:
                    self.calls.left_room(ch, m["nick"])
                ch.view.add_system(f"{m['nick']} {'entrou' if m['on'] else 'saiu'}", "#55555e")
                self.refresh_members()
        elif op == "msg":
            self.on_room_msg(m)
        elif op == "dm":
            self.on_dm(m)
        elif op == "whois":
            self.on_whois(m)
        elif op == "ice":
            self.ice = clean_ice(m.get("servers"))

    def room_by_rid(self, rid: str) -> Channel | None:
        return self.channels.get("room:" + rid)

    # ------------------------------------------------------------ verificacao de remetente
    def verify_sender(self, body: dict) -> str:
        """Confere se a chave que assinou e a chave do nick (diretorio + chave fixada localmente)."""
        nick, k = body["n"], body["k"]
        if nick == self.ident.nick:
            return "ok" if k == self.ident.pk_b64 else "mismatch"
        known = self.directory.get(nick, "?")
        if known == "?":
            if nick not in self.pending_verify:
                self.client.send({"op": "whois", "nick": nick})
            return "pending"
        if known != k:
            return "mismatch"
        return self.store.pin(nick, k)

    def on_whois(self, m: dict):
        nick, pk = m.get("nick"), m.get("pk")
        if not valid_nick(nick):
            return
        if not crypto.valid_pk(pk):
            pk = None
        self.directory[nick] = pk
        for body, w, rch in self.pending_verify.pop(nick, []):
            status = "mismatch" if pk != body["k"] else self.store.pin(nick, pk)
            if w is None:                                 # sinalizacao de call da sala
                if status in ("ok", "new") and self.channels.get(rch.cid) is rch:
                    self.calls.on_room(rch, body)
                continue
            try:
                w.set_status(status)
            except RuntimeError:                          # a mensagem ja sumiu da tela
                pass
        ch = self.pending_dm.pop(nick, None)
        if ch:
            if not pk:
                ch.view.add_system(f"{nick} nao existe neste servidor", "#ff2e40")
            else:
                if self.store.pin(nick, pk) == "changed":
                    ch.peer_pk, ch.changed_pk = self.store.data["pins"][nick], pk
                    ch.view.add_system(f"ATENCAO: a chave de {nick} mudou desde a ultima conversa. Pode ser outra "
                                       "pessoa ou um servidor malicioso. Nada sera enviado sem voce confirmar.",
                                       "#ffb347")
                else:
                    ch.peer_pk = pk
                ch.view.add_system(f"chave de {nick}: {identity.fingerprint(crypto.ub64(pk))}  ·  "
                                   f"{'online' if m.get('online') else 'offline'}", "#8c8c96")
            if ch is self.current:
                self.refresh_members()

    # ------------------------------------------------------------ salas
    def join_dialog(self):
        d = JoinDialog(self)
        if d.exec() == QDialog.Accepted and d.name.text().strip():
            self.join_room(d.name.text().strip(), d.pw.text())

    def join_room(self, name: str, pw: str):
        name = name.strip().lstrip("#")[:48]
        self.toast("derivando chave da sala (Argon2id)...", "#55555e")
        t = Task(crypto.room_key, name, pw)

        def done(key):
            if isinstance(key, Exception):
                return self.toast(f"erro: {key}")
            ch = Channel("room", name, key, locked=bool(pw))
            if ch.cid in self.channels:
                return self.select_channel(self.channels[ch.cid])
            self.channels[ch.cid] = ch
            self.stack.addWidget(ch.view)
            ch.item = QListWidgetItem(("🔒 " if pw else "#  ") + name)
            ch.item.setData(Qt.UserRole, ch.cid)
            self.rooms_list.addItem(ch.item)
            ch.view.add_system(f"sala {name} · id para o servidor: {ch.rid[:12]}… · "
                               + ("protegida por senha" if pw else "publica (sem senha)"), "#8c8c96")
            self.client.send({"op": "join", "room": ch.rid})
            if self.store.data.get("remember_rooms"):
                rooms = [r for r in self.store.data.get("rooms", []) if r["name"] != name]
                self.store.data["rooms"] = rooms + [{"name": name, "pw": pw}]
                self.store.save()
            self.select_channel(ch)
        t.done.connect(done)
        self.tasks = [x for x in self.tasks if x.isRunning()] + [t]
        t.start()

    def on_room_msg(self, m: dict):
        ch = self.room_by_rid(m["room"])
        if not ch:
            return
        try:
            body = crypto.open_room(ch.key, m.get("blob", ""))
        except crypto.OldMessage as e:
            return ch.view.add_system(f"{e.nick} usa uma versao antiga do HOLO: mensagem recusada (peca para atualizar)",
                                      "#ffb347")
        if not body:
            return ch.view.add_system("mensagem que nao abre com esta chave (descartada)", "#ffb347")
        if not self.replay.fresh(body):
            return
        status = self.verify_sender(body)
        if "d" in body:                                   # sinalizacao de call: nunca vira texto
            if not crypto.Replay.on_time(body):
                return
            if status == "pending":
                self.pending_verify.setdefault(body["n"], []).append((body, None, ch))
            elif status in ("ok", "new"):
                self.calls.on_room(ch, body)
            return
        w = ch.view.add_message(body, body["n"] == self.ident.nick, status)
        if status == "pending":
            self.pending_verify.setdefault(body["n"], []).append((body, w, ch))
        self.bump(ch)

    # ------------------------------------------------------------ diretas
    def dm_dialog(self):
        d = DmDialog(self)
        if d.exec() == QDialog.Accepted and d.nick.text().strip():
            self.open_dm(d.nick.text().strip())

    def open_dm(self, nick: str):
        if not nick or nick == self.ident.nick:
            return
        if not valid_nick(nick):
            return self.toast("nick invalido: confira (ex.: KuroiRonin-7F3A)")
        ch = self.channels.get("dm:" + nick)
        if not ch:
            ch = self.new_dm(nick)
            ch.view.add_system(f"conversa direta com {nick} · cifrada so para voces dois · nada fica salvo",
                               "#8c8c96")
            self.pending_dm[nick] = ch
            self.client.send({"op": "whois", "nick": nick})
        self.select_channel(ch)

    def new_dm(self, nick: str, pk: str = "") -> Channel:
        ch = Channel("dm", nick, peer=nick, peer_pk=pk)
        self.channels[ch.cid] = ch
        self.stack.addWidget(ch.view)
        ch.item = QListWidgetItem("@  " + nick)
        ch.item.setData(Qt.UserRole, ch.cid)
        self.dm_list.addItem(ch.item)
        return ch

    def on_dm(self, m: dict):
        frm, pk = m.get("from"), m.get("from_pk")
        if not valid_nick(frm) or frm == self.ident.nick or not crypto.valid_pk(pk):
            return
        ch = self.channels.get("dm:" + frm)
        try:
            body = crypto.open_dm(self.ident.sk, pk, m.get("blob", ""))
        except crypto.OldMessage:
            return self.toast(f"{frm} usa uma versao antiga do HOLO: mensagem recusada (peca para atualizar)", "#ffb347")
        if not body or body["n"] != frm:
            # so quem ja conversa com voce gera aviso: lixo de estranhos nao abre conversa nem fixa chave
            return ch.view.add_system("mensagem direta invalida descartada", "#ffb347") if ch else None
        if not self.replay.fresh(body):
            return
        known = frm in self.store.data["pins"]
        pin = self.store.pin(frm, pk)
        is_call = "d" in body
        if is_call and body["d"].get("a") != "invite":    # offer, answer, hangup...: so valem dentro de uma call
            if pin != "changed" and crypto.Replay.on_time(body):
                self.calls.on_dm(frm, pk, body, known)
            return
        if not ch:
            ch = self.new_dm(frm, pk)
            ch.view.add_system(f"{frm} abriu uma conversa direta · chave {identity.fingerprint(crypto.ub64(pk))}",
                               "#8c8c96")
        ch.peer_pk = ch.peer_pk or pk
        if pin == "changed":
            ch.changed_pk = pk
            ch.view.add_system(f"ATENCAO: a chave de {frm} mudou. Confirme com a pessoa por outro meio.", "#ffb347")
        if is_call:
            if pin != "changed" and crypto.Replay.on_time(body):
                self.calls.on_dm(frm, pk, body, known)
        else:
            ch.view.add_message(body, False, "changed" if pin == "changed" else "ok")
        self.bump(ch)

    # ------------------------------------------------------------ envio
    def send(self):
        ch = self.current
        text = self.input.toPlainText().strip()
        if not ch or not text:
            return
        if len(text) > crypto.MAX_TEXT:
            return self.toast(f"mensagem maior que {crypto.MAX_TEXT} caracteres")
        if not self.client or not self.client.connected:
            return self.toast("sem conexao com o servidor")
        ttl = int(self.ttl.currentData() or 0)
        if ch.kind == "room":
            self.client.send({"op": "msg", "room": ch.rid,
                              "blob": crypto.seal_room(ch.key, self.ident.sk, self.ident.nick, text, ttl)})
        else:
            if not ch.peer_pk:
                return self.toast("ainda buscando a chave do destinatario...")
            if ch.changed_pk and not self.accept_key(ch):
                return
            blob = crypto.seal_dm(self.ident.sk, self.ident.nick, ch.peer_pk, text, ttl)
            self.client.send({"op": "dm", "to": ch.peer, "blob": blob})
            body = {"n": self.ident.nick, "k": self.ident.pk_b64, "t": text, "ts": int(time.time()), "ttl": ttl}
            ch.view.add_message(body, True, "ok")
        self.input.clear()

    def accept_key(self, ch: Channel) -> bool:
        """O contato aparece com outra chave: so passa a usar a nova se a pessoa confirmar."""
        new = identity.fingerprint(crypto.ub64(ch.changed_pk))
        r = QMessageBox.warning(self, "A chave do contato mudou",
                                f"{ch.peer} aparece com uma chave diferente da que voce conhecia.\n\nChave nova: {new}\n\n"
                                "Pode ser outra pessoa ou um servidor mal-intencionado. Confira a impressao digital por "
                                "outro meio. Confiar na chave nova?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if r != QMessageBox.Yes:
            return False
        ch.peer_pk, ch.changed_pk = ch.changed_pk, ""
        self.store.repin(ch.peer, ch.peer_pk)
        self.refresh_members()
        return True

    def send_data(self, nick: str, pk: str, data: dict):
        """Sinalizacao de call por mensagem direta cifrada."""
        if self.client:
            self.client.send({"op": "dm", "to": nick,
                              "blob": crypto.seal_dm(self.ident.sk, self.ident.nick, pk, "", 0, data)})

    def send_room_data(self, ch: Channel, data: dict):
        if self.client:
            self.client.send({"op": "msg", "room": ch.rid,
                              "blob": crypto.seal_room(ch.key, self.ident.sk, self.ident.nick, "", 0, data)})

    def update_call_button(self):
        ch = self.current
        self.call_btn.setVisible(bool(ch))
        if not ch:
            return
        n = len(self.calls.rooms.get(ch.cid, ()))
        self.call_btn.setText(f"CALL ({n})" if n else "CALL")
        self.call_btn.setEnabled(not self.calls.busy())

    # ------------------------------------------------------------ navegacao
    def select_item(self, it: QListWidgetItem):
        ch = self.channels.get(it.data(Qt.UserRole))
        if ch:
            self.select_channel(ch)

    def select_channel(self, ch: Channel):
        self.current = ch
        ch.unread = 0
        self.update_item(ch)
        self.stack.setCurrentWidget(ch.view)
        self.title.setText(("#" if ch.kind == "room" else "@") + ch.title.upper())
        self.lock.setText("■ SENHA" if ch.locked else ("■ PUBLICA" if ch.kind == "room" else "■ DIRETA"))
        self.composer.setEnabled(True)
        (self.rooms_list if ch.kind == "room" else self.dm_list).setCurrentItem(ch.item)
        (self.dm_list if ch.kind == "room" else self.rooms_list).clearSelection()
        self.refresh_members()
        self.update_call_button()
        self.input.setFocus()

    def bump(self, ch: Channel):
        if ch is not self.current or not self.isActiveWindow():
            ch.unread += 1
            self.update_item(ch)
            QApplication.alert(self, 0)

    def update_item(self, ch: Channel):
        if ch.item:
            base = (("🔒 " if ch.locked else "#  ") if ch.kind == "room" else "@  ") + ch.title
            ch.item.setText(base + (f"   ({ch.unread})" if ch.unread else ""))

    def refresh_members(self):
        self.members.clear()
        ch = self.current
        if not ch:
            return
        if ch.kind == "room":
            self.side_title.setText(f"ONLINE  ·  {len(ch.members)}")
            for n in sorted(ch.members):
                it = QListWidgetItem(("◆ " if n == self.ident.nick else "● ") + n)
                it.setData(Qt.UserRole, n)
                it.setForeground(QColor(nick_color(n)))
                self.members.addItem(it)
            self.peer_info.setText("O servidor ve quantos nicks estao na sala, mas nao o nome dela nem as "
                                   "mensagens.")
        else:
            self.side_title.setText("CONTATO")
            it = QListWidgetItem("● " + ch.peer)
            it.setForeground(QColor(nick_color(ch.peer)))
            self.members.addItem(it)
            fp = identity.fingerprint(crypto.ub64(ch.peer_pk)) if ch.peer_pk else "buscando..."
            if ch.changed_pk:
                fp += "\n⚠ apareceu com outra chave: " + identity.fingerprint(crypto.ub64(ch.changed_pk))
            self.peer_info.setText(f"IMPRESSAO DIGITAL\n{fp}\n\nConfira com a pessoa por outro meio. Se mudar, "
                                   "o HOLO avisa.")

    # ------------------------------------------------------------ extras
    def settings_dialog(self):
        d = SettingsDialog(self)
        if d.exec() == QDialog.Accepted:
            changed = normalize_url(d.server.text()) != self.store.data["server"]
            self.store.data["server"] = normalize_url(d.server.text()) or DEFAULT_SERVER
            self.store.data["remember_rooms"] = d.remember.isChecked()
            if not d.remember.isChecked():
                self.store.data["rooms"] = []
            self.store.data.update(mic=d.mic.currentData(), speaker=d.spk.currentData(),
                                   accept_calls=d.accept_calls.currentData(), hide_ip=d.hide_ip.isChecked())
            self.store.save()
            if changed:
                self.connect_server()

    def toggle_host(self):
        if self.hosting:
            if self.host_loop and self.host_stop:
                self.host_loop.call_soon_threadsafe(self.host_stop.set)
            self.hosting = False
            return
        import asyncio
        from . import server
        ready = threading.Event()
        failed = []

        def run():
            self.host_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.host_loop)
            self.host_stop = asyncio.Event()
            try:
                self.host_loop.run_until_complete(server.serve("0.0.0.0", 7077, server.default_data_dir(),
                                                               quiet=True, stop=self.host_stop, ready=ready.set))
            except OSError as e:
                failed.append(e)
                self.bridge.event.emit({"op": "error", "code": "host", "msg": f"servidor local: {e}"})
                ready.set()
        threading.Thread(target=run, daemon=True).start()
        ready.wait(5)
        if failed or not ready.is_set():
            return
        self.hosting = True
        if self.store.data["server"] != LOCAL_SERVER:
            self.store.data["server"] = LOCAL_SERVER
            self.store.save()
            self.connect_server()

    def panic(self):
        self.calls.shutdown()
        self.calls.forget_rooms()
        for ch in list(self.channels.values()):
            if ch.kind == "room" and self.client:
                self.client.send({"op": "leave", "room": ch.rid})
            ch.view.clear_all()
            self.stack.removeWidget(ch.view)
            ch.view.deleteLater()
        self.channels.clear()
        self.pending_verify.clear()
        self.pending_dm.clear()
        self.tasks = [t for t in self.tasks if t.isRunning()]      # guardavam o nome e a senha das salas
        if self.store.data.get("rooms"):                           # senhas de 'Lembrar as salas'
            self.store.data["rooms"] = []
            self.store.save()
        self.rooms_list.clear()
        self.dm_list.clear()
        self.members.clear()
        self.current = None
        self.input.clear()
        self.composer.setEnabled(False)
        self.title.setText("")
        self.lock.setText("")
        self.stack.setCurrentWidget(self.welcome)
        QApplication.clipboard().clear()
        self.update_call_button()
        self.statusBar().showMessage("PANICO: saiu da call e das salas, e apagou conversas e senhas salvas", 4000)

    def backup_reminder(self):
        """Sem backup da chave, o nick se perde ao reinstalar: lembra (no maximo uma vez por semana)."""
        if self.store.data.get("key_backup"):
            return
        last = self.store.data.get("key_backup_reminded", "")
        if last and time.time() - time.mktime(time.strptime(last, "%Y-%m-%d")) < 7 * 86400:
            return
        self.store.data["key_backup_reminded"] = time.strftime("%Y-%m-%d")
        self.store.save()
        box = QMessageBox(self)
        box.setWindowTitle("Backup da chave")
        box.setText(f"Voce ainda nao fez backup da chave do nick {self.ident.nick}.")
        box.setInformativeText("Se reinstalar o sistema ou trocar de PC sem o backup, voce perde esse nick para sempre. "
                               "O backup e um arquivo protegido por senha.")
        now = box.addButton("FAZER BACKUP AGORA", QMessageBox.AcceptRole)
        box.addButton("LEMBRAR DEPOIS", QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is now:
            export_key(self, self)

    def closeEvent(self, e):
        self.calls.shutdown()
        if self.client:
            self.client.stop()
        e.accept()


def install_error_dialog(win: MainWindow):
    """Erro inesperado: aparece na tela (o app roda sem terminal) e vai para errors.log, so neste PC."""
    seen: set[str] = set()
    plain = sys.excepthook

    def hook(kind, e, tb):
        plain(kind, e, tb)
        if issubclass(kind, KeyboardInterrupt):
            return
        last = traceback.extract_tb(tb)[-1:] if tb else []
        where = f"{Path(last[0].filename).name}:{last[0].lineno}" if last else "?"
        text = f"{kind.__name__}: {e}\n{where}"
        try:
            log = win.store.dir / "errors.log"
            if log.exists() and log.stat().st_size > 200_000:
                log.unlink()
            # so o tipo e os locais no codigo: o texto do erro poderia conter um pedaco de conversa
            stack = " < ".join(f"{Path(f.filename).name}:{f.lineno}" for f in reversed(traceback.extract_tb(tb)))
            with open(log, "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {VERSION} {kind.__name__} {stack}\n")
        except OSError:
            pass
        if where not in seen:                    # cada erro aparece uma vez: um timer nao pode abrir mil janelas
            seen.add(where)
            QTimer.singleShot(0, win, lambda: QMessageBox.warning(
                win, "Erro no HOLO", f"Aconteceu um erro inesperado (o HOLO continua aberto):\n\n{text[:400]}\n\n"
                f"Versao {VERSION}. Mande um print desta janela para quem cuida do HOLO."))
    sys.excepthook = hook


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    QApplication.setApplicationName("arasaka-holo")
    QApplication.setApplicationDisplayName(APP_NAME)
    QApplication.setDesktopFileName("arasaka-holo")
    app = QApplication(argv)
    load_fonts()
    app.setStyleSheet(stylesheet() + EXTRA_QSS)
    app.setWindowIcon(QIcon(str(ASSETS / "arasaka-holo.svg")))
    store = Store()
    srv = next((a.split("=", 1)[1] for a in argv if a.startswith("--server=")), None)
    if srv:
        store.data["server"] = srv
    try:
        ident = identity.load_identity()
    except OSError as e:
        QMessageBox.critical(None, APP_NAME, f"Nao consegui ler a sua chave:\n{identity.Identity.key_path()}\n\n{e}\n\n"
                             "Nada foi alterado. Confira a permissao do arquivo e abra de novo.")
        return 1
    win = MainWindow(ident, store)
    install_error_dialog(win)
    # visual Cyberpunk (CRT, glitch, inicialização, barra de status); sem a tela de inicialização nas prévias
    fx.install(win, name="ARASAKA HOLO", icon=ASSETS / "arasaka-holo.svg", extra=lambda: [("NET", win.state_lbl.text())], boot=not any(a.startswith("--screenshot=") for a in argv))
    win.show()
    if not any(a.startswith("--screenshot=") for a in argv):
        QTimer.singleShot(6000, win.backup_reminder)
    shot = next((a.split("=", 1)[1] for a in argv if a.startswith("--screenshot=")), None)
    if shot:
        QTimer.singleShot(int(next((a.split("=", 1)[1] for a in argv if a.startswith("--delay=")), "3000")),
                          lambda: (win.grab().save(shot), app.quit()))
    return app.exec()
