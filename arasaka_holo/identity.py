"""
ARASAKA HOLO // identidade.

Nick eterno derivado do MAC da placa de rede fisica:

    MAC (nunca sai do computador)
      -> scrypt(MAC, sal fixo do HOLO)       hash lento: dificulta voltar do nick ao MAC
      -> 32 bytes -> palavra + palavra + 4 hex  ex.: "KuroiRonin-7F3A"

O MAC e publico na rede local, entao ele NAO serve como senha. A posse do
nick e provada por uma chave Ed25519 gerada aleatoriamente neste computador
(guardada em ~/.config/arasaka-holo/identity.key). O servidor associa
nick -> chave publica na primeira conexao (TOFU) e nunca mais aceita outra.
Faca backup da chave (Configuracoes > Exportar identidade) para manter o
nick depois de reinstalar o sistema.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from nacl import pwhash
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey

APP_ID = "arasaka-holo"
NICK_SALT = b"ARASAKA//HOLO//NICK//v1"

ADJ = ("Kuroi Akai Shiro Neon Chrome Silent Ghost Iron Steel Crimson Void Static Hollow Vapor Razor Night Cyber "
       "Black Red Pale Sharp Cold Burnt Toxic Rogue Phantom Shadow Lunar Solar Quantum Hex Prime Feral Lucid Mute "
       "Grim Noir Rapid Zero Blind Arc Nova Echo Glitch Iso Fused Molten Frozen Wired Spectral Atomic Obsidian "
       "Scarlet Azure Onyx Ashen Ivory Rusted Electric Hyper Ultra Omega Delta Sigma Mirage").split()
NOUN = ("Ronin Oni Samurai Kitsune Tengu Shogun Ninja Daemon Netrunner Fixer Solo Nomad Techie Medic Corpo Ripper "
        "Wraith Specter Raven Viper Cobra Mantis Hornet Falcon Wolf Tiger Dragon Kraken Golem Cipher Vector Pulse "
        "Signal Circuit Kernel Socket Proxy Router Beacon Sentinel Warden Hunter Drifter Runner Phantom Reaper "
        "Monk Blade Katana Shuriken Lotus Sakura Koi Crane Moth Spider Hydra Titan Atlas Orion Vega Lynx").split()


# ================================================================ MAC
@dataclass
class Nic:
    name: str
    mac: str          # "aa:bb:cc:dd:ee:ff"
    wired: bool
    permanent: bool   # endereco de fabrica


def _norm(mac: str) -> str:
    h = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ""


def _usable(mac: str) -> bool:
    if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    first = int(mac[:2], 16)
    # bit 0x02 = endereco "administrado localmente" (MAC aleatorio / virtual); 0x01 = multicast
    return not (first & 0x02) and not (first & 0x01)


VIRTUAL = re.compile(r"virtual|vmware|virtualbox|hyper-v|vethernet|tap|tun|wintun|wireguard|vpn|bluetooth|"
                     r"loopback|docker|wsl|npcap|zerotier|tailscale|hamachi|teredo|isatap|kernel debug", re.I)


def _linux_nics() -> list[Nic]:
    out = []
    base = Path("/sys/class/net")
    if not base.is_dir():
        return out
    for dev in sorted(base.iterdir()):
        name = dev.name
        if name == "lo" or not (dev / "device").exists():       # sem 'device' = interface virtual
            continue
        if re.match(r"(veth|docker|br-|virbr|vmnet|vboxnet|tun|tap|wg|zt|tailscale)", name):
            continue
        mac = ""
        if shutil_which("ethtool"):
            try:
                r = subprocess.run(["ethtool", "-P", name], capture_output=True, text=True, timeout=3)
                mac = _norm(r.stdout.split(":", 1)[-1]) if "Permanent" in r.stdout else ""
            except Exception:
                mac = ""
        permanent = bool(mac)
        if not mac:
            try:
                mac = _norm((dev / "address").read_text())
            except OSError:
                continue
        wireless = (dev / "wireless").exists() or (dev / "phy80211").exists()
        out.append(Nic(name, mac, not wireless, permanent))
    return out


def _windows_nics() -> list[Nic]:
    out = []
    try:
        ps = ("Get-NetAdapter -Physical | Select-Object Name,InterfaceDescription,MacAddress,PermanentAddress,"
              "MediaType | ConvertTo-Json -Compress")
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        data = json.loads(r.stdout or "[]")
        if isinstance(data, dict):
            data = [data]
        for a in data:
            desc = f"{a.get('Name', '')} {a.get('InterfaceDescription', '')}"
            if VIRTUAL.search(desc):
                continue
            perm = _norm(a.get("PermanentAddress") or "")
            mac = perm or _norm(a.get("MacAddress") or "")
            wired = "802.3" in str(a.get("MediaType", "")) and not re.search(r"wi-?fi|wireless|802\.11", desc, re.I)
            out.append(Nic(a.get("Name", "?"), mac, wired, bool(perm)))
    except Exception:
        pass
    if not out:   # fallback: getmac
        try:
            r = subprocess.run(["getmac", "/v", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=10,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for line in r.stdout.splitlines():
                cols = [c.strip('"') for c in line.split('","')]
                if len(cols) >= 3 and not VIRTUAL.search(cols[0] + cols[1]):
                    out.append(Nic(cols[0], _norm(cols[2]), not re.search(r"wi-?fi|wireless", cols[1], re.I),
                                   False))
        except Exception:
            pass
    return out


def shutil_which(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None


def find_nics() -> list[Nic]:
    nics = _windows_nics() if sys.platform == "win32" else _linux_nics()
    return [n for n in nics if _usable(n.mac)]


def pick_mac(remembered_hash: str = "") -> tuple[str, str]:
    """Escolhe o MAC de forma deterministica. Retorna (mac, descricao)."""
    override = os.environ.get("ARASAKA_HOLO_MAC")   # apenas para testes
    if override:
        return _norm(override), "override (teste)"
    nics = find_nics()
    if not nics:
        return "", "nenhuma placa de rede fisica encontrada"
    if remembered_hash:
        for n in nics:
            if mac_hash(n.mac) == remembered_hash:
                return n.mac, n.name
    # regra fixa: cabeada primeiro, depois endereco de fabrica, depois o menor MAC
    nics.sort(key=lambda n: (not n.wired, not n.permanent, n.mac))
    n = nics[0]
    return n.mac, n.name


def mac_hash(mac: str) -> str:
    """Hash local do MAC (so para lembrar qual placa foi usada; nunca enviado)."""
    return hashlib.blake2b(bytes.fromhex(mac.replace(":", "")), digest_size=16,
                           person=b"holo-mac-pick").hexdigest()


def nick_from_mac(mac: str) -> str:
    raw = bytes.fromhex(mac.replace(":", ""))
    d = hashlib.scrypt(raw, salt=NICK_SALT, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    a = ADJ[int.from_bytes(d[0:2], "big") % len(ADJ)]
    b = NOUN[int.from_bytes(d[2:4], "big") % len(NOUN)]
    return f"{a}{b}-{d[4:6].hex().upper()}"


def fingerprint(pk: bytes) -> str:
    h = hashlib.blake2b(pk, digest_size=8).hexdigest().upper()
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


NICK_RE = re.compile(r"^[A-Z][A-Za-z]{2,24}[A-Z][A-Za-z]{1,24}-[0-9A-F]{4}$")


# ================================================================ identidade local
def config_dir() -> Path:
    if os.environ.get("ARASAKA_HOLO_HOME"):
        return Path(os.environ["ARASAKA_HOLO_HOME"])
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home())) / APP_ID
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_ID


class Identity:
    def __init__(self, nick: str, sk: SigningKey, source: str):
        self.nick = nick
        self.sk = sk
        self.source = source

    @property
    def vk(self) -> VerifyKey:
        return self.sk.verify_key

    @property
    def pk_b64(self) -> str:
        return base64.b64encode(bytes(self.vk)).decode()

    @property
    def fp(self) -> str:
        return fingerprint(bytes(self.vk))

    # export / import (backup da chave para manter o nick depois de reinstalar)
    def export(self, password: str | None = None) -> str:
        """Backup da chave. Com senha (formato 2): Argon2id + XSalsa20-Poly1305; sem senha (formato 1): texto puro."""
        plain = {"holo": 1, "nick": self.nick, "sk": base64.b64encode(bytes(self.sk)).decode()}
        if not password:
            return json.dumps(plain)
        salt = os.urandom(pwhash.argon2id.SALTBYTES)
        key = pwhash.argon2id.kdf(SecretBox.KEY_SIZE, password.encode("utf-8"), salt,
                                  opslimit=pwhash.argon2id.OPSLIMIT_MODERATE, memlimit=pwhash.argon2id.MEMLIMIT_MODERATE)
        box = SecretBox(key).encrypt(json.dumps(plain).encode("utf-8"))
        return json.dumps({"holo": 2, "nick": self.nick, "kdf": "argon2id-moderate",
                           "salt": base64.b64encode(salt).decode(), "box": base64.b64encode(bytes(box)).decode()})

    @staticmethod
    def key_path() -> Path:
        return config_dir() / "identity.key"


def _write_private(path: Path, data: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(data, encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)


def load_identity() -> Identity:
    """Carrega (ou cria) a identidade deste computador."""
    path = Identity.key_path()
    state = {}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    mac, source = pick_mac(state.get("mac_hash", ""))
    if mac:
        nick = nick_from_mac(mac)
    elif state.get("nick"):
        nick, source = state["nick"], "salvo (sem placa de rede)"
    else:
        # sem MAC utilizavel: nick aleatorio, salvo para sempre neste perfil
        nick = nick_from_mac(os.urandom(6).hex())
        source = "aleatorio (sem placa de rede fisica)"
    if state.get("sk") and state.get("nick") == nick:
        sk = SigningKey(base64.b64decode(state["sk"]))
    else:
        sk = SigningKey.generate()
    state.update({"holo": 1, "nick": nick, "sk": base64.b64encode(bytes(sk)).decode(),
                  "mac_hash": mac_hash(mac) if mac else ""})
    _write_private(path, json.dumps(state))
    return Identity(nick, sk, source)


def backup_needs_password(text: str) -> bool:
    try:
        return json.loads(text).get("holo") == 2
    except Exception:
        return False


def import_identity(text: str, password: str | None = None) -> Identity:
    d = json.loads(text)
    if d.get("holo") == 2:
        if not password:
            raise ValueError("esse backup tem senha")
        key = pwhash.argon2id.kdf(SecretBox.KEY_SIZE, password.encode("utf-8"), base64.b64decode(d["salt"]),
                                  opslimit=pwhash.argon2id.OPSLIMIT_MODERATE, memlimit=pwhash.argon2id.MEMLIMIT_MODERATE)
        try:
            d = json.loads(SecretBox(key).decrypt(base64.b64decode(d["box"])).decode("utf-8"))
        except CryptoError:
            raise ValueError("senha errada") from None
    if d.get("holo") != 1 or "sk" not in d or "nick" not in d:
        raise ValueError("arquivo de identidade invalido")
    sk = SigningKey(base64.b64decode(d["sk"]))
    path = Identity.key_path()
    state = {}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    state.update({"holo": 1, "nick": d["nick"], "sk": d["sk"]})
    _write_private(path, json.dumps(state))
    return Identity(d["nick"], sk, "importado")
