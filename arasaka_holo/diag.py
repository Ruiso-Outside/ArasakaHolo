"""
ARASAKA HOLO // diagnostico da conexao, passo a passo.

    arasaka-holo --diag        mostra no terminal

Nao usa a chave, nao entra no servidor e nao coloca no relatorio o seu nick, o seu IP nem o usuario do sistema.
"""
from __future__ import annotations

import platform
import re
import socket
import ssl
import time
import urllib.request
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

from . import net


def _hide(text: str) -> str:
    """Tira usuario e senha de enderecos (proxy) que aparecem em mensagens de erro."""
    return re.sub(r"//[^/@\s]+@", "//***@", str(text))[:200]


def run(url: str, step=lambda ok, name, info: None, version: str = "") -> str:
    """Executa os passos (chamando step a cada um) e devolve o relatorio para copiar."""
    lines = [f"ARASAKA HOLO {version} · {platform.system()} {platform.release()} · Python {platform.python_version()}",
             f"servidor: {_hide(url)}"]

    def say(ok, name, info=""):
        info = _hide(info)
        lines.append(f"{'OK  ' if ok else 'ERRO' if ok is False else 'INFO'} {name}{': ' + info if info else ''}")
        step(ok, name, info)

    def done():
        return "\n".join(lines)

    p = urlsplit(net.normalize_url(url))
    try:
        host, port = p.hostname or "", p.port or (443 if p.scheme in ("https", "wss") else 80)
    except ValueError:
        host, port = "", 0
    if not host or p.scheme not in ("http", "https", "ws", "wss"):
        say(False, "endereco", "invalido: confira em CONFIG > SERVIDOR")
        return done()
    if host in ("127.0.0.1", "localhost"):
        say(None, "endereco", "e o seu proprio PC (INICIAR SERVIDOR). A rede oficial e https://piphin.online/")

    proxy = {k: v for k, v in urllib.request.getproxies().items() if k in ("http", "https", "all")}
    used = bool(proxy) and not urllib.request.proxy_bypass(host)
    if used:
        say(None, "proxy do sistema", "ligado (" + ", ".join(sorted(set(proxy.values()))) + "). Se voce nao usa proxy, desligue "
            "em Configuracoes > Rede > Proxy")

    # ---------------------------------------------------------------- DNS
    addrs = []
    try:
        for fam, _t, _p, _c, sa in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            if (fam, sa) not in addrs:
                addrs.append((fam, sa))
        say(True, "DNS", f"{len(addrs)} endereco(s)")
    except OSError as e:
        say(None if used else False, "DNS", f"nao achou {host} ({e}). Troque o DNS para 1.1.1.1 ou confira a internet")
        if not used:
            return done()

    # ---------------------------------------------------------------- porta
    good = None
    for fam, sa in addrs:
        name = f"porta {port} por " + ("IPv6" if fam == socket.AF_INET6 else "IPv4")
        t0 = time.monotonic()
        try:
            with socket.socket(fam, socket.SOCK_STREAM) as s:
                s.settimeout(6)
                s.connect(sa)
            say(True, name, f"{(time.monotonic() - t0) * 1000:.0f} ms")
            good = good or (fam, sa)
        except OSError as e:
            say(None, name, f"nao conectou ({e})")
    if not good and not used:
        say(False, "conexao", "bloqueada: feche VPN (Radmin, Hamachi...), libere o Holo no antivirus e no firewall, ou teste "
            "outra rede (4G do celular)")
        return done()

    # ---------------------------------------------------------------- TLS
    if good and p.scheme in ("https", "wss"):
        try:
            with socket.socket(good[0], socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect(good[1])
                with net.tls_context().wrap_socket(s, server_hostname=host) as t:
                    say(True, "certificado", t.version() or "")
        except ssl.SSLCertVerificationError as e:
            say(False, "certificado", f"{e.verify_message}. Acerte a data e a hora do Windows. Se o antivirus inspeciona HTTPS, "
                "crie uma excecao para o Holo")
        except OSError as e:
            say(False, "TLS", f"{e}. VPN, antivirus ou a rede esta cortando a conexao segura")

    # ---------------------------------------------------------------- relay
    if p.scheme in ("ws", "wss"):
        say(None, "relay", "servidor WebSocket: a porta foi testada, o login so no app")
        return done()
    try:
        r, date = net.request(net.normalize_url(url), {"op": "hello"}, 20)
    except net.NotHttpRelay as e:
        say(False, "relay", f"respondeu uma pagina em vez do relay ({e}). Pode ser a protecao da hospedagem, o portal do Wi-Fi ou "
            "um endereco errado")
        return done()
    except Exception as e:  # noqa: BLE001
        say(False, "relay", f"{net.friendly_error(e)} [{type(e).__name__}]")
        return done()
    if not isinstance(r, dict) or r.get("op") != "hello":
        say(False, "relay", str(r.get("msg") if isinstance(r, dict) else r))
        return done()
    say(True, "relay", "respondeu")
    if r.get("auth") != 2:
        say(False, "versao do servidor", "antiga: o index.php precisa ser atualizado")
    if date:
        try:
            diff = time.time() - parsedate_to_datetime(date).timestamp()
            say(None if abs(diff) > 120 else True, "relogio",
                f"{diff:+.0f} s em relacao ao servidor" + (". Acerte a data e a hora" if abs(diff) > 120 else ""))
        except (TypeError, ValueError):
            pass
    t0 = time.monotonic()
    from . import crypto
    crypto.solve_pow(f"diagnostico{t0}", "x", "y", min(18, int(r.get("pow", 18))))
    say(True, "prova de trabalho", f"{time.monotonic() - t0:.1f} s")
    say(True, "resultado", "a rede esta boa. Se o app ainda nao entra, mande este relatorio junto com o erro da tela")
    return done()
