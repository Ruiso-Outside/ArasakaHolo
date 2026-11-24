"""
Testes de identidade, criptografia e servidor WebSocket.

    python tests/test_core.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
HOME = Path(tempfile.mkdtemp())
os.environ["ARASAKA_HOLO_HOME"] = str(HOME)            # nunca toca no perfil real

from nacl.secret import SecretBox                       # noqa: E402
from nacl.signing import SigningKey                     # noqa: E402

from arasaka_holo import crypto, identity, server       # noqa: E402
from arasaka_holo.identity import Identity, valid_nick  # noqa: E402
from arasaka_holo.net import HoloClient                 # noqa: E402

KEY = HOME / "identity.key"
MAC1, MAC2 = "00:11:22:33:44:55", "00:11:22:33:44:66"


def sk_of(path=KEY):
    return json.loads(path.read_text())["sk"]


def test_identity():
    os.environ["ARASAKA_HOLO_MAC"] = MAC1
    a = identity.load_identity()
    k = sk_of()
    backup = a.export("senha-forte-123")
    os.environ["ARASAKA_HOLO_MAC"] = MAC2              # trocou a placa de rede
    b = identity.load_identity()
    assert b.nick == a.nick and sk_of() == k, "trocar a placa nao pode trocar nick nem chave"

    KEY.unlink()                                       # outro PC, com outro nick
    c = identity.load_identity()
    assert c.nick != a.nick
    other = sk_of()
    try:
        identity.import_identity(backup, "errada")
        raise AssertionError("aceitou senha errada")
    except ValueError:
        pass
    assert sk_of() == other
    identity.import_identity(backup, "senha-forte-123")
    d = identity.load_identity()
    assert d.nick == a.nick and sk_of() == k, "a chave importada tem que sobreviver a reabertura"
    kept = [p for p in HOME.glob("identity-*.key") if sk_of(p) == other]
    assert kept, "a chave anterior tem que ficar guardada"

    KEY.write_text("{lixo")                            # arquivo corrompido: guarda e cria outro
    identity.load_identity()
    assert any(p.read_text() == "{lixo" for p in HOME.glob("identity-corrompida-*.key"))
    for bad in ('{"holo":1,"nick":"x","sk":"AA=="}', '{"holo":1,"nick":"KuroiRonin-7F3A","sk":"AA=="}', "[]x"):
        try:
            identity.import_identity(bad)
            raise AssertionError("importou lixo")
        except ValueError:
            pass
    assert valid_nick("KuroiRonin-7F3A")
    for n in ("KuroiRonin-7F3A\n", "KuroiRonin-7F3A ", "kuroiRonin-7F3A", "<b>Ronin-7F3A", "", None, 3):
        assert not valid_nick(n), repr(n)
    assert all(valid_nick(f"{x}{y}-0AF9") for x in identity.ADJ for y in identity.NOUN)
    print("  identidade: ok")


def old_payload(sk, nick, text):
    body = {"v": 1, "n": nick, "k": crypto.b64(bytes(sk.verify_key)), "t": text, "ts": int(time.time()), "ttl": 0, "id": "aa" * 8}
    return sk.sign(json.dumps(body).encode())


def test_crypto():
    a, b = SigningKey.generate(), SigningKey.generate()
    pa, pb = crypto.b64(bytes(a.verify_key)), crypto.b64(bytes(b.verify_key))
    na = "KuroiRonin-7F3A"
    k1, k2 = crypto.room_key("Lobby ", ""), crypto.room_key("lobby", "senha")
    assert k1 == crypto.room_key("lobby", "") and k1 != k2
    blob = crypto.seal_room(k1, a, na, "ola", 30)
    body = crypto.open_room(k1, blob)
    assert body["t"] == "ola" and body["ttl"] == 30 and body["n"] == na
    assert crypto.open_room(k2, blob) is None
    dm = crypto.seal_dm(a, na, pb, "segredo")
    assert crypto.open_dm(b, pa, dm)["t"] == "segredo"
    assert crypto.open_dm(a, pa, dm) is None and crypto.open_dm(b, pb, dm) is None

    # quem recebeu uma direta nao consegue publicar numa sala, nem levar de uma sala para outra
    signed_dm = crypto.Box(crypto.box_keys(b), crypto.box_pub(pa)).decrypt(crypto.ub64(dm))
    assert crypto.open_room(k1, crypto.b64(SecretBox(k1).encrypt(signed_dm))) is None
    signed_room = SecretBox(k1).decrypt(crypto.ub64(blob))
    assert crypto.open_room(k2, crypto.b64(SecretBox(k2).encrypt(signed_room))) is None
    # nem devolver para o autor como se ele tivesse mandado para si, nem passar para um terceiro
    c = SigningKey.generate()
    fwd = crypto.b64(crypto.Box(crypto.box_keys(b), crypto.box_pub(crypto.b64(bytes(c.verify_key)))).encrypt(signed_dm))
    assert crypto.open_dm(c, pb, fwd) is None and crypto.open_dm(c, pa, fwd) is None

    r = crypto.Replay(limit=3)
    assert r.fresh(body) and not r.fresh(body), "repeticao"
    assert r.on_time(body) and not r.on_time({**body, "ts": 5})
    try:
        crypto.open_room(k1, crypto.b64(SecretBox(k1).encrypt(old_payload(a, na, "velha"))))
        raise AssertionError("aceitou formato antigo")
    except crypto.OldMessage as e:
        assert e.nick == na
    # campos malformados de alguem com a chave da sala nao derrubam o app
    base = {"v": 2, "n": na, "k": pa, "c": crypto.room_ctx(k1), "t": "x", "ts": 1, "ttl": 0, "id": "a" * 16}
    for ch in ({"t": 5}, {"ts": "x"}, {"ts": True}, {"ttl": -1}, {"ttl": 1e9}, {"id": None}, {"n": na + "\n"}, {"d": 3}, {"k": 1},
               {"ts": 10 ** 30}, {"v": None}):
        s = a.sign(json.dumps({**base, **ch}).encode())
        assert crypto.open_room(k1, crypto.b64(SecretBox(k1).encrypt(s))) is None, ch
    for junk in (b"", b"x" * 64, b"x" * 64 + b"[]", b"x" * 64 + b"{}"):
        assert crypto.open_room(k1, crypto.b64(SecretBox(k1).encrypt(junk))) is None
    for junk in ("", "@@@", None, 5):
        assert crypto.open_room(k1, junk) is None and crypto.open_dm(b, pa, junk) is None
    assert crypto.valid_pk(pa) and not any(map(crypto.valid_pk, (None, "", "AA==", 3, "A" * 44)))

    # login preso ao endereco do servidor
    sig = crypto.auth_signature(a, "ch", na, "piphin.online")
    assert crypto.check_auth(pa, "ch", na, sig, "piphin.online")
    assert not crypto.check_auth(pa, "ch", na, sig, "servidor-mau.com")
    old = crypto.b64(a.sign(f"HOLO-AUTH|ch|{na}".encode()).signature)
    assert crypto.check_auth(pa, "ch", na, old, "h") and not crypto.check_auth(pa, "ch", na, old, "h", legacy=False)
    assert not crypto.check_auth("lixo", "ch", na, "lixo", "h")
    for u, h in (("https://Piphin.Online/", "piphin.online"), ("wss://a.com:443/x", "a.com"), ("ws://1.2.3.4:7077", "1.2.3.4:7077"),
                 ("ws://[::1]:7077", "::1:7077"), ("https://u:p@b.com:8443/", "b.com:8443")):
        assert crypto.url_host(u) == h, (u, crypto.url_host(u))
    print("  criptografia: ok")


def wait_for(events, pred, what, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        for e in list(events):
            if pred(e):
                return e
        time.sleep(0.05)
    raise AssertionError(f"{what}: nao chegou; recebidos: {events}"[:900])


def test_ws_server():
    loop, ready = asyncio.new_event_loop(), threading.Event()
    port = 17077
    box = {}

    def run():
        asyncio.set_event_loop(loop)
        box["stop"] = asyncio.Event()
        loop.run_until_complete(server.serve("127.0.0.1", port, HOME / "srv", quiet=True, stop=box["stop"], ready=ready.set,
                                             ice=lambda: server.ice_servers("stun:s:1", "turn:t:3478", "segredo")))
    threading.Thread(target=run, daemon=True).start()
    assert ready.wait(10)
    url = f"ws://127.0.0.1:{port}"
    ea, eb, ec = [], [], []
    a = HoloClient(url, Identity("KuroiRonin-7F3A", SigningKey.generate(), "t"), ea.append)
    b = HoloClient(url, Identity("AkaiShogun-01BC", SigningKey.generate(), "t"), eb.append)
    a.start()
    b.start()
    w = wait_for(ea, lambda e: e["op"] == "welcome", "a entrar")
    wait_for(eb, lambda e: e["op"] == "welcome", "b entrar")
    turn = w["ice"][1]
    assert w["ice"][0]["urls"] == ["stun:s:1"] and turn["username"].endswith(":holo") and len(turn["credential"]) == 28
    a.send({"op": "join", "room": "r"})
    wait_for(ea, lambda e: e["op"] == "joined", "sala a")
    b.send({"op": "join", "room": "r"})
    wait_for(ea, lambda e: e["op"] == "presence" and e["on"], "presenca")
    a.send({"op": "msg", "room": "r", "blob": "X"})
    wait_for(eb, lambda e: e["op"] == "msg" and e["blob"] == "X", "msg")
    b.send({"op": "dm", "to": a.ident.nick, "blob": "Y"})
    wait_for(ea, lambda e: e["op"] == "dm" and e["from_pk"] == b.ident.pk_b64, "dm")
    a.send({"op": "ice"})
    wait_for(ea, lambda e: e["op"] == "ice", "ice")
    thief = HoloClient(url, Identity("KuroiRonin-7F3A", SigningKey.generate(), "t"), ec.append)
    thief.start()
    wait_for(ec, lambda e: e.get("code") == "nick_taken", "nick de outro recusado")
    thief.stop()
    t0 = time.time()
    b.stop()
    wait_for(ea, lambda e: e["op"] == "presence" and not e["on"], "saida")
    a.stop()
    assert time.time() - t0 < 5
    loop.call_soon_threadsafe(box["stop"].set)
    print("  servidor WebSocket: ok")


if __name__ == "__main__":
    test_identity()
    test_crypto()
    test_ws_server()
    print("OK: nucleo")
