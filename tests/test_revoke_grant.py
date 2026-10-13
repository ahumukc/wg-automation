from pathlib import Path

import pytest

from wgau import service, wgconf
from wgau.config import AppConfig
from wgau.errors import ClientNotFoundError

WG0_TEXT = (
    "[Interface]\n"
    "PrivateKey = srv\n"
    "\n"
    "# BEGIN_PEER client1\n"
    "[Peer]\n"
    "PublicKey = a\n"
    "PresharedKey = psk1\n"
    "AllowedIPs = 10.7.0.2/32\n"
    "# END_PEER client1\n"
    "\n"
    "# BEGIN_PEER client2\n"
    "[Peer]\n"
    "PublicKey = b\n"
    "AllowedIPs = 10.7.0.3/32\n"
    "# END_PEER client2\n"
)


def make_app(tmp_path: Path) -> AppConfig:
    clients = tmp_path / "clients"
    clients.mkdir()
    (clients / "client1").mkdir()
    (clients / "client1" / "sec.key").write_text("priv1\n", encoding="utf-8")
    wg0 = tmp_path / "wg0.conf"
    wg0.write_text(WG0_TEXT, encoding="utf-8")
    return AppConfig(
        clients_dir=clients,
        trash_dir=tmp_path / "trash",
        wg_conf=wg0,
        endpoint="vpn.example.com:51820",
        dns="1.1.1.1",
        address_base="10.7.0",
        client_prefix="client",
    )


def get_peer(app: AppConfig, name: str):
    _, peers = wgconf.parse_wg0(app.wg_conf)
    return next(p for p in peers if p.name == name)


def test_revoke_comments_block(tmp_path, sync_stub):
    app = make_app(tmp_path)

    service.revoke_client(app, "client1")

    text = app.wg_conf.read_text(encoding="utf-8")
    assert "#[Peer]" in text
    assert "#PublicKey = a" in text
    assert "# BEGIN_PEER client1" in text
    assert "# END_PEER client1" in text
    assert "PublicKey = b" in text
    assert (app.clients_dir / "client1").exists()
    assert sync_stub.calls == [("wg0", app.wg_conf)]


def test_revoke_parses_revoked_peer(tmp_path, sync_stub):
    app = make_app(tmp_path)

    service.revoke_client(app, "client1")

    p1 = get_peer(app, "client1")
    p2 = get_peer(app, "client2")
    assert p1.revoked is True
    assert p1.public_key == "a"
    assert p1.psk == "psk1"
    assert p1.first_ip == "10.7.0.2"
    assert p2.revoked is False
    assert p2.public_key == "b"


def test_revoked_ip_stays_reserved(tmp_path, sync_stub):
    app = make_app(tmp_path)

    service.revoke_client(app, "client1")

    _, peers = wgconf.parse_wg0(app.wg_conf)
    assert service._used_suffixes(app, peers) == {2, 3}


def test_grant_restores_exact_content(tmp_path, sync_stub):
    app = make_app(tmp_path)
    service.revoke_client(app, "client1")
    sync_stub.calls.clear()

    service.grant_client(app, "client1")

    assert app.wg_conf.read_text(encoding="utf-8") == WG0_TEXT
    assert sync_stub.calls == [("wg0", app.wg_conf)]


def test_revoke_twice_is_noop(tmp_path, sync_stub):
    app = make_app(tmp_path)
    service.revoke_client(app, "client1")
    sync_stub.calls.clear()

    service.revoke_client(app, "client1")

    assert sync_stub.calls == []
    assert get_peer(app, "client1").revoked is True


def test_grant_active_peer_is_noop(tmp_path, sync_stub):
    app = make_app(tmp_path)

    service.grant_client(app, "client1")

    assert sync_stub.calls == []
    assert app.wg_conf.read_text(encoding="utf-8") == WG0_TEXT


def test_revoke_grant_not_found(tmp_path, sync_stub):
    app = make_app(tmp_path)

    with pytest.raises(ClientNotFoundError):
        service.revoke_client(app, "nope")
    with pytest.raises(ClientNotFoundError):
        service.grant_client(app, "nope")

    assert sync_stub.calls == []


def test_roundtrip_with_inner_comment(tmp_path, sync_stub):
    original = (
        "[Interface]\n"
        "PrivateKey = srv\n"
        "\n"
        "# BEGIN_PEER client1\n"
        "[Peer]\n"
        "# note = old\n"
        "PublicKey = a\n"
        "AllowedIPs = 10.7.0.2/32\n"
        "# END_PEER client1\n"
    )
    app = make_app(tmp_path)
    app.wg_conf.write_text(original, encoding="utf-8")

    service.revoke_client(app, "client1")

    assert "## note = old" in app.wg_conf.read_text(encoding="utf-8")
    p1 = get_peer(app, "client1")
    assert p1.revoked is True
    assert "note" not in p1.params

    service.grant_client(app, "client1")

    assert app.wg_conf.read_text(encoding="utf-8") == original
