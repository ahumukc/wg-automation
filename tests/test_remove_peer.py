import os
from pathlib import Path

import pytest

from wgau import service, wg as wg_module, wgconf
from wgau.config import AppConfig
from wgau.errors import ClientNotFoundError, PermissionDeniedError

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


class SyncStub:
    def __init__(self):
        self.calls = []

    def __call__(self, interface: str, conf_path: Path) -> None:
        self.calls.append((interface, conf_path))


@pytest.fixture
def sync_stub(monkeypatch) -> SyncStub:
    stub = SyncStub()
    monkeypatch.setattr(wg_module, "syncconf", stub)
    return stub


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


def test_remove_peer_returns_block(tmp_path: Path) -> None:
    wg0 = tmp_path / "wg0.conf"
    wg0.write_text(WG0_TEXT, encoding="utf-8")

    block = wgconf.remove_peer(wg0, "client1")

    assert block is not None
    assert "# BEGIN_PEER client1" in block
    assert "# END_PEER client1" in block
    text = wg0.read_text(encoding="utf-8")
    assert "client1" not in text
    assert "client2" in text
    assert "\n\n\n" not in text


def test_remove_peer_missing(tmp_path: Path) -> None:
    wg0 = tmp_path / "wg0.conf"
    wg0.write_text(WG0_TEXT, encoding="utf-8")
    before = wg0.read_text(encoding="utf-8")

    assert wgconf.remove_peer(wg0, "missing") is None
    assert wg0.read_text(encoding="utf-8") == before


def test_delete_moves_to_trash(tmp_path: Path, sync_stub: SyncStub) -> None:
    app = make_app(tmp_path)

    service.delete_client(app, "client1", assume_yes=True)

    assert "client1" not in app.wg_conf.read_text(encoding="utf-8")
    assert "client2" in app.wg_conf.read_text(encoding="utf-8")
    assert not (app.clients_dir / "client1").exists()

    entries = list(app.trash_dir.iterdir())
    assert len(entries) == 1
    dest = entries[0]
    assert dest.name.startswith("client1.")
    assert (dest / "client1" / "sec.key").exists()
    peer_block = (dest / "peer.block").read_text(encoding="utf-8")
    assert "# BEGIN_PEER client1" in peer_block

    assert sync_stub.calls == [("wg0", app.wg_conf)]


def test_delete_permanently(tmp_path: Path, sync_stub: SyncStub) -> None:
    app = make_app(tmp_path)

    service.delete_client(app, "client1", assume_yes=True, permanently=True)

    assert "client1" not in app.wg_conf.read_text(encoding="utf-8")
    assert not (app.clients_dir / "client1").exists()
    assert not app.trash_dir.exists()
    assert sync_stub.calls == [("wg0", app.wg_conf)]


def test_delete_cancelled(tmp_path: Path, sync_stub: SyncStub,
                          monkeypatch) -> None:
    app = make_app(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _: "n")

    service.delete_client(app, "client1")

    assert "client1" in app.wg_conf.read_text(encoding="utf-8")
    assert (app.clients_dir / "client1").exists()
    assert not app.trash_dir.exists()
    assert sync_stub.calls == []


def test_delete_not_found(tmp_path: Path, sync_stub: SyncStub) -> None:
    app = make_app(tmp_path)

    with pytest.raises(ClientNotFoundError):
        service.delete_client(app, "nope", assume_yes=True)

    assert sync_stub.calls == []


def test_delete_invalid_name(tmp_path: Path) -> None:
    app = make_app(tmp_path)

    for bad in ("../evil", "a/b", ""):
        with pytest.raises(ClientNotFoundError):
            service.delete_client(app, bad, assume_yes=True)


def test_delete_folder_only(tmp_path: Path, sync_stub: SyncStub) -> None:
    app = make_app(tmp_path)
    (app.clients_dir / "ghost").mkdir()

    service.delete_client(app, "ghost", assume_yes=True)

    assert not (app.clients_dir / "ghost").exists()
    entries = list(app.trash_dir.iterdir())
    assert len(entries) == 1
    assert (entries[0] / "ghost").is_dir()
    assert not (entries[0] / "peer.block").exists()
    assert sync_stub.calls == []


def _deny_access(monkeypatch, denied: set) -> None:
    real_access = os.access
    monkeypatch.setattr(
        os, "access",
        lambda p, m: real_access(p, m) and Path(p) not in denied,
    )


def test_delete_denied_before_any_mutation(tmp_path: Path,
                                           sync_stub: SyncStub,
                                           monkeypatch) -> None:
    app = make_app(tmp_path)
    _deny_access(monkeypatch, {
        app.wg_conf, app.wg_conf.parent,
        app.clients_dir, app.clients_dir / "client1", app.trash_dir,
    })
    before = app.wg_conf.read_text(encoding="utf-8")

    with pytest.raises(PermissionDeniedError) as excinfo:
        service.delete_client(app, "client1", assume_yes=True)

    assert "sudo" in str(excinfo.value)
    assert app.wg_conf.read_text(encoding="utf-8") == before
    assert (app.clients_dir / "client1").exists()
    assert not app.trash_dir.exists()
    assert sync_stub.calls == []


def test_delete_denied_folder_only_checks_trash(tmp_path: Path,
                                                sync_stub: SyncStub,
                                                monkeypatch) -> None:
    app = make_app(tmp_path)
    (app.clients_dir / "ghost").mkdir()
    _deny_access(monkeypatch, {
        app.clients_dir, app.clients_dir / "ghost", app.trash_dir,
    })

    with pytest.raises(PermissionDeniedError):
        service.delete_client(app, "ghost", assume_yes=True)

    assert (app.clients_dir / "ghost").exists()
    assert not app.trash_dir.exists()
    assert sync_stub.calls == []

