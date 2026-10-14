from __future__ import annotations

from dataclasses import replace

import pytest

from wgau import db, service, wg, wgconf
from wgau.errors import (
    ClientNotFoundError,
    KeyMismatchError,
    NoFreeIPError,
    Wg0Error,
)
from wgau.models import KeyPair

WG0_ONE_PEER = (
    "[Interface]\n"
    "PrivateKey = SERVER_SEC\n"
    "Address = 10.7.0.1/24\n"
    "\n"
    "# BEGIN_PEER client1\n"
    "[Peer]\n"
    "PublicKey = OLD_PUB\n"
    "PresharedKey = OLD_PSK\n"
    "AllowedIPs = 10.7.0.2/32\n"
    "# END_PEER client1\n"
)


class TestAddClient:
    def test_full_cycle(self, app, fake_wg, capsys):
        service.add_client(app)

        client_dir = app.clients_dir / "client1"
        assert (client_dir / "sec.key").read_text() == "CLIENT_SEC\n"
        assert (client_dir / "pub.key").read_text() == "CLIENT_PUB\n"
        assert (client_dir / "psk.key").read_text() == "CLIENT_PSK\n"

        conf = (client_dir / "client.conf").read_text()
        assert "CLIENT_SEC" in conf
        assert "SERVER_PUB" in conf
        assert "CLIENT_PSK" in conf
        assert "10.7.0.2" in conf
        assert "vpn.example.com:51820" in conf

        assert (client_dir / "client1.png").exists()
        assert "Client client1 generated" in capsys.readouterr().out

        wg0 = app.wg_conf.read_text()
        assert "# BEGIN_PEER client1" in wg0
        assert "# END_PEER client1" in wg0
        assert "AllowedIPs = 10.7.0.2/32" in wg0

    def test_second_client_gets_next_name_and_ip(self, app, fake_wg):
        service.add_client(app)
        service.add_client(app)
        assert (app.clients_dir / "client2").is_dir()
        assert "AllowedIPs = 10.7.0.3/32" in app.wg_conf.read_text()

    def test_skips_busy_ip(self, app, fake_wg):
        app.wg_conf.write_text(WG0_ONE_PEER)
        service.add_client(app)
        assert "AllowedIPs = 10.7.0.3/32" in app.wg_conf.read_text()

    def test_skips_existing_folder_name(self, app, fake_wg):
        (app.clients_dir / "client1").mkdir()
        service.add_client(app)
        assert (app.clients_dir / "client2").is_dir()

    def test_no_free_ip(self, app, fake_wg):
        lines = ["[Interface]", "PrivateKey = SERVER_SEC"]
        for i in range(2, 255):
            lines += ["[Peer]", f"PublicKey = K{i}", f"AllowedIPs = 10.7.0.{i}/32"]
        app.wg_conf.write_text("\n".join(lines) + "\n")
        with pytest.raises(NoFreeIPError):
            service.add_client(app)
        assert "BEGIN_PEER" not in app.wg_conf.read_text()

    def test_no_interface_private_key_no_side_effects(self, app, fake_wg):
        app.wg_conf.write_text("[Interface]\nAddress = 10.7.0.1/24\n")
        with pytest.raises(Wg0Error):
            service.add_client(app)
        assert "BEGIN_PEER" not in app.wg_conf.read_text()
        assert not (app.clients_dir / "client1").exists()

    def test_db_row_created(self, app, fake_wg, sync_stub):
        service.add_client(app)

        rows = db.list_rows(app.db_path)
        assert len(rows) == 1
        r = rows[0]
        assert r["name"] == "client1"
        assert r["internal_ip"] == "10.7.0.2"
        assert r["public_key"] == "CLIENT_PUB"
        assert r["preshared_key"] == "CLIENT_PSK"
        assert r["status"] == "active"
        assert r["deleted_at"] == 0
        assert r["expires_at"] is None

    def test_db_failure_is_only_warning(self, app, fake_wg, sync_stub,
                                        capsys):
        broken = replace(app, db_path=app.clients_dir)  # директория, не файл
        service.add_client(broken)

        assert (broken.clients_dir / "client1" / "client.conf").exists()
        assert "warning: database not updated" in capsys.readouterr().err


class TestDbHistory:
    def test_delete_then_recreate_same_name(self, app, fake_wg, sync_stub,
                                            monkeypatch):
        app.wg_conf.write_text(WG0_ONE_PEER)  # client1 с OLD_PUB и IP .2
        service.sync_folders(app)
        assert len(db.list_rows(app.db_path)) == 1

        service.delete_client(app, "client1", assume_yes=True)

        rows = db.list_rows(app.db_path)
        assert len(rows) == 1
        assert rows[0]["status"] == "deleted"
        assert rows[0]["public_key"] == "OLD_PUB"
        assert rows[0]["deleted_at"] > 0

        # папки и пира client1 больше нет — имя свободно, ключи новые
        monkeypatch.setattr(wg, "generate_keys",
                            lambda: KeyPair("S2", "PUB2", "PSK2"))
        service.add_client(app)

        rows = db.list_rows(app.db_path)
        assert len(rows) == 2
        live = [r for r in rows if r["status"] == "active"]
        history = [r for r in rows if r["status"] == "deleted"]
        assert len(live) == 1 and len(history) == 1
        assert live[0]["name"] == "client1"
        assert live[0]["public_key"] == "PUB2"
        assert live[0]["internal_ip"] == "10.7.0.2"  # IP переиспользован
        assert history[0]["name"] == "client1"
        assert history[0]["public_key"] == "OLD_PUB"

    def test_sync_archives_manually_removed_peer(self, app, fake_wg,
                                                  monkeypatch, sync_stub):
        # wg genkey всегда уникален — повторяем это в фикстуре
        keys = iter([KeyPair("S1", "PUB1", "PSK1"),
                     KeyPair("S2", "PUB2", "PSK2")])
        monkeypatch.setattr(wg, "generate_keys", lambda: next(keys))
        service.add_client(app)
        service.add_client(app)
        assert len(db.list_rows(app.db_path)) == 2

        wgconf.remove_peer(app.wg_conf, "client2")  # ручное удаление блока
        service.sync_folders(app)

        rows = {r["name"]: r for r in db.list_rows(app.db_path)}
        assert rows["client1"]["status"] == "active"
        assert rows["client1"]["public_key"] == "PUB1"
        assert rows["client2"]["status"] == "deleted"
        assert rows["client2"]["public_key"] == "PUB2"
        assert rows["client2"]["deleted_at"] > 0


class TestSyncFolders:
    def test_unnamed_peers_get_markers_and_folders(self, app):
        app.wg_conf.write_text(
            "[Interface]\nPrivateKey = SERVER_SEC\n\n"
            "[Peer]\nPublicKey = AAA\nPresharedKey = PSA\nAllowedIPs = 10.7.0.2/32\n\n"
            "[Peer]\nPublicKey = BBB\nPresharedKey = PSB\nAllowedIPs = 10.7.0.3/32\n"
        )
        assert service.sync_folders(app) == 2

        # регрессия «+1»: первый безымянный пир — client1, а не client2
        assert (app.clients_dir / "client1").is_dir()
        assert (app.clients_dir / "client2").is_dir()
        assert (app.clients_dir / "client1" / "pub.key").read_text() == "AAA\n"
        assert (app.clients_dir / "client1" / "psk.key").read_text() == "PSA\n"
        assert (app.clients_dir / "client2" / "pub.key").read_text() == "BBB\n"

        wg0 = app.wg_conf.read_text()
        assert "# BEGIN_PEER client1\n" in wg0
        assert "# BEGIN_PEER client2\n" in wg0

    def test_named_peers_no_rewrite(self, app):
        app.wg_conf.write_text(WG0_ONE_PEER)
        before = app.wg_conf.read_text()
        assert service.sync_folders(app) == 1
        assert app.wg_conf.read_text() == before
        assert (app.clients_dir / "client1").is_dir()

    def test_existing_folder_skipped(self, app):
        app.wg_conf.write_text(WG0_ONE_PEER)
        sentinel = app.clients_dir / "client1"
        sentinel.mkdir()
        (sentinel / "keep.txt").write_text("keep")
        assert service.sync_folders(app) == 0
        assert (sentinel / "keep.txt").read_text() == "keep"

    def test_idempotent(self, app):
        app.wg_conf.write_text(
            "[Interface]\nPrivateKey = SERVER_SEC\n\n"
            "[Peer]\nPublicKey = AAA\nAllowedIPs = 10.7.0.2/32\n"
        )
        service.sync_folders(app)
        snapshot = app.wg_conf.read_text()
        assert service.sync_folders(app) == 0
        assert app.wg_conf.read_text() == snapshot


class TestShowQr:
    def test_prints_qr(self, app, capsys):
        d = app.clients_dir / "client1"
        d.mkdir()
        (d / "client.conf").write_text("[Interface]\nPrivateKey = x\n")
        service.show_qr(app, "client1")
        assert capsys.readouterr().out.strip()

    def test_unknown_client(self, app):
        with pytest.raises(ClientNotFoundError):
            service.show_qr(app, "nope")


class TestMakeConfFromSecKey:
    def prepare(self, app, *, pub="CLIENT_PUB"):
        app.wg_conf.write_text(
            "[Interface]\nPrivateKey = SERVER_SEC\n\n"
            "# BEGIN_PEER client1\n"
            "[Peer]\n"
            "PublicKey = CLIENT_PUB\n"
            "PresharedKey = PSK1\n"
            "AllowedIPs = 10.7.0.7/32\n"
            "# END_PEER client1\n"
        )
        d = app.clients_dir / "client1"
        d.mkdir()
        (d / "sec.key").write_text("CLIENT_SEC\n")
        (d / "pub.key").write_text(pub + "\n")
        return d

    def test_happy_path(self, app, fake_wg):
        d = self.prepare(app)
        path = service.make_conf_from_sec_key(app, "client1")
        text = path.read_text()
        assert "CLIENT_SEC" in text
        assert "SERVER_PUB" in text
        assert "PSK1" in text
        assert "10.7.0.7" in text
        assert (d / "client1.png").exists()

    def test_key_mismatch(self, app, fake_wg):
        self.prepare(app, pub="OTHER_PUB")
        with pytest.raises(KeyMismatchError):
            service.make_conf_from_sec_key(app, "client1")

    def test_missing_sec_key(self, app, fake_wg):
        self.prepare(app)
        (app.clients_dir / "client1" / "sec.key").unlink()
        with pytest.raises(ClientNotFoundError):
            service.make_conf_from_sec_key(app, "client1")

    def test_peer_not_in_wg0(self, app, fake_wg):
        self.prepare(app)
        app.wg_conf.write_text("[Interface]\nPrivateKey = SERVER_SEC\n")
        with pytest.raises(ClientNotFoundError):
            service.make_conf_from_sec_key(app, "client1")

    def test_peer_without_allowed_ips(self, app, fake_wg):
        self.prepare(app)
        app.wg_conf.write_text(
            "[Interface]\nPrivateKey = SERVER_SEC\n\n"
            "# BEGIN_PEER client1\n[Peer]\nPublicKey = CLIENT_PUB\n# END_PEER client1\n"
        )
        with pytest.raises(Wg0Error):
            service.make_conf_from_sec_key(app, "client1")