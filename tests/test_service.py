from __future__ import annotations

import pytest

from wgau import service
from wgau.errors import (
    ClientNotFoundError,
    KeyMismatchError,
    NoFreeIPError,
    Wg0Error,
)

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