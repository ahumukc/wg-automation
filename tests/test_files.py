from __future__ import annotations

from pathlib import Path

import pytest

from wgau import files
from wgau.config import AppConfig
from wgau.errors import ClientNotFoundError
from wgau.models import KeyPair, Peer

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def make_client_dir(tmp_path: Path) -> Path:
    d = tmp_path / "client1"
    d.mkdir()
    return d


class TestRenderClientConf:
    def test_substitutes_all_values(self, app: AppConfig):
        text = files.render_client_conf(
            KeyPair("SEC", "PUB", "PSK"), "10.7.0.2", "SRVPUB", app
        )
        assert "SEC" in text
        assert "SRVPUB" in text
        assert "PSK" in text
        assert "10.7.0.2" in text
        assert "vpn.example.com:51820" in text
        assert "1.1.1.1" in text
        assert "$" not in text  # все плейсхолдеры заполнены


class TestWriteKeys:
    def test_contents_and_modes(self, tmp_path: Path):
        d = make_client_dir(tmp_path)
        files.write_keys(d, KeyPair("SEC", "PUB", "PSK"))
        assert (d / "sec.key").read_text() == "SEC\n"
        assert (d / "pub.key").read_text() == "PUB\n"
        assert (d / "psk.key").read_text() == "PSK\n"
        for name in ("sec.key", "pub.key", "psk.key"):
            assert (d / name).stat().st_mode & 0o777 == 0o600


class TestWritePeerKeysFromWg0:
    def test_writes_pub_and_psk(self, tmp_path: Path):
        d = make_client_dir(tmp_path)
        files.write_peer_keys_from_wg0(
            d, Peer(params={"PublicKey": "PUB", "PresharedKey": "PSK"})
        )
        assert (d / "pub.key").read_text() == "PUB\n"
        assert (d / "psk.key").read_text() == "PSK\n"

    def test_partial(self, tmp_path: Path):
        d = make_client_dir(tmp_path)
        files.write_peer_keys_from_wg0(d, Peer(params={"PublicKey": "PUB"}))
        assert (d / "pub.key").exists()
        assert not (d / "psk.key").exists()

    def test_empty_peer_writes_nothing(self, tmp_path: Path):
        d = make_client_dir(tmp_path)
        files.write_peer_keys_from_wg0(d, Peer())
        assert list(d.iterdir()) == []


class TestClientConf:
    def test_write_returns_path_0600(self, tmp_path: Path):
        d = make_client_dir(tmp_path)
        path = files.write_client_conf(d, "[Interface]\n")
        assert path == d / "client.conf"
        assert path.read_text() == "[Interface]\n"
        assert path.stat().st_mode & 0o777 == 0o600

    def test_read_missing_raises(self, tmp_path: Path):
        with pytest.raises(ClientNotFoundError):
            files.read_client_conf(make_client_dir(tmp_path))


class TestQR:
    def test_png_created(self, tmp_path: Path):
        d = make_client_dir(tmp_path)
        path = files.generate_qr_png(d, "client1", "some conf text")
        assert path == d / "client1.png"
        assert path.read_bytes()[:8] == PNG_MAGIC
        assert path.stat().st_mode & 0o777 == 0o600  # требует патча атомарного PNG

    def test_ascii_printed_to_stdout(self, capsys):
        files.print_qr_ascii("https://example.com/wgau")
        out = capsys.readouterr().out
        assert out.strip()
        assert len(out.splitlines()) > 3