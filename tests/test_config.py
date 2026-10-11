from __future__ import annotations

from pathlib import Path

import pytest

from wgau.config import default_config_path, ensure_config, load_config, template_text
from wgau.errors import ConfigError, Wg0Error


def write_conf(path: Path, *, clients_dir: str, wg_conf: str,
               endpoint: str = "vpn.example.com:51820",
               address_base: str = "10.7.0",
               dns: str = "1.1.1.1",
               prefix: str = "client") -> Path:
    path.write_text(
        "[General]\n"
        f"CLIENTS_FOLDER_PATH = {clients_dir}\n"
        f"WIREGUARD_CONFIG_FILE = {wg_conf}\n"
        "\n[Wireguard]\n"
        f"ENDPOINT = {endpoint}\n"
        f"ADDRESS_BASE = {address_base}\n"
        f"DNS_SERVER = {dns}\n"
        "\n[Naming]\n"
        f"CLIENT_PREFIX = {prefix}\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture()
def paths(tmp_path: Path):
    wg0 = tmp_path / "wg0.conf"
    wg0.write_text("[Interface]\nPrivateKey = s\n", encoding="utf-8")
    conf = write_conf(tmp_path / "wgau.conf",
                      clients_dir=str(tmp_path / "clients"), wg_conf=str(wg0))
    return conf, wg0


class TestLoadConfig:
    def test_ok(self, paths):
        conf, wg0 = paths
        app = load_config(conf)
        assert app.clients_dir == conf.parent / "clients"
        assert app.wg_conf == wg0
        assert app.endpoint == "vpn.example.com:51820"
        assert app.dns == "1.1.1.1"
        assert app.address_base == "10.7.0"
        assert app.client_prefix == "client"

    def test_missing_option(self, paths):
        conf, _ = paths
        text = conf.read_text().replace("ENDPOINT = vpn.example.com:51820\n", "")
        conf.write_text(text)
        with pytest.raises(ConfigError):
            load_config(conf)

    def test_missing_section(self, paths):
        conf, _ = paths
        text = conf.read_text()
        conf.write_text(text[: text.index("[Naming]")])
        with pytest.raises(ConfigError):
            load_config(conf)

    @pytest.mark.parametrize("bad", ["10.7", "10.7.0.1", "10.7.0.0/24", "abc", ""])
    def test_bad_address_base(self, paths, bad):
        conf, wg0 = paths
        write_conf(conf, clients_dir=str(conf.parent / "clients"),
                   wg_conf=str(wg0), address_base=bad)
        with pytest.raises(ConfigError):
            load_config(conf)

    def test_relative_clients_dir(self, paths):
        conf, wg0 = paths
        write_conf(conf, clients_dir="clients", wg_conf=str(wg0))
        with pytest.raises(ConfigError):
            load_config(conf)

    def test_relative_wg_conf(self, paths):
        conf, _ = paths
        write_conf(conf, clients_dir=str(conf.parent / "clients"), wg_conf="wg0.conf")
        with pytest.raises(ConfigError):
            load_config(conf)

    def test_wg0_missing(self, paths):
        conf, wg0 = paths
        wg0.unlink()
        with pytest.raises(Wg0Error):
            load_config(conf)

    def test_config_missing(self, tmp_path):
        with pytest.raises(ConfigError):
            load_config(tmp_path / "nope.conf")


class TestEnsureConfig:
    def test_creates_from_template(self, tmp_path):
        path = tmp_path / "wgau.conf"
        assert ensure_config(path) is True
        assert path.read_text(encoding="utf-8") == template_text("wgau.conf")
        assert path.stat().st_mode & 0o777 == 0o644

    def test_existing_not_touched(self, tmp_path):
        path = tmp_path / "wgau.conf"
        path.write_text("[General]\n", encoding="utf-8")
        assert ensure_config(path) is False
        assert path.read_text() == "[General]\n"

    def test_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "deep" / "wgau.conf"
        assert ensure_config(path) is True
        assert path.exists()


def test_template_missing():
    with pytest.raises(ConfigError):
        template_text("no-such-template.txt")


def test_default_config_path():
    assert default_config_path() == Path("/etc/wgau/wgau.conf")