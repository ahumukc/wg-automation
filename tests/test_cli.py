from __future__ import annotations

from pathlib import Path

import pytest

from wgau import cli, config, service
from wgau.errors import WgauError


def write_conf(path: Path, *, clients_dir: str, wg_conf: str) -> Path:
    path.write_text(
        "[General]\n"
        f"CLIENTS_FOLDER_PATH = {clients_dir}\n"
        f"WIREGUARD_CONFIG_FILE = {wg_conf}\n"
        "\n[Wireguard]\n"
        "ENDPOINT = vpn.example.com:51820\n"
        "ADDRESS_BASE = 10.7.0\n"
        "DNS_SERVER = 1.1.1.1\n"
        "\n[Naming]\n"
        "CLIENT_PREFIX = client\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture()
def conf_file(tmp_path: Path, app) -> Path:
    return write_conf(tmp_path / "wgau.conf",
                      clients_dir=str(app.clients_dir), wg_conf=str(app.wg_conf))


def stub(monkeypatch, app, tmp_path):
    """Путь к конфигу — tmp_path/wgau.conf; конфиг уже создан и валиден."""
    monkeypatch.setattr(config, "default_config_path",
                        lambda: tmp_path / "wgau.conf")
    monkeypatch.setattr(config, "ensure_config", lambda p: False)
    monkeypatch.setattr(config, "load_config", lambda p: app)


class TestParser:
    def test_add(self):
        assert cli.build_parser().parse_args(["add"]).command == "add"

    def test_show(self):
        args = cli.build_parser().parse_args(["show", "client7"])
        assert (args.command, args.client_name) == ("show", "client7")

    def test_conf(self):
        args = cli.build_parser().parse_args(["conf", "client7"])
        assert (args.command, args.client_name) == ("conf", "client7")

    def test_no_config_flag(self):
        # --config не существует — argparse должен отказаться парсить
        with pytest.raises(SystemExit) as excinfo:
            cli.build_parser().parse_args(["--config", "/tmp/x.conf", "add"])
        assert excinfo.value.code == 2

    def test_command_required(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args([])


class TestDispatch:
    def test_add(self, monkeypatch, app, tmp_path):
        stub(monkeypatch, app, tmp_path)
        seen = []
        monkeypatch.setattr(service, "add_client", seen.append)
        assert cli.main(["add"]) == 0
        assert seen == [app]

    def test_sync(self, monkeypatch, app, tmp_path, capsys):
        stub(monkeypatch, app, tmp_path)
        monkeypatch.setattr(service, "sync_folders", lambda a: 3)
        assert cli.main(["sync"]) == 0
        assert "Created 3 folder(s)" in capsys.readouterr().out

    def test_show(self, monkeypatch, app, tmp_path):
        stub(monkeypatch, app, tmp_path)
        seen = []
        monkeypatch.setattr(service, "show_qr", lambda a, name: seen.append(name))
        assert cli.main(["show", "client9"]) == 0
        assert seen == ["client9"]

    def test_conf(self, monkeypatch, app, tmp_path, capsys):
        stub(monkeypatch, app, tmp_path)
        monkeypatch.setattr(
            service, "make_conf_from_sec_key", lambda a, name: Path("/x/client.conf")
        )
        assert cli.main(["conf", "client9"]) == 0
        assert "Config generated: /x/client.conf" in capsys.readouterr().out

    def test_env_ignored(self, monkeypatch, app, tmp_path):
        # регрессия: WGAU_CONFIG больше не читается, путь — только дефолтный
        monkeypatch.setenv("WGAU_CONFIG", "/tmp/should-be-ignored.conf")
        monkeypatch.setattr(config, "default_config_path",
                            lambda: tmp_path / "right.conf")
        monkeypatch.setattr(config, "ensure_config", lambda p: False)
        loaded = []

        def fake_load(p):
            loaded.append(p)
            return app

        monkeypatch.setattr(config, "load_config", fake_load)
        monkeypatch.setattr(service, "add_client", lambda a: None)
        assert cli.main(["add"]) == 0
        assert loaded == [tmp_path / "right.conf"]

    def test_error_returns_1(self, monkeypatch, app, tmp_path, capsys):
        stub(monkeypatch, app, tmp_path)

        def boom(a):
            raise WgauError("something broke")

        monkeypatch.setattr(service, "add_client", boom)
        assert cli.main(["add"]) == 1
        assert "error: something broke" in capsys.readouterr().err

    def test_first_run_creates_config(self, monkeypatch, tmp_path, capsys):
        conf = tmp_path / "wgau.conf"
        monkeypatch.setattr(config, "default_config_path", lambda: conf)
        monkeypatch.setattr(config, "ensure_config", lambda p: True)

        def must_not_load(p):
            raise AssertionError("load_config не должен вызываться при первом запуске")

        monkeypatch.setattr(config, "load_config", must_not_load)
        assert cli.main(["add"]) == 0
        assert "Config was created" in capsys.readouterr().out


class TestEndToEnd:
    def test_add_creates_real_files(self, app, fake_wg, conf_file,
                                     monkeypatch, capsys):
        monkeypatch.setattr(config, "default_config_path", lambda: conf_file)
        assert cli.main(["add"]) == 0
        assert "Client client1 generated" in capsys.readouterr().out
        assert (app.clients_dir / "client1" / "client.conf").exists()
        assert "# BEGIN_PEER client1" in app.wg_conf.read_text()