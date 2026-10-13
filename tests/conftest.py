from __future__ import annotations

from pathlib import Path

import pytest

from wgau import wg
from wgau.config import AppConfig
from wgau.models import KeyPair


@pytest.fixture()
def clients_dir(tmp_path: Path) -> Path:
    d = tmp_path / "clients"
    d.mkdir()
    return d


@pytest.fixture()
def wg0(tmp_path: Path) -> Path:
    """wg0.conf с валидным интерфейсом (PrivateKey = SERVER_SEC)."""
    p = tmp_path / "wg0.conf"
    p.write_text(
        "[Interface]\n"
        "PrivateKey = SERVER_SEC\n"
        "Address = 10.7.0.1/24\n"
        "ListenPort = 51820\n"
    )
    return p


@pytest.fixture()
def app(clients_dir: Path, wg0: Path) -> AppConfig:
    return AppConfig(
        clients_dir=clients_dir,
        trash_dir=clients_dir.parent / "trash",
        wg_conf=wg0,
        endpoint="vpn.example.com:51820",
        dns="1.1.1.1",
        address_base="10.7.0",
        client_prefix="client",
    )


@pytest.fixture()
def fake_wg(monkeypatch) -> KeyPair:
    """Подменяет вызовы бинарника `wg` детерминированными ключами."""
    keys = KeyPair(private_key="CLIENT_SEC", public_key="CLIENT_PUB", psk="CLIENT_PSK")

    def fake_derive(sec: str) -> str:
        return {
            "SERVER_SEC": "SERVER_PUB",   # ключ интерфейса сервера
            "CLIENT_SEC": "CLIENT_PUB",   # ключ клиента
        }[sec]

    monkeypatch.setattr(wg, "generate_keys", lambda: keys)
    monkeypatch.setattr(wg, "derive_public_key", fake_derive)
    return keys