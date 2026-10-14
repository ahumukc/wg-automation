from __future__ import annotations

import configparser
import os
import re
from dataclasses import dataclass
from pathlib import Path

from wgau.errors import ConfigError, Wg0Error
from wgau.utils import atomic_write

CONFIG_NAME = "wgau.conf"


@dataclass(frozen=True)
class AppConfig:
    clients_dir: Path
    trash_dir: Path
    wg_conf: Path
    db_path: Path
    endpoint: str
    dns: str
    address_base: str
    client_prefix: str


def default_config_path() -> Path:
    return Path("/etc/wgau/wgau.conf")


TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def template_text(name: str) -> str:
    path = TEMPLATES_DIR / name
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise ConfigError(f"Template '{name}' not found in {TEMPLATES_DIR}") from e


def ensure_config(path: Path) -> bool:
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, template_text(CONFIG_NAME), mode=0o644)
    return True


def load_config(path: Path) -> AppConfig:
    parser = configparser.ConfigParser()
    try:
        with path.open(encoding="utf-8") as f:
            parser.read_file(f)
    except OSError as e:
        raise ConfigError(f"Cannot read {path}: {e}") from e

    try:
        clients_dir = Path(parser["General"]["CLIENTS_FOLDER_PATH"]).expanduser()
        wg_conf = Path(parser["General"]["WIREGUARD_CONFIG_FILE"]).expanduser()
        endpoint = parser["Wireguard"]["ENDPOINT"].strip()
        address_base = parser["Wireguard"]["ADDRESS_BASE"].strip()
        dns = parser["Wireguard"]["DNS_SERVER"].strip()
        client_prefix = parser["Naming"]["CLIENT_PREFIX"].strip()
    except KeyError as e:
        raise ConfigError(f"Missing option {e} in {path}") from e

    trash_raw = parser["General"].get("TRASH_FOLDER_PATH", "").strip()
    trash_dir = (
        Path(trash_raw).expanduser()
        if trash_raw
        else clients_dir.parent / "trash"
    )
    db_raw = parser["General"].get("DATABASE_PATH", "").strip()

    if not clients_dir.is_absolute():
        raise ConfigError(f"CLIENTS_FOLDER_PATH must be absolute, got: {clients_dir}")
    if not wg_conf.is_absolute():
        raise ConfigError(f"WIREGUARD_CONFIG_FILE must be absolute, got: {wg_conf}")
    if not trash_dir.is_absolute():
        raise ConfigError(f"TRASH_FOLDER_PATH must be absolute, got: {trash_dir}")

    db_path = Path(db_raw).expanduser() if db_raw else clients_dir.parent / "wgau.db"
    if not db_path.is_absolute():
        raise ConfigError(f"DATABASE_PATH must be absolute, got: {db_path}")

    clients_dir = clients_dir.resolve()
    trash_dir = trash_dir.resolve()
    wg_conf = wg_conf.resolve()
    db_path = db_path.resolve()

    if not re.fullmatch(r"\d+\.\d+\.\d+", address_base):
        raise ConfigError(f"ADDRESS_BASE must look like '10.7.0', got: {address_base}")
    if not wg_conf.exists():
        raise Wg0Error(f"WireGuard config not found: {wg_conf}")

    return AppConfig(
        clients_dir=clients_dir,
        trash_dir=trash_dir,
        wg_conf=wg_conf,
        db_path=db_path,
        endpoint=endpoint,
        dns=dns,
        address_base=address_base,
        client_prefix=client_prefix,
    )