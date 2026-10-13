from __future__ import annotations

import io
import shutil
from pathlib import Path
from string import Template

from wgau.config import AppConfig, template_text
from wgau.errors import ClientNotFoundError
from wgau.models import KeyPair, Peer
from wgau.utils import atomic_write, atomic_write_bytes

try:
    import qrcode
except ImportError as e:
    raise RuntimeError("qrcode is not installed. Run: pip install 'qrcode[pil]'") from e

CLIENT_CONF_NAME = "client.conf"
CLIENT_TEMPLATE_NAME = "client.conf"


def render_client_conf(keys: KeyPair, client_ip: str,
                       server_public_key: str, app: AppConfig) -> str:
    template = Template(template_text(CLIENT_TEMPLATE_NAME))
    return template.substitute(
        private_key=keys.private_key,
        client_ip=client_ip,
        server_public_key=server_public_key,
        psk=keys.psk,
        endpoint=app.endpoint,
        dns=app.dns,
    )


def create_client_dir(clients_dir: Path, name: str) -> Path:
    client_dir = clients_dir / name
    client_dir.mkdir(parents=True, exist_ok=True)
    return client_dir


def delete_client_dir(client_dir: Path) -> None:
    shutil.rmtree(client_dir)


def write_keys(client_dir: Path, keys: KeyPair) -> None:
    atomic_write(client_dir / "sec.key", keys.private_key + "\n", mode=0o600)
    atomic_write(client_dir / "pub.key", keys.public_key + "\n", mode=0o600)
    atomic_write(client_dir / "psk.key", keys.psk + "\n", mode=0o600)


def write_peer_keys_from_wg0(client_dir: Path, peer: Peer) -> None:
    """sync: сохранить то, что wg0.conf знает о пире (приватного ключа там нет)."""
    if peer.public_key:
        atomic_write(client_dir / "pub.key", peer.public_key + "\n", mode=0o600)
    if peer.psk:
        atomic_write(client_dir / "psk.key", peer.psk + "\n", mode=0o600)


def write_client_conf(client_dir: Path, conf_text: str) -> Path:
    conf_path = client_dir / CLIENT_CONF_NAME
    atomic_write(conf_path, conf_text, mode=0o600)
    return conf_path


def read_client_conf(client_dir: Path) -> str:
    conf_path = client_dir / CLIENT_CONF_NAME
    if not conf_path.exists():
        raise ClientNotFoundError(
            f"{conf_path} not found — run 'wgau add' or 'wgau conf'"
        )
    return conf_path.read_text(encoding="utf-8")


def generate_qr_png(client_dir: Path, client_name: str, conf_text: str) -> Path:
    qr_path = client_dir / f"{client_name}.png"
    img = qrcode.make(conf_text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    atomic_write_bytes(qr_path, buf.getvalue(), mode=0o600)
    return qr_path


def print_qr_ascii(conf_text: str) -> None:
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        border=1,
    )
    qr.add_data(conf_text)
    qr.print_ascii(invert=True)