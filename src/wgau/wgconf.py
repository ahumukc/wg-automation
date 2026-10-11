from __future__ import annotations

import re
from pathlib import Path

from wgau.errors import PeerExistsError, Wg0Error
from wgau.models import Peer, WgInterface
from wgau.utils import atomic_write

BEGIN_PEER_RE = re.compile(r"#\s*BEGIN_PEER\s+(\S+)")
END_PEER_RE = re.compile(r"#\s*END_PEER\s+(\S+)")


def parse_wg0(path: Path) -> tuple[WgInterface, list[Peer]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        raise Wg0Error(f"Cannot read {path}: {e}") from e

    interface = WgInterface()
    peers: list[Peer] = []
    current: WgInterface | Peer | None = None

    for line in lines:
        stripped = line.strip()

        if (m := BEGIN_PEER_RE.fullmatch(stripped)):
            current = Peer(name=m.group(1))
            peers.append(current)
            continue
        if END_PEER_RE.fullmatch(stripped):
            current = None
            continue
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            if section == "Interface":
                current = interface
            elif section == "Peer":
                if not (isinstance(current, Peer) and not current.params):
                    current = Peer(name=None)
                    peers.append(current)
            else:
                current = None
            continue

        if "=" in stripped and current is not None:
            key, _, value = stripped.partition("=")
            current.params[key.strip()] = value.strip()

    return interface, peers


def build_peer_block(name: str, public_key: str, psk: str, client_ip: str) -> str:
    return (
        f"# BEGIN_PEER {name}\n"
        f"[Peer]\n"
        f"PublicKey = {public_key}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {client_ip}/32\n"
        f"# END_PEER {name}\n"
    )


def add_peer(path: Path, name: str, public_key: str,
             psk: str, client_ip: str) -> None:
    content = path.read_text(encoding="utf-8")
    if f"# BEGIN_PEER {name}\n" in content:
        raise PeerExistsError(f"Peer {name} already exists in {path}")
    block = build_peer_block(name, public_key, psk, client_ip)
    mode = path.stat().st_mode & 0o777
    atomic_write(path, content.rstrip("\n") + "\n\n" + block, mode=mode)