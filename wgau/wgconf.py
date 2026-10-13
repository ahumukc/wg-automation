from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from wgau.errors import ClientNotFoundError, PeerExistsError, Wg0Error
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
        if not stripped:
            continue

        if stripped.startswith("#"):
            if isinstance(current, Peer) and current.name is not None:
                content = stripped[1:].strip()
                if content and not content.startswith("#"):
                    if content == "[Peer]" and not current.params:
                        current.revoked = True
                    elif current.revoked and "=" in content:
                        key, _, value = content.partition("=")
                        current.params[key.strip()] = value.strip()
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


def remove_peer(path: Path, name: str) -> str | None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        raise Wg0Error(f"Cannot read {path}: {e}") from e

    out: list[str] = []
    block: list[str] = []
    removing = False
    removed = False
    skip_blank = False

    for line in lines:
        stripped = line.strip()

        if removing:
            m = END_PEER_RE.fullmatch(stripped)
            if m and m.group(1) == name:
                block.append(f"# END_PEER {name}")
                removing = False
                skip_blank = True
                continue
            if m or BEGIN_PEER_RE.fullmatch(stripped):
                raise Wg0Error(
                    f"Malformed {path}: unexpected marker {stripped!r} "
                    f"inside '# BEGIN_PEER {name}' block"
                )
            block.append(line)
            continue

        m = BEGIN_PEER_RE.fullmatch(stripped)
        if m and m.group(1) == name:
            block.append(f"# BEGIN_PEER {name}")
            removing = True
            removed = True
            continue

        if skip_blank:
            skip_blank = False
            if not stripped:
                continue

        out.append(line)

    if removing:
        raise Wg0Error(
            f"Malformed {path}: '# BEGIN_PEER {name}' without matching END_PEER"
        )

    if not removed:
        return None

    mode = path.stat().st_mode & 0o777
    atomic_write(path, "\n".join(out).rstrip("\n") + "\n", mode=mode)
    return "\n".join(block)


def set_peer_revoked(path: Path, name: str, revoked: bool) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        raise Wg0Error(f"Cannot read {path}: {e}") from e

    out: list[str] = []
    inside = False
    found = False

    for line in lines:
        stripped = line.strip()

        if not inside:
            m = BEGIN_PEER_RE.fullmatch(stripped)
            if m and m.group(1) == name:
                inside = True
                found = True
            out.append(line)
            continue

        m = END_PEER_RE.fullmatch(stripped)
        if m:
            if m.group(1) != name:
                raise Wg0Error(
                    f"Malformed {path}: expected '# END_PEER {name}', "
                    f"got {stripped!r}"
                )
            inside = False
            out.append(line)
            continue
        if BEGIN_PEER_RE.fullmatch(stripped):
            raise Wg0Error(
                f"Malformed {path}: unexpected marker {stripped!r} "
                f"inside '# BEGIN_PEER {name}' block"
            )

        if not stripped:
            out.append(line)
            continue

        if revoked:
            out.append("#" + line)
        elif stripped.startswith("#"):
            idx = line.find("#")
            out.append(line[:idx] + line[idx + 1:])
        else:
            out.append(line)

    if inside:
        raise Wg0Error(
            f"Malformed {path}: '# BEGIN_PEER {name}' without matching END_PEER"
        )
    if not found:
        raise ClientNotFoundError(f"Peer {name} not found in {path}")

    mode = path.stat().st_mode & 0o777
    atomic_write(path, "\n".join(out) + "\n", mode=mode)


def name_unnamed_peers(path: Path, new_name: Callable[[], str]) -> int:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        raise Wg0Error(f"Cannot read {path}: {e}") from e

    out: list[str] = []
    renamed = 0
    in_named_block = False

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if BEGIN_PEER_RE.fullmatch(stripped):
            in_named_block = True
            out.append(line)
            i += 1
            continue

        if END_PEER_RE.fullmatch(stripped):
            in_named_block = False
            out.append(line)
            i += 1
            continue

        if stripped == "[Peer]" and not in_named_block:
            j = i + 1
            while j < len(lines):
                s = lines[j].strip()
                if (
                    (s.startswith("[") and s.endswith("]"))
                    or BEGIN_PEER_RE.fullmatch(s)
                    or END_PEER_RE.fullmatch(s)
                ):
                    break
                j += 1

            end = j - 1
            while end > i and not lines[end].strip():
                end -= 1

            name = new_name()
            out.append(f"# BEGIN_PEER {name}")
            out.extend(lines[i:end + 1])
            out.append(f"# END_PEER {name}")
            renamed += 1
            i = end + 1
            continue

        out.append(line)
        i += 1

    if renamed:
        mode = path.stat().st_mode & 0o777
        atomic_write(path, "\n".join(out) + "\n", mode=mode)
    return renamed