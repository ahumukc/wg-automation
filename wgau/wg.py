from __future__ import annotations

import subprocess
from pathlib import Path

from wgau.errors import WgError
from wgau.models import KeyPair


def run_wg(args: list[str], stdin_data: str | None = None) -> str:
    try:
        result = subprocess.run(
            ["wg", *args],
            input=stdin_data,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as e:
        raise WgError("`wg` not found — is wireguard-tools installed?") from e
    except subprocess.CalledProcessError as e:
        raise WgError(f"wg {' '.join(args)} failed: {(e.stderr or '').strip()}") from e
    return result.stdout.strip()


def generate_keys() -> KeyPair:
    private_key = run_wg(["genkey"])
    public_key = run_wg(["pubkey"], private_key)
    psk = run_wg(["genpsk"])
    return KeyPair(private_key=private_key, public_key=public_key, psk=psk)


def derive_public_key(private_key: str) -> str:
    return run_wg(["pubkey"], private_key)


def syncconf(interface: str, wg_quick_conf: Path) -> None:
    try:
        stripped = subprocess.run(
            ["wg-quick", "strip", str(wg_quick_conf)],
            capture_output=True, text=True, check=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        raise WgError(f"wg-quick strip failed: {e}") from e
    run_wg(["syncconf", interface, "/dev/stdin"], stdin_data=stripped)