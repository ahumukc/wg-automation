from __future__ import annotations

import re
from typing import Iterable

from wgau.errors import NoFreeIPError


def ip_suffix(base: str, ip: str) -> int | None:
    m = re.fullmatch(rf"{re.escape(base)}\.(\d+)", ip)
    return int(m.group(1)) if m else None


def used_suffixes(base: str, ips: Iterable[str]) -> set[int]:
    return {s for ip in ips if (s := ip_suffix(base, ip)) is not None}


def next_free_ip(base: str, used: set[int], lo: int = 2, hi: int = 254) -> str:
    for i in range(lo, hi + 1):
        if i not in used:
            return f"{base}.{i}"
    raise NoFreeIPError(f"No free IP in {base}.{lo}–{base}.{hi}")


def next_name(prefix: str, taken: Iterable[str]) -> str:
    taken = set(taken)
    n = 1
    while f"{prefix}{n}" in taken:
        n += 1
    return f"{prefix}{n}"