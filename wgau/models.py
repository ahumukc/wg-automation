from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class KeyPair:
    private_key: str
    public_key: str
    psk: str


@dataclass
class WgInterface:
    params: dict[str, str] = field(default_factory=dict)

    @property
    def private_key(self) -> str | None:
        return self.params.get("PrivateKey")


@dataclass
class Peer:
    name: str | None = field(default=None)
    params: dict[str, str] = field(default_factory=dict)

    @property
    def public_key(self) -> str | None:
        return self.params.get("PublicKey")

    @property
    def psk(self) -> str | None:
        return self.params.get("PresharedKey")

    @property
    def allowed_ips(self) -> list[str]:
        """AllowedIPs как список «голых» IP (без /32)."""
        raw = self.params.get("AllowedIPs", "")
        return [p.strip().split("/")[0] for p in raw.split(",") if p.strip()]

    @property
    def first_ip(self) -> str | None:
        return self.allowed_ips[0] if self.allowed_ips else None