from __future__ import annotations

from pathlib import Path

from wgau import wgconf


def test_remove_peer(tmp_path: Path) -> None:
    wg0 = tmp_path / "wg0.conf"
    wg0.write_text(
        "[Interface]\nPrivateKey = srv\n\n"
        "# BEGIN_PEER client1\n[Peer]\nPublicKey = a\n"
        "AllowedIPs = 10.7.0.2/32\n# END_PEER client1\n\n"
        "# BEGIN_PEER client2\n[Peer]\nPublicKey = b\n"
        "AllowedIPs = 10.7.0.3/32\n# END_PEER client2\n",
        encoding="utf-8",
    )

    assert wgconf.remove_peer(wg0, "client1") is True
    text = wg0.read_text(encoding="utf-8")
    assert "client1" not in text
    assert "client2" in text
    assert "\n\n\n" not in text

    assert wgconf.remove_peer(wg0, "missing") is False
    assert wg0.read_text(encoding="utf-8") == text
