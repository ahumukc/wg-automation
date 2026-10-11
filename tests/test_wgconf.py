from __future__ import annotations

from pathlib import Path

import pytest

from wgau import alloc
from wgau.errors import PeerExistsError, Wg0Error
from wgau.wgconf import add_peer, build_peer_block, name_unnamed_peers, parse_wg0

WG0 = (
    "[Interface]\n"
    "PrivateKey = SERVER_SEC\n"
    "Address = 10.7.0.1/24\n"
    "\n"
    "# BEGIN_PEER client1\n"
    "[Peer]\n"
    "PublicKey = PUB1\n"
    "PresharedKey = PSK1\n"
    "AllowedIPs = 10.7.0.2/32\n"
    "# END_PEER client1\n"
    "\n"
    "# BEGIN_PEER client2\n"
    "[Peer]\n"
    "PublicKey = PUB2\n"
    "PresharedKey = PSK2\n"
    "AllowedIPs = 10.7.0.3/32\n"
    "# END_PEER client2\n"
)


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "wg0.conf"
    p.write_text(text, encoding="utf-8")
    return p


def name_factory(prefix: str = "client", initial: set[str] | None = None):
    """Тот же генератор имён, что использует service.sync_folders."""
    taken = set(initial or ())

    def new_name() -> str:
        name = alloc.next_name(prefix, taken)
        taken.add(name)
        return name

    return new_name


class TestParseWg0:
    def test_interface_params(self, tmp_path):
        iface, _ = parse_wg0(write(tmp_path, WG0))
        assert iface.private_key == "SERVER_SEC"
        assert iface.params["Address"] == "10.7.0.1/24"

    def test_named_peers(self, tmp_path):
        _, peers = parse_wg0(write(tmp_path, WG0))
        assert [p.name for p in peers] == ["client1", "client2"]
        assert peers[0].public_key == "PUB1"
        assert peers[0].psk == "PSK1"
        assert peers[1].first_ip == "10.7.0.3"

    def test_unnamed_peer(self, tmp_path):
        text = ("[Interface]\nPrivateKey = s\n\n"
                "[Peer]\nPublicKey = A\nAllowedIPs = 10.7.0.5/32\n")
        _, peers = parse_wg0(write(tmp_path, text))
        assert len(peers) == 1
        assert peers[0].name is None
        assert peers[0].first_ip == "10.7.0.5"

    def test_marker_then_peer_header_is_one_peer(self, tmp_path):
        # BEGIN_PEER создаёт Peer, следующий [Peer] не плодит второй
        text = "# BEGIN_PEER x\n[Peer]\nPublicKey = A\n# END_PEER x\n"
        _, peers = parse_wg0(write(tmp_path, text))
        assert len(peers) == 1

    def test_comments_ignored(self, tmp_path):
        text = "[Interface]\n# comment = not a param\nPrivateKey = s\n"
        iface, peers = parse_wg0(write(tmp_path, text))
        assert "comment" not in iface.params
        assert peers == []

    def test_params_after_end_peer_dropped(self, tmp_path):
        text = "# BEGIN_PEER x\n[Peer]\nPublicKey = A\n# END_PEER x\nStray = 1\n"
        _, peers = parse_wg0(write(tmp_path, text))
        assert peers[0].params == {"PublicKey": "A"}

    def test_unknown_section_resets(self, tmp_path):
        text = "[Interface]\nPrivateKey = s\n[Unknown]\nFoo = 1\n"
        iface, _ = parse_wg0(write(tmp_path, text))
        assert "Foo" not in iface.params

    def test_no_spaces_around_equals(self, tmp_path):
        iface, _ = parse_wg0(write(tmp_path, "[Interface]\nPrivateKey=s\n"))
        assert iface.private_key == "s"

    def test_empty_file(self, tmp_path):
        iface, peers = parse_wg0(write(tmp_path, ""))
        assert iface.params == {}
        assert peers == []

    def test_missing_file(self, tmp_path):
        with pytest.raises(Wg0Error):
            parse_wg0(tmp_path / "nope.conf")


class TestBuildPeerBlock:
    def test_format(self):
        assert build_peer_block("client1", "PUB", "PSK", "10.7.0.2") == (
            "# BEGIN_PEER client1\n"
            "[Peer]\n"
            "PublicKey = PUB\n"
            "PresharedKey = PSK\n"
            "AllowedIPs = 10.7.0.2/32\n"
            "# END_PEER client1\n"
        )


class TestAddPeer:
    def test_appends_block(self, tmp_path):
        p = write(tmp_path, "[Interface]\nPrivateKey = s\n")
        add_peer(p, "client1", "PUB", "PSK", "10.7.0.2")
        assert p.read_text() == (
            "[Interface]\nPrivateKey = s\n\n"
            "# BEGIN_PEER client1\n[Peer]\nPublicKey = PUB\n"
            "PresharedKey = PSK\nAllowedIPs = 10.7.0.2/32\n# END_PEER client1\n"
        )

    def test_existing_content_preserved(self, tmp_path):
        p = write(tmp_path, WG0)
        add_peer(p, "client9", "PUB9", "PSK9", "10.7.0.9")
        text = p.read_text()
        assert text.startswith(WG0)
        assert "# END_PEER client9\n" in text

    def test_duplicate_name_rejected(self, tmp_path):
        p = write(tmp_path, WG0)
        with pytest.raises(PeerExistsError):
            add_peer(p, "client1", "PUB", "PSK", "10.7.0.2")

    def test_no_write_on_duplicate(self, tmp_path):
        p = write(tmp_path, WG0)
        before = p.read_text()
        with pytest.raises(PeerExistsError):
            add_peer(p, "client2", "PUB", "PSK", "10.7.0.9")
        assert p.read_text() == before

    def test_mode_preserved(self, tmp_path):
        p = write(tmp_path, "[Interface]\nPrivateKey = s\n")
        p.chmod(0o600)
        add_peer(p, "client1", "PUB", "PSK", "10.7.0.2")
        assert p.stat().st_mode & 0o777 == 0o600

    def test_trailing_blank_lines_normalized(self, tmp_path):
        p = write(tmp_path, "[Interface]\nPrivateKey = s\n\n\n")
        add_peer(p, "client1", "PUB", "PSK", "10.7.0.2")
        assert p.read_text() == (
            "[Interface]\nPrivateKey = s\n\n"
            "# BEGIN_PEER client1\n[Peer]\nPublicKey = PUB\n"
            "PresharedKey = PSK\nAllowedIPs = 10.7.0.2/32\n# END_PEER client1\n"
        )


class TestNameUnnamedPeers:
    def test_wraps_single_peer(self, tmp_path):
        p = write(tmp_path, "[Peer]\nPublicKey = A\nAllowedIPs = 10.7.0.2/32\n")
        assert name_unnamed_peers(p, name_factory()) == 1
        assert p.read_text() == (
            "# BEGIN_PEER client1\n[Peer]\nPublicKey = A\n"
            "AllowedIPs = 10.7.0.2/32\n# END_PEER client1\n"
        )

    def test_sequential_names_not_ip_octet(self, tmp_path):
        # регрессия «+1»: имена последовательные, а не из последнего октета IP
        p = write(tmp_path, "[Peer]\nPublicKey = A\nAllowedIPs = 10.7.0.2/32\n\n"
                            "[Peer]\nPublicKey = B\nAllowedIPs = 10.7.0.3/32\n")
        name_unnamed_peers(p, name_factory())
        _, peers = parse_wg0(p)
        assert [p.name for p in peers] == ["client1", "client2"]

    def test_blank_line_between_blocks_outside_markers(self, tmp_path):
        p = write(tmp_path, "[Peer]\nPublicKey = A\n\n[Peer]\nPublicKey = B\n")
        name_unnamed_peers(p, name_factory())
        assert "# END_PEER client1\n\n# BEGIN_PEER client2\n" in p.read_text()

    def test_named_file_untouched(self, tmp_path):
        p = write(tmp_path, WG0)

        def must_not_be_called():
            raise AssertionError("new_name не должен вызываться для именованных пиров")

        assert name_unnamed_peers(p, must_not_be_called) == 0
        assert p.read_text() == WG0

    def test_mode_preserved(self, tmp_path):
        p = write(tmp_path, "[Peer]\nPublicKey = A\n")
        p.chmod(0o640)
        name_unnamed_peers(p, name_factory())
        assert p.stat().st_mode & 0o777 == 0o640

    def test_trailing_blanks_stay_outside_markers(self, tmp_path):
        p = write(tmp_path, "[Peer]\nPublicKey = A\n\n")
        name_unnamed_peers(p, name_factory())
        assert p.read_text().endswith("# END_PEER client1\n\n")

    def test_mixed_named_and_unnamed(self, tmp_path):
        p = write(tmp_path, WG0 + "\n[Peer]\nPublicKey = C\n")
        # client1/client2 уже заняты именованными пирами
        assert name_unnamed_peers(p, name_factory(initial={"client1", "client2"})) == 1
        _, peers = parse_wg0(p)
        assert [p.name for p in peers] == ["client1", "client2", "client3"]