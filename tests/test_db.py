from __future__ import annotations

from pathlib import Path

import pytest

from wgau import db, wgconf
from wgau.errors import DbError
from wgau.models import Peer

WG0_TWO_PEERS = (
    "[Interface]\n"
    "PrivateKey = SERVER_SEC\n"
    "Address = 10.7.0.1/24\n"
    "\n"
    "# BEGIN_PEER client1\n"
    "[Peer]\n"
    "PublicKey = PUBA\n"
    "PresharedKey = PSKA\n"
    "AllowedIPs = 10.7.0.2/32\n"
    "# END_PEER client1\n"
    "\n"
    "# BEGIN_PEER client2\n"
    "[Peer]\n"
    "PublicKey = PUBB\n"
    "PresharedKey = PSKB\n"
    "AllowedIPs = 10.7.0.3/32\n"
    "# END_PEER client2\n"
)

WG0_ONE_PEER = WG0_TWO_PEERS[: WG0_TWO_PEERS.index("# BEGIN_PEER client2")]
WG0_ONE_PEER = WG0_ONE_PEER.rstrip("\n") + "\n"

WG0_REVOKED = (
    "[Interface]\n"
    "PrivateKey = SERVER_SEC\n"
    "\n"
    "# BEGIN_PEER client1\n"
    "#[Peer]\n"
    "#PublicKey = PUBA\n"
    "#PresharedKey = PSKA\n"
    "#AllowedIPs = 10.7.0.2/32\n"
    "# END_PEER client1\n"
)


def parse(text: str, tmp_path: Path) -> list[Peer]:
    conf = tmp_path / "wg0.conf"
    conf.write_text(text, encoding="utf-8")
    return wgconf.parse_wg0(conf)[1]


def upsert(db_path: Path, name: str, ip: str, pub: str,
           status: str = "active") -> None:
    db.upsert_live(db_path, name=name, internal_ip=ip, public_key=pub,
                   preshared_key="P" + pub, status=status)


class TestInit:
    def test_creates_schema(self, tmp_path):
        path = tmp_path / "wgau.db"
        db.init_db(path)
        assert path.exists()
        conn = db.connect(path)
        try:
            assert conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0] == 0
        finally:
            conn.close()

    def test_idempotent_keeps_rows(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "A")
        db.init_db(path)
        assert len(db.list_rows(path)) == 1

    def test_failure_on_directory(self, tmp_path):
        directory = tmp_path / "clients"
        directory.mkdir()
        with pytest.raises(DbError):
            upsert(directory, "client1", "10.7.0.2", "A")


class TestRebuild:
    def test_rows_from_wg0(self, tmp_path):
        path = tmp_path / "wgau.db"
        db.rebuild_from_wg0(path, parse(WG0_TWO_PEERS, tmp_path))

        rows = db.list_rows(path)
        assert [r["name"] for r in rows] == ["client1", "client2"]
        assert rows[0]["internal_ip"] == "10.7.0.2"
        assert rows[0]["public_key"] == "PUBA"
        assert rows[0]["preshared_key"] == "PSKA"
        assert rows[0]["status"] == "active"
        assert rows[0]["deleted_at"] == 0
        assert rows[0]["expires_at"] is None
        assert rows[0]["created_at"] > 0

    def test_revoked_status_from_comments(self, tmp_path):
        path = tmp_path / "wgau.db"
        db.rebuild_from_wg0(path, parse(WG0_REVOKED, tmp_path))
        rows = db.list_rows(path)
        assert len(rows) == 1
        assert rows[0]["status"] == "revoked"

    def test_peer_missing_from_file_archived(self, tmp_path):
        path = tmp_path / "wgau.db"
        db.rebuild_from_wg0(path, parse(WG0_TWO_PEERS, tmp_path))
        db.rebuild_from_wg0(path, parse(WG0_ONE_PEER, tmp_path))

        rows = {r["name"]: r for r in db.list_rows(path)}
        assert rows["client1"]["status"] == "active"
        assert rows["client2"]["status"] == "deleted"
        assert rows["client2"]["deleted_at"] > 0
        assert rows["client2"]["internal_ip"] == "10.7.0.3"

    def test_idempotent(self, tmp_path):
        path = tmp_path / "wgau.db"
        db.rebuild_from_wg0(path, parse(WG0_TWO_PEERS, tmp_path))
        db.rebuild_from_wg0(path, parse(WG0_TWO_PEERS, tmp_path))

        rows = db.list_rows(path)
        assert len(rows) == 2
        assert all(r["status"] == "active" and r["deleted_at"] == 0
                   for r in rows)

    def test_preserves_expires_at(self, tmp_path):
        path = tmp_path / "wgau.db"
        db.rebuild_from_wg0(path, parse(WG0_TWO_PEERS, tmp_path))
        deadline = db.now_us() + 86_400_000_000
        upsert(path, "client1", "10.7.0.2", "PUBA")
        conn = db.connect(path)
        conn.execute("UPDATE peers SET expires_at = ? WHERE name = 'client1'",
                     (deadline,))
        conn.commit()
        conn.close()

        db.rebuild_from_wg0(path, parse(WG0_TWO_PEERS, tmp_path))
        rows = {r["name"]: r for r in db.list_rows(path)}
        assert rows["client1"]["expires_at"] == deadline

    def test_skips_unnamed_peers(self, tmp_path):
        unnamed = (
            "[Interface]\nPrivateKey = SERVER_SEC\n\n"
            "[Peer]\nPublicKey = X\nAllowedIPs = 10.7.0.2/32\n"
        )
        path = tmp_path / "wgau.db"
        db.rebuild_from_wg0(path, parse(unnamed, tmp_path))
        assert db.list_rows(path) == []


class TestArchiveAndRecreate:
    def test_deleted_name_can_be_reused(self, tmp_path):
        """Удаление архивирует строку с уникальным deleted_at, имя освобождается."""
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "A")
        db.archive_peer(path, "client1")
        upsert(path, "client1", "10.7.0.2", "B")

        rows = db.list_rows(path)
        assert len(rows) == 2
        live = next(r for r in rows if r["status"] == "active")
        history = next(r for r in rows if r["status"] == "deleted")
        assert live["public_key"] == "B"
        assert live["deleted_at"] == 0
        assert history["public_key"] == "A"
        assert history["name"] == "client1"      # имя в истории сохранено
        assert history["deleted_at"] > 0
        assert history["deleted_at"] != live["deleted_at"]

    def test_archive_missing_row_keeps_history(self, tmp_path):
        peer = Peer(name="client1", params={
            "PublicKey": "A", "PresharedKey": "P", "AllowedIPs": "10.7.0.2/32",
        })
        path = tmp_path / "wgau.db"
        db.archive_peer(path, "client1", peer=peer)

        rows = db.list_rows(path)
        assert len(rows) == 1
        assert rows[0]["status"] == "deleted"
        assert rows[0]["public_key"] == "A"
        assert rows[0]["internal_ip"] == "10.7.0.2"
        assert rows[0]["deleted_at"] > 0

    def test_archive_unknown_name_is_noop(self, tmp_path):
        path = tmp_path / "wgau.db"
        db.archive_peer(path, "ghost")
        assert db.list_rows(path) == []

    def test_ip_unique_among_live_peers(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "A")
        with pytest.raises(DbError):
            upsert(path, "client2", "10.7.0.2", "B")

        db.archive_peer(path, "client1")
        upsert(path, "client2", "10.7.0.2", "B")
        assert len(db.list_rows(path)) == 2

    def test_status_flow(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "A")
        upsert(path, "client1", "10.7.0.2", "A", status="revoked")
        rows = db.list_rows(path)
        assert len(rows) == 1
        assert rows[0]["status"] == "revoked"
        assert rows[0]["created_at"] > 0  # срок создания не сбросился

    def test_resurrection_after_reappearing_in_file(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "A")
        db.archive_peer(path, "client1")
        # пир вернулся в wg0.conf с тем же ключом — строка «оживает»
        peers = parse(
            "[Interface]\nPrivateKey = SERVER_SEC\n\n"
            "# BEGIN_PEER client1\n"
            "[Peer]\n"
            "PublicKey = A\n"
            "PresharedKey = PA\n"
            "AllowedIPs = 10.7.0.2/32\n"
            "# END_PEER client1\n",
            tmp_path,
        )
        db.rebuild_from_wg0(path, peers)

        rows = db.list_rows(path)
        assert len(rows) == 1
        assert rows[0]["status"] == "active"
        assert rows[0]["deleted_at"] == 0
        assert rows[0]["public_key"] == "A"


class TestTitle:
    def test_new_db_has_title_null(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "A")
        rows = db.list_rows(path)
        assert rows[0]["title"] is None

    def test_set_and_clear(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "A")
        db.set_peer_title(path, "client1", "Ноутбук Ани")
        assert db.list_rows(path)[0]["title"] == "Ноутбук Ани"
        assert db.find_live(path, "client1")["title"] == "Ноутбук Ани"

        db.set_peer_title(path, "client1", None)
        assert db.list_rows(path)[0]["title"] is None
        assert db.find_live(path, "client1")["title"] is None

    def test_empty_string_means_no_title(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "A")
        db.set_peer_title(path, "client1", "Телефон")
        db.set_peer_title(path, "client1", "  ")
        assert db.list_rows(path)[0]["title"] is None

    def test_strips_title(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "A")
        db.set_peer_title(path, "client1", "  Alice  ")
        assert db.list_rows(path)[0]["title"] == "Alice"

    def test_set_on_unknown_name_is_noop(self, tmp_path):
        path = tmp_path / "wgau.db"
        db.set_peer_title(path, "ghost", "X")
        assert db.list_rows(path) == []

    def test_find_live(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "A")
        db.archive_peer(path, "client1")
        assert db.find_live(path, "client1") is None
        assert db.find_live(path, "ghost") is None

    def test_survives_rebuild_from_wg0(self, tmp_path):
        path = tmp_path / "wgau.db"
        db.rebuild_from_wg0(path, parse(WG0_ONE_PEER, tmp_path))
        db.set_peer_title(path, "client1", "Телефон")
        db.rebuild_from_wg0(path, parse(WG0_ONE_PEER, tmp_path))
        assert db.list_rows(path)[0]["title"] == "Телефон"

    def test_survives_upsert_with_same_key(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "PUBA")
        db.set_peer_title(path, "client1", "Планшет")
        upsert(path, "client1", "10.7.0.2", "PUBA", status="revoked")
        rows = db.list_rows(path)
        assert len(rows) == 1
        assert rows[0]["status"] == "revoked"
        assert rows[0]["title"] == "Планшет"

    def test_archived_row_keeps_title_new_row_has_none(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client1", "10.7.0.2", "A")
        db.set_peer_title(path, "client1", "Старый")
        db.archive_peer(path, "client1")
        upsert(path, "client1", "10.7.0.2", "B")

        rows = {r["status"]: r for r in db.list_rows(path)}
        assert rows["deleted"]["title"] == "Старый"
        assert rows["active"]["title"] is None


class TestMigrateTitle:
    """Базы, созданные до появления title, достраиваются через ALTER TABLE."""

    OLD_SCHEMA = """
    CREATE TABLE peers (
        name          TEXT    NOT NULL,
        deleted_at    INTEGER NOT NULL DEFAULT 0,
        internal_ip   TEXT    NOT NULL,
        public_key    TEXT    NOT NULL UNIQUE,
        preshared_key TEXT,
        status        TEXT    NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'revoked', 'deleted')),
        expires_at    INTEGER,
        created_at    INTEGER NOT NULL,
        updated_at    INTEGER NOT NULL,
        PRIMARY KEY (name, deleted_at)
    );
    """

    def old_db(self, tmp_path) -> Path:
        path = tmp_path / "wgau.db"
        conn = db.connect(path)
        conn.executescript(self.OLD_SCHEMA)
        conn.execute(
            "INSERT INTO peers (name, internal_ip, public_key, created_at,"
            " updated_at) VALUES ('client1', '10.7.0.2', 'A', 1, 1)"
        )
        conn.commit()
        conn.close()
        return path

    def test_write_migrates(self, tmp_path):
        path = self.old_db(tmp_path)
        upsert(path, "client1", "10.7.0.2", "A")
        rows = db.list_rows(path)
        assert len(rows) == 1
        assert rows[0]["title"] is None

    def test_read_migrates(self, tmp_path):
        path = self.old_db(tmp_path)
        rows = db.list_rows(path)
        assert len(rows) == 1
        assert rows[0]["name"] == "client1"
        assert rows[0]["title"] is None

    def test_read_migrates_for_find_live(self, tmp_path):
        path = self.old_db(tmp_path)
        assert db.find_live(path, "client1")["title"] is None


class TestListRows:
    def test_live_before_history(self, tmp_path):
        path = tmp_path / "wgau.db"
        upsert(path, "client2", "10.7.0.3", "B")
        upsert(path, "client1", "10.7.0.2", "A")
        db.archive_peer(path, "client1")

        rows = db.list_rows(path)
        assert [r["name"] for r in rows] == ["client2", "client1"]
        assert rows[0]["status"] == "active"
        assert rows[1]["status"] == "deleted"


class TestFmtUs:
    @pytest.mark.parametrize("value,expected", [
        (0, "-"),
        (None, "-"),
    ])
    def test_empty(self, value, expected):
        assert db.fmt_us(value) == expected

    def test_formats_utc(self):
        # 2026-10-14 11:26:57 UTC в микросекундах
        assert db.fmt_us(1_791_977_217_000_000) == "2026-10-14 11:26"
