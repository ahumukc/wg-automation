from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Sequence

from wgau.errors import DbError
from wgau.models import Peer

# База — проекция (кэш/индекс) поверх wg0.conf, а не второй источник правды.
#
# Все времена — целые микросекунды Unix UTC.
# deleted_at = 0 значит «пир жив» и входит в PRIMARY KEY (name, deleted_at):
# при удалении client1 его строка уходит в архив с уникальной меткой
# deleted_at, освобождая имя client1 для нового клиента. История сохраняется.

SCHEMA = """
CREATE TABLE IF NOT EXISTS peers (
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

-- живые пиры не могут делить один IP; удалённые историю не занимают
CREATE UNIQUE INDEX IF NOT EXISTS peers_ip_live
    ON peers(internal_ip) WHERE status != 'deleted';
"""

_UPSERT_LIVE = """
INSERT INTO peers (name, deleted_at, internal_ip, public_key, preshared_key,
                   status, expires_at, created_at, updated_at)
VALUES (:name, 0, :internal_ip, :public_key, :preshared_key,
        :status, :expires_at, :now, :now)
ON CONFLICT (public_key) DO UPDATE SET
    name          = excluded.name,
    deleted_at    = 0,
    internal_ip   = excluded.internal_ip,
    preshared_key = excluded.preshared_key,
    status        = excluded.status,
    expires_at    = COALESCE(:expires_at, peers.expires_at),
    updated_at    = excluded.updated_at
"""

# одноимённый «прошлый» пир (другие ключи) уходит в архив перед вставкой
_ARCHIVE_SAME_NAME = """
UPDATE peers
   SET status = 'deleted', deleted_at = :now, updated_at = :now
 WHERE name = :name AND deleted_at = 0 AND public_key <> :public_key
"""

_ARCHIVE_BY_NAME = """
UPDATE peers
   SET status = 'deleted', deleted_at = :now, updated_at = :now
 WHERE name = :name AND deleted_at = 0
"""

_INSERT_DELETED = """
INSERT INTO peers (name, deleted_at, internal_ip, public_key, preshared_key,
                   status, created_at, updated_at)
VALUES (:name, :deleted_at, :internal_ip, :public_key, :preshared_key,
        'deleted', :now, :now)
"""

_last_delete_us = 0


def now_us() -> int:
    """Текущее время в микросекундах Unix UTC."""
    return int(datetime.now(timezone.utc).timestamp() * 1_000_000)


def _next_delete_us() -> int:
    """Монотонная уникальная метка удаления (в рамках процесса)."""
    global _last_delete_us
    ts = max(now_us(), _last_delete_us + 1)
    _last_delete_us = ts
    return ts


def fmt_us(value: int | None) -> str:
    """Микросекунды UTC → 'YYYY-MM-DD HH:MM' для вывода; 0/None → '-'."""
    if not value:
        return "-"
    dt = datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M")


def connect(path: Path) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 10000")
    except sqlite3.Error as e:
        raise DbError(f"cannot open {path}: {e}") from e
    return conn


@contextmanager
def write_txn(path: Path) -> Iterator[sqlite3.Connection]:
    conn = connect(path)
    try:
        yield conn
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        raise DbError(f"{path}: {e}") from e
    finally:
        conn.close()


def init_db(path: Path) -> None:
    """Создать файл и схему, если их ещё нет (идемпотентно)."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = connect(path)
    except (OSError, DbError) as e:
        raise DbError(f"cannot initialize {path}: {e}") from e
    try:
        with conn:
            conn.executescript(SCHEMA)
    except sqlite3.Error as e:
        raise DbError(f"cannot initialize {path}: {e}") from e
    finally:
        conn.close()


def _upsert_live(conn: sqlite3.Connection, *, name: str, internal_ip: str,
                 public_key: str, preshared_key: str | None, status: str,
                 expires_at: int | None = None) -> None:
    params = {
        "name": name,
        "internal_ip": internal_ip,
        "public_key": public_key,
        "preshared_key": preshared_key,
        "status": status,
        "expires_at": expires_at,
        "now": _next_delete_us(),
    }
    conn.execute(_ARCHIVE_SAME_NAME, params)
    conn.execute(_UPSERT_LIVE, params)


def upsert_live(path: Path, *, name: str, internal_ip: str, public_key: str,
                preshared_key: str | None, status: str,
                expires_at: int | None = None) -> None:
    """Вставить/обновить живого пира (add/revoke/grant, rebuild).

    Одноимённый прошлый пир с другими ключами предварительно архивируется.
    expires_at не перезаписвается, если не передан явно (это метаданные БД,
    их нет в wg0.conf). Строка с тем же public_key «оживает» — deleted_at = 0.
    """
    init_db(path)
    with write_txn(path) as conn:
        _upsert_live(conn, name=name, internal_ip=internal_ip,
                     public_key=public_key, preshared_key=preshared_key,
                     status=status, expires_at=expires_at)


def archive_peer(path: Path, name: str, peer: Peer | None = None) -> None:
    """Перевести пира в архив: живая строка → deleted, либо новая архивная.

    deleted_at уникален, поэтому (name, deleted_at) не конфликтует с новой
    строкой того же имени, а уникальный индекс IP освобождает адрес.
    Если строки в БД не было, но пир был в wg0.conf — создаём архивную запись
    из его данных (история не теряется даже без предварительного sync).
    """
    init_db(path)
    with write_txn(path) as conn:
        params = {"name": name, "now": _next_delete_us()}
        cur = conn.execute(_ARCHIVE_BY_NAME, params)
        if cur.rowcount == 0 and peer is not None and peer.public_key:
            conn.execute(_INSERT_DELETED, {
                **params,
                "deleted_at": params["now"],
                "internal_ip": peer.first_ip or "",
                "public_key": peer.public_key,
                "preshared_key": peer.psk,
            })


def rebuild_from_wg0(path: Path, peers: Sequence[Peer]) -> None:
    """Пересобрать проекцию БД из wg0.conf (wg0.conf — источник правды).

    Живым пирам файла соответствует upsert; живые строки БД, которых нет
    в файле (ручное удаление блока), уходят в архив. expires_at и created_at
    при этом сохраняются.
    """
    init_db(path)
    in_file = {p.public_key for p in peers if p.public_key}
    with write_txn(path) as conn:
        # живые строки, которых нет в wg0.conf (ручное удаление блока),
        # уходят в архив; имена живых пиров уникальны, поэтому одна метка
        # deleted_at не конфликтует внутри одного UPDATE
        stale = [
            row["public_key"]
            for row in conn.execute(
                "SELECT public_key FROM peers WHERE deleted_at = 0"
            ).fetchall()
            if row["public_key"] not in in_file
        ]
        if stale:
            marks = ",".join("?" * len(stale))
            conn.execute(
                "UPDATE peers SET status = 'deleted', deleted_at = ?,"
                " updated_at = ? WHERE deleted_at = 0"
                f" AND public_key IN ({marks})",
                (now_us(), now_us(), *stale),
            )
        for peer in peers:
            if not peer.name or not peer.public_key or not peer.first_ip:
                continue  # имя — часть PK; sync именует пиров до пересборки
            _upsert_live(
                conn,
                name=peer.name or "",
                internal_ip=peer.first_ip,
                public_key=peer.public_key,
                preshared_key=peer.psk,
                status="revoked" if peer.revoked else "active",
            )


def list_rows(path: Path) -> list[sqlite3.Row]:
    """Все строки: сначала живые (deleted_at = 0), затем архив по времени."""
    if not path.exists():
        return []
    conn = connect(path)
    try:
        return conn.execute(
            "SELECT name, internal_ip, public_key, preshared_key, status,"
            " expires_at, deleted_at, created_at"
            " FROM peers ORDER BY deleted_at, name"
        ).fetchall()
    except sqlite3.Error as e:
        raise DbError(f"cannot read {path}: {e}") from e
    finally:
        conn.close()
