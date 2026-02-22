import queue

import io
import psycopg2
from psycopg2.extras import DictCursor
from sdio_dejavu.base_classes.common_database import CommonDatabase
from sdio_dejavu.config.settings import (FIELD_FILE_SHA1, FIELD_FINGERPRINTED,
                                    FIELD_HASH, FIELD_OFFSET, FIELD_SONG_ID,
                                    FIELD_HASH64,
                                    FIELD_SONGNAME, FIELD_TOTAL_HASHES,
                                    FINGERPRINTS_TABLENAME, SONGS_TABLENAME)


class PostgreSQLDatabase(CommonDatabase):
    type = "postgres"

    # CREATES
    CREATE_SONGS_TABLE = f"""
        CREATE TABLE IF NOT EXISTS "{SONGS_TABLENAME}" (
            "{FIELD_SONG_ID}" SERIAL
        ,   "{FIELD_SONGNAME}" VARCHAR(250) NOT NULL
        ,   "{FIELD_FINGERPRINTED}" SMALLINT DEFAULT 0
        ,   "{FIELD_FILE_SHA1}" BYTEA
        ,   "{FIELD_TOTAL_HASHES}" INT NOT NULL DEFAULT 0
        ,   "date_created" TIMESTAMP NOT NULL DEFAULT now()
        ,   "date_modified" TIMESTAMP NOT NULL DEFAULT now()
        ,   CONSTRAINT "pk_{SONGS_TABLENAME}_{FIELD_SONG_ID}" PRIMARY KEY ("{FIELD_SONG_ID}")
        ,   CONSTRAINT "uq_{SONGS_TABLENAME}_{FIELD_SONG_ID}" UNIQUE ("{FIELD_SONG_ID}")
        );
    """

    CREATE_CREATIVE_TABLE_INDEX = f"""CREATE UNIQUE INDEX "idx_{SONGS_TABLENAME}_{FIELD_SONGNAME}" ON "{SONGS_TABLENAME}" ("{FIELD_SONGNAME}");"""


    CREATE_FINGERPRINTS_TABLE = f"""
    CREATE TABLE IF NOT EXISTS "{FINGERPRINTS_TABLENAME}" (
        "{FIELD_HASH}" BYTEA NOT NULL,
        "{FIELD_SONG_ID}" INT NOT NULL,
        "{FIELD_OFFSET}" INT NOT NULL,
        "date_created" TIMESTAMP NOT NULL DEFAULT now(),
        "date_modified" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "uq_{FINGERPRINTS_TABLENAME}" UNIQUE ("{FIELD_SONG_ID}", "{FIELD_OFFSET}", "{FIELD_HASH}", "date_created"),
        CONSTRAINT "fk_{FINGERPRINTS_TABLENAME}_{FIELD_SONG_ID}" FOREIGN KEY ("{FIELD_SONG_ID}")
        REFERENCES "{SONGS_TABLENAME}"("{FIELD_SONG_ID}") ON DELETE CASCADE
    )
    PARTITION BY RANGE ("date_created");

    CREATE INDEX IF NOT EXISTS "ix_{FINGERPRINTS_TABLENAME}_{FIELD_HASH}" ON "{FINGERPRINTS_TABLENAME}" USING hash ("{FIELD_HASH}");
    """

    CREATE_FINGERPRINTS_TABLE_DEFAULT = f"""
    CREATE TABLE IF NOT EXISTS "{FINGERPRINTS_TABLENAME}" (
        "{FIELD_HASH}" BYTEA NOT NULL,
        "{FIELD_HASH64}" BIGINT NOT NULL,
        "{FIELD_SONG_ID}" INT NOT NULL,
        "{FIELD_OFFSET}" INT NOT NULL,
        "date_created" TIMESTAMP NOT NULL DEFAULT now(),
        "date_modified" TIMESTAMP NOT NULL DEFAULT now(),

        CONSTRAINT "uq_{FINGERPRINTS_TABLENAME}"
            UNIQUE ("{FIELD_SONG_ID}", "{FIELD_OFFSET}", "{FIELD_HASH}", date_created),

        CONSTRAINT "fk_{FINGERPRINTS_TABLENAME}_{FIELD_SONG_ID}"
            FOREIGN KEY ("{FIELD_SONG_ID}")
            REFERENCES "{SONGS_TABLENAME}"("{FIELD_SONG_ID}")
            ON DELETE CASCADE
    );
    """

    CREATE_FINGERPRINTS_TABLE_INDEX_HASH64 = f"""
    CREATE INDEX IF NOT EXISTS
        "ix_{FINGERPRINTS_TABLENAME}_{FIELD_HASH64}"
    ON "{FINGERPRINTS_TABLENAME}"
    USING btree ("{FIELD_HASH64}");
    """

    CREATE_FINGERPRINTS_TABLE_INDEX_SONGID = f"""
    CREATE INDEX IF NOT EXISTS
        "ix_{FINGERPRINTS_TABLENAME}_{FIELD_SONG_ID}"
    ON "{FINGERPRINTS_TABLENAME}" ("{FIELD_SONG_ID}");
    """

    CREATE_FINGERPRINTS_TABLE_INDEX_ALL = f"""
    CREATE INDEX CONCURRENTLY idx_fingerprints_lookup_optimized 
    ON {FINGERPRINTS_TABLENAME} ({FIELD_HASH64}) 
    INCLUDE ({FIELD_SONG_ID}, "{FIELD_OFFSET}");"""

    CREATE_FINGERPRINTS_TABLE_SQL = (
        CREATE_FINGERPRINTS_TABLE_DEFAULT
        + CREATE_FINGERPRINTS_TABLE_INDEX_HASH64
        + CREATE_FINGERPRINTS_TABLE_INDEX_SONGID
        + CREATE_FINGERPRINTS_TABLE_INDEX_ALL
    )



    # INSERTS (IGNORES DUPLICATES)
    INSERT_FINGERPRINT = f"""
        INSERT INTO "{FINGERPRINTS_TABLENAME}" (
                "{FIELD_SONG_ID}"
            ,   "{FIELD_HASH}"
            ,   "{FIELD_HASH64}"
            ,   "{FIELD_OFFSET}")
        VALUES (%s, decode(%s, 'hex'), %s, %s) ON CONFLICT DO NOTHING;
    """

    INSERT_FINGERPRINT_TEMPLATE = "(%s, decode(%s, 'hex'), %s, %s)"

    INSERT_FINGERPRINT_VALUES = f"""
        INSERT INTO "{FINGERPRINTS_TABLENAME}" (
                "{FIELD_SONG_ID}"
            ,   "{FIELD_HASH}"
            ,   "{FIELD_HASH64}"
            ,   "{FIELD_OFFSET}")
        VALUES %s ON CONFLICT DO NOTHING;
    """

    INSERT_SONG = f"""
        INSERT INTO "{SONGS_TABLENAME}" ("{FIELD_SONGNAME}", "{FIELD_FILE_SHA1}","{FIELD_TOTAL_HASHES}")
        VALUES (%s, decode(%s, 'hex'), %s)
        ON CONFLICT ("{FIELD_SONGNAME}") DO NOTHING
        RETURNING "{FIELD_SONG_ID}";
    """

    SELECT_SONG_ID_BY_NAME = f"""
        SELECT "{FIELD_SONG_ID}"
        FROM "{SONGS_TABLENAME}"
        WHERE "{FIELD_SONGNAME}" = %s;
    """

    COPY_TEMP_TABLE = "tmp_fp_audio_fingerprints"

    # SELECTS
    SELECT = f"""
        SELECT "{FIELD_SONG_ID}", "{FIELD_OFFSET}"
        FROM "{FINGERPRINTS_TABLENAME}"
        WHERE "{FIELD_HASH}" = decode(%s, 'hex');
    """

    SELECT_MULTIPLE = f"""
        SELECT upper(encode("{FIELD_HASH}", 'hex')), "{FIELD_SONG_ID}", "{FIELD_OFFSET}"
        FROM "{FINGERPRINTS_TABLENAME}"
        WHERE "{FIELD_HASH}" IN (%s);
    """

    SELECT_MULTIPLE_INT64 = f"""
    SELECT "{FIELD_HASH64}", "{FIELD_SONG_ID}", "{FIELD_OFFSET}"
    FROM "{FINGERPRINTS_TABLENAME}"
    WHERE "{FIELD_HASH64}" IN (%s);
    """

    MATCHES_HASH64_UNNEST = f"""
    WITH input_hashes({FIELD_HASH64}, input_offset) AS (
        SELECT *
        FROM UNNEST(%s::bigint[], %s::int[])
    )
    SELECT
        f.{FIELD_SONG_ID},
        i.{FIELD_HASH64},
        f.{FIELD_OFFSET} - i.input_offset AS offset_diff
    FROM input_hashes i
    JOIN {FINGERPRINTS_TABLENAME}  f
    ON f.{FIELD_HASH64} = i.{FIELD_HASH64};
    """

    SELECT_FINGERPRINTS_BY_SONG_NAME = f"""
        SELECT
            f."{FIELD_HASH64}",
            f."{FIELD_OFFSET}"
        FROM "{FINGERPRINTS_TABLENAME}" f
        JOIN "{SONGS_TABLENAME}" c
            ON f."{FIELD_SONG_ID}" = c."{FIELD_SONG_ID}"
        WHERE c."{FIELD_SONGNAME}" = %s
        ORDER BY f."{FIELD_OFFSET}";
    """

    SELECT_FINGERPRINTS_BY_SONG_NAME_LIST = f"""
        SELECT
            c."{FIELD_SONGNAME}",
            f."{FIELD_HASH64}",
            f."{FIELD_OFFSET}"
        FROM "{FINGERPRINTS_TABLENAME}" f
        JOIN "{SONGS_TABLENAME}" c
            ON f."{FIELD_SONG_ID}" = c."{FIELD_SONG_ID}"
        WHERE c."{FIELD_SONGNAME}" IN ({{}})
        ORDER BY f."{FIELD_OFFSET}";
    """

    SELECT_MULTIPLE1 = f"""
        SELECT upper(encode("{FIELD_HASH}", 'hex')), "{FIELD_SONG_ID}", "{FIELD_OFFSET}"
        FROM """

    SELECT_MULTIPLE2 = f"""    
        WHERE "{FIELD_HASH}" IN (%s);
    """

    SELECT_ALL = f'SELECT "{FIELD_SONG_ID}", "{FIELD_OFFSET}" FROM "{FINGERPRINTS_TABLENAME}";'

    SELECT_SONG = f"""
        SELECT
            "{FIELD_SONGNAME}"
        ,   upper(encode("{FIELD_FILE_SHA1}", 'hex')) AS "{FIELD_FILE_SHA1}"
        ,   "{FIELD_TOTAL_HASHES}"
        FROM "{SONGS_TABLENAME}"
        WHERE "{FIELD_SONG_ID}" = %s;
    """

    SELECT_NUM_FINGERPRINTS = f'SELECT COUNT(*) AS n FROM "{FINGERPRINTS_TABLENAME}";'

    SELECT_BLACKLISTED_HASHED = f"""
        SELECT {FIELD_HASH64}
        FROM {FINGERPRINTS_TABLENAME}
        GROUP BY {FIELD_HASH64}
        HAVING COUNT(*) > %s;
    """

    SELECT_UNIQUE_SONG_IDS = f"""
        SELECT COUNT("{FIELD_SONG_ID}") AS n
        FROM "{SONGS_TABLENAME}"
        WHERE "{FIELD_FINGERPRINTED}" = 1;
    """

    SELECT_SONGS = f"""
        SELECT
            "{FIELD_SONG_ID}"
        ,   "{FIELD_SONGNAME}"
        ,   upper(encode("{FIELD_FILE_SHA1}", 'hex')) AS "{FIELD_FILE_SHA1}"
        ,   "{FIELD_TOTAL_HASHES}"
        ,   "date_created"
        FROM "{SONGS_TABLENAME}"
        WHERE "{FIELD_FINGERPRINTED}" = 1;
    """

    SELECT_SONGS_BY_IDS = f"""
        SELECT
            "{FIELD_SONG_ID}"
        ,   "{FIELD_SONGNAME}"
        ,   upper(encode("{FIELD_FILE_SHA1}", 'hex')) AS "{FIELD_FILE_SHA1}"
        ,   "{FIELD_TOTAL_HASHES}"
        ,   "date_created"
        FROM "{SONGS_TABLENAME}" 
    """
    
    # DROPS
    DROP_FINGERPRINTS = F'DROP TABLE IF EXISTS "{FINGERPRINTS_TABLENAME}";'
    DROP_SONGS = F'DROP TABLE IF EXISTS "{SONGS_TABLENAME}";'

    # UPDATE
    UPDATE_SONG_FINGERPRINTED = f"""
        UPDATE "{SONGS_TABLENAME}" SET
            "{FIELD_FINGERPRINTED}" = 1
        ,   "date_modified" = now()
        WHERE "{FIELD_SONG_ID}" = %s;
    """

    # DELETES
    DELETE_UNFINGERPRINTED = f"""
        DELETE FROM "{SONGS_TABLENAME}" WHERE "{FIELD_FINGERPRINTED}" = 0;
    """

    DELETE_SONGS = f"""
        DELETE FROM "{SONGS_TABLENAME}" WHERE "{FIELD_SONG_ID}" IN (%s);
    """

    # IN
    IN_MATCH = f"decode(%s, 'hex')"

    def __init__(self, **options):
        super().__init__()
        self.cursor = cursor_factory(**options)
        self._options = options

        
    def after_fork(self) -> None:
        # Clear the cursor cache, we don't want any stale connections from
        # the previous process.
        Cursor.clear_cache()

    def insert_song(self, song_name: str, file_hash: str, total_hashes: int, cur=None) -> int:
        """
        Inserts a song name into the database, returns the new
        identifier of the song.

        :param song_name: The name of the song.
        :param file_hash: Hash from the fingerprinted file.
        :param total_hashes: amount of hashes to be inserted on fingerprint table.
        :return: the inserted id.
        """
        if cur is not None:
            cur.execute(self.INSERT_SONG, (song_name, file_hash, total_hashes))
            row = cur.fetchone()
            if row:
                return row[0]
            cur.execute(self.SELECT_SONG_ID_BY_NAME, (song_name,))
            return cur.fetchone()[0]
        with self.cursor() as cur:
            cur.execute(self.INSERT_SONG, (song_name, file_hash, total_hashes))
            row = cur.fetchone()
            if row:
                return row[0]
            cur.execute(self.SELECT_SONG_ID_BY_NAME, (song_name,))
            return cur.fetchone()[0]

    def insert_hashes_copy_batch(self, batch: list[tuple[int, list[tuple]]], cur=None) -> None:
        """
        Fast path: COPY a whole batch into a temp table, then INSERT ... ON CONFLICT DO NOTHING.
        batch: [(song_id, hashes), ...]
        """
        if not batch:
            return

        if cur is None:
            with self.cursor() as cur:
                self.insert_hashes_copy_batch(batch, cur=cur)
            return

        cur.execute(f"""
            CREATE TEMP TABLE IF NOT EXISTS {self.COPY_TEMP_TABLE} (
                "{FIELD_SONG_ID}" INT NOT NULL,
                "{FIELD_HASH}" BYTEA,
                "{FIELD_HASH64}" BIGINT,
                "{FIELD_OFFSET}" INT NOT NULL
            ) ON COMMIT DROP;
        """)
        cur.execute(f"TRUNCATE {self.COPY_TEMP_TABLE};")

        buf = io.StringIO()
        for song_id, hashes in batch:
            for item in hashes:
                if len(item) == 3:
                    hsh, hsh_64, offset = item
                elif len(item) == 2:
                    hsh, offset = item
                    hsh_64 = None
                else:
                    raise ValueError(f"Unexpected hash tuple length: {len(item)}")

                hash_text = f"\\\\x{hsh}" if hsh is not None else "\\\\N"
                hash64_text = str(hsh_64) if hsh_64 is not None else "\\\\N"
                buf.write(f"{song_id},{hash_text},{hash64_text},{int(offset)}\n")

        buf.seek(0)
        copy_sql = (
            f'COPY {self.COPY_TEMP_TABLE} ("{FIELD_SONG_ID}","{FIELD_HASH}","{FIELD_HASH64}","{FIELD_OFFSET}") '
            "FROM STDIN WITH (FORMAT csv, NULL '\\N')"
        )
        cur.copy_expert(copy_sql, buf)

        cur.execute(f"""
            INSERT INTO "{FINGERPRINTS_TABLENAME}" (
                "{FIELD_SONG_ID}", "{FIELD_HASH}", "{FIELD_HASH64}", "{FIELD_OFFSET}"
            )
            SELECT "{FIELD_SONG_ID}", "{FIELD_HASH}", "{FIELD_HASH64}", "{FIELD_OFFSET}"
            FROM {self.COPY_TEMP_TABLE}
            ON CONFLICT DO NOTHING;
        """)

    def __getstate__(self):
        return self._options,

    def __setstate__(self, state):
        self._options, = state
        self.cursor = cursor_factory(**self._options)


def cursor_factory(**factory_options):
    def cursor(**options):
        options.update(factory_options)
        return Cursor(**options)
    return cursor


class Cursor(object):
    """
    Establishes a connection to the database and returns an open cursor.
    # Use as context manager
    with Cursor() as cur:
        cur.execute(query)
        ...
    """
    _cache = queue.Queue(maxsize=5)

    def __init__(self, dictionary=False, **options):
        super().__init__()

        conn = None
        try:
            conn = Cursor._cache.get_nowait()
            try:
                if hasattr(conn, "ping"):
                    conn.ping(True)
                elif getattr(conn, "closed", 0) != 0:
                    conn = None
            except Exception:
                conn = None
        except queue.Empty:
            conn = None

        if conn is None:
            conn = psycopg2.connect(**options)

        self.conn = conn
        self.dictionary = dictionary

    @classmethod
    def clear_cache(cls):
        cls._cache = queue.Queue(maxsize=5)

    def __enter__(self):
        if self.dictionary:
            self.cursor = self.conn.cursor(cursor_factory=DictCursor)
        else:
            self.cursor = self.conn.cursor()
        return self.cursor

    def __exit__(self, extype, exvalue, traceback):
        # if we had a PostgreSQL related error we try to rollback the cursor.
        if extype is psycopg2.DatabaseError:
            self.cursor.rollback()

        self.cursor.close()
        self.conn.commit()

        # Put it back on the queue
        try:
            Cursor._cache.put_nowait(self.conn)
        except queue.Full:
            self.conn.close()
