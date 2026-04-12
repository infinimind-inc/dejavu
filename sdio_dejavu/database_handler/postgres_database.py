import queue

import psycopg2
from psycopg2 import extensions
from psycopg2.extras import DictCursor
from loguru import logger
from datetime import datetime, timedelta
from sdio_dejavu.base_classes.common_database import CommonDatabase
from sdio_dejavu.config.settings import (FIELD_FILE_SHA1, FIELD_FINGERPRINTED,
                                    FIELD_HASH, FIELD_OFFSET, FIELD_SONG_ID,
                                    FIELD_HASH64,
                                    FIELD_SONGNAME, FIELD_TOTAL_HASHES,
                                    FINGERPRINTS_TABLENAME, SONGS_TABLENAME,DAILY_PARTITION)

PK_SONG_ID_CONSTRAINT = f"pk_{SONGS_TABLENAME}_{FIELD_SONG_ID}"
SONG_NAME_UNIQUE_INDEX = f"{SONGS_TABLENAME}_{FIELD_SONGNAME}_uk"
FINGERPRINTS_UNIQUE_CONSTRAINT = f"uq_{FINGERPRINTS_TABLENAME}"
FINGERPRINTS_HASH64_INDEX = f"ix_{FINGERPRINTS_TABLENAME}_{FIELD_HASH64}"
FINGERPRINTS_SONG_ID_INDEX = f"ix_{FINGERPRINTS_TABLENAME}_{FIELD_SONG_ID}"
LEGACY_FINGERPRINT_LOOKUP_INDEX = "idx_fingerprints_lookup_optimized"
FINGERPRINT_LOOKUP_INDEX = (
    LEGACY_FINGERPRINT_LOOKUP_INDEX
    if FINGERPRINTS_TABLENAME == "fp_audio_fingerprints_prod"
    else f"idx_{FINGERPRINTS_TABLENAME}_lookup_optimized"
)
FINGERPRINT_INDEX_LAYOUT_LOCK = 2026041202


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

    CREATE_CREATIVE_TABLE_INDEX = (
        f'CREATE UNIQUE INDEX IF NOT EXISTS "{SONG_NAME_UNIQUE_INDEX}" '
        f'ON "{SONGS_TABLENAME}" ("{FIELD_SONGNAME}");'
    )


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

        CONSTRAINT "fk_{FINGERPRINTS_TABLENAME}_{FIELD_SONG_ID}"
            FOREIGN KEY ("{FIELD_SONG_ID}")
            REFERENCES "{SONGS_TABLENAME}"("{FIELD_SONG_ID}")
            ON DELETE CASCADE
    );
    """

    CREATE_FINGERPRINTS_TABLE_INDEX_HASH64 = f"""
    CREATE INDEX IF NOT EXISTS
        "{FINGERPRINTS_HASH64_INDEX}"
    ON "{FINGERPRINTS_TABLENAME}"
    USING btree ("{FIELD_HASH64}");
    """

    CREATE_FINGERPRINTS_TABLE_INDEX_SONGID = f"""
    CREATE INDEX IF NOT EXISTS
        "{FINGERPRINTS_SONG_ID_INDEX}"
    ON "{FINGERPRINTS_TABLENAME}" ("{FIELD_SONG_ID}");
    """

    CREATE_FINGERPRINTS_TABLE_INDEX_ALL = f"""
    CREATE INDEX IF NOT EXISTS "{FINGERPRINT_LOOKUP_INDEX}"
    ON "{FINGERPRINTS_TABLENAME}" ("{FIELD_HASH64}")
    INCLUDE ("{FIELD_SONG_ID}", "{FIELD_OFFSET}");"""

    DROP_FINGERPRINTS_TABLE_INDEX_HASH64 = f"""
    DROP INDEX IF EXISTS "{FINGERPRINTS_HASH64_INDEX}";
    """

    RENAME_FINGERPRINT_LOOKUP_INDEX = f"""
    ALTER INDEX "{LEGACY_FINGERPRINT_LOOKUP_INDEX}"
    RENAME TO "{FINGERPRINT_LOOKUP_INDEX}";
    """

    DROP_FINGERPRINTS_TABLE_UNIQUE_CONSTRAINT = f"""
    ALTER TABLE "{FINGERPRINTS_TABLENAME}"
    DROP CONSTRAINT IF EXISTS "{FINGERPRINTS_UNIQUE_CONSTRAINT}";
    """

    CREATE_FINGERPRINTS_TABLE_SQL = (
        CREATE_FINGERPRINTS_TABLE_DEFAULT
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

    INSERT_SONG = f"""
        INSERT INTO "{SONGS_TABLENAME}" ("{FIELD_SONGNAME}", "{FIELD_FILE_SHA1}","{FIELD_TOTAL_HASHES}")
        VALUES (%s, decode(%s, 'hex'), %s)
        RETURNING "{FIELD_SONG_ID}";
    """

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

    MATCHES_HASH64_UNNEST_GROUPED = f"""
    WITH input_hashes({FIELD_HASH64}, input_offset) AS (
        SELECT *
        FROM UNNEST(%s::bigint[], %s::int[])
    )
    SELECT
        f.{FIELD_SONG_ID},
        f.{FIELD_OFFSET} - i.input_offset AS offset_diff,
        COUNT(*) AS vote_count
    FROM input_hashes i
    JOIN {FINGERPRINTS_TABLENAME} f
      ON f.{FIELD_HASH64} = i.{FIELD_HASH64}
    GROUP BY
        f.{FIELD_SONG_ID},
        f.{FIELD_OFFSET} - i.input_offset;
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

    SELECT_BLACKLISTED_HASHED_VIEW = f"""SELECT hash64 FROM fp_hash_stats WHERE freq > %s;"""

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

    def setup(self) -> None:
        super().setup()
        self.ensure_song_name_unique_index()
        self.ensure_fingerprint_index_layout()

    def ensure_song_name_unique_index(self) -> None:
        with self.cursor() as cur:
            cur.execute(self.CREATE_CREATIVE_TABLE_INDEX)

    def ensure_fingerprint_index_layout(self) -> None:
        """
        Keep fingerprint-table indexes aligned with the production layout:
        - keep song_id btree index
        - keep one covering hash64 lookup index
        - remove the redundant plain hash64 index
        - remove the legacy unique constraint on fingerprints
        """
        table_regclass = f"public.{FINGERPRINTS_TABLENAME}"
        uses_legacy_lookup_name = FINGERPRINT_LOOKUP_INDEX == LEGACY_FINGERPRINT_LOOKUP_INDEX

        with self.cursor() as cur:
            # Use a transaction-scoped lock so failed DDL cannot strand a session-level lock
            # on a pooled connection.
            cur.execute("SELECT pg_advisory_xact_lock(%s);", (FINGERPRINT_INDEX_LAYOUT_LOCK,))

            cur.execute(
                """
                SELECT indexname
                FROM pg_indexes
                WHERE schemaname = current_schema()
                  AND tablename = %s
                  AND indexname IN (%s, %s);
                """,
                (
                    FINGERPRINTS_TABLENAME,
                    FINGERPRINT_LOOKUP_INDEX,
                    LEGACY_FINGERPRINT_LOOKUP_INDEX,
                ),
            )
            existing_lookup_indexes = {row[0] for row in cur.fetchall()}
            has_desired_lookup_index = FINGERPRINT_LOOKUP_INDEX in existing_lookup_indexes
            has_legacy_lookup_index = LEGACY_FINGERPRINT_LOOKUP_INDEX in existing_lookup_indexes

            cur.execute(
                """
                SELECT 1
                FROM pg_indexes
                WHERE schemaname = current_schema()
                  AND tablename = %s
                  AND indexname = %s;
                """,
                (FINGERPRINTS_TABLENAME, FINGERPRINTS_HASH64_INDEX),
            )
            has_plain_hash64_index = cur.fetchone() is not None

            cur.execute(
                """
                SELECT 1
                FROM pg_constraint
                WHERE conname = %s
                  AND conrelid = to_regclass(%s);
                """,
                (FINGERPRINTS_UNIQUE_CONSTRAINT, table_regclass),
            )
            has_unique_constraint = cur.fetchone() is not None

            if has_legacy_lookup_index and not uses_legacy_lookup_name:
                logger.info(
                    "Renaming legacy fingerprint lookup index {} to {} on {}.",
                    LEGACY_FINGERPRINT_LOOKUP_INDEX,
                    FINGERPRINT_LOOKUP_INDEX,
                    FINGERPRINTS_TABLENAME,
                )
                cur.execute(self.RENAME_FINGERPRINT_LOOKUP_INDEX)
                has_desired_lookup_index = True

            if not has_desired_lookup_index:
                logger.info(
                    "Creating covering fingerprint lookup index {} on {}.",
                    FINGERPRINT_LOOKUP_INDEX,
                    FINGERPRINTS_TABLENAME,
                )
                cur.execute(self.CREATE_FINGERPRINTS_TABLE_INDEX_ALL)

            cur.execute(self.CREATE_FINGERPRINTS_TABLE_INDEX_SONGID)

            if has_plain_hash64_index:
                logger.info(
                    "Dropping redundant plain hash64 index {} on {}.",
                    FINGERPRINTS_HASH64_INDEX,
                    FINGERPRINTS_TABLENAME,
                )
                cur.execute(self.DROP_FINGERPRINTS_TABLE_INDEX_HASH64)

            if has_unique_constraint:
                logger.info(
                    "Dropping legacy fingerprint unique constraint {} on {}.",
                    FINGERPRINTS_UNIQUE_CONSTRAINT,
                    FINGERPRINTS_TABLENAME,
                )
                cur.execute(self.DROP_FINGERPRINTS_TABLE_UNIQUE_CONSTRAINT)
    
    def ensure_daily_partition(self) -> None:
        if DAILY_PARTITION:
            pass
        else:
            return
        today = datetime.now().date()
        tomorrow = today + timedelta(days=1)
        part_name = f'{FINGERPRINTS_TABLENAME}_{today.year}_{today.month:02d}_{today.day:02d}'
        start = f"{today} 00:00:00+09"
        end = f"{tomorrow} 00:00:00+09"

        with self.cursor() as cur:
            # 20251107: Advisory lock for daily partition creation (fingerprints)
            try:
                cur.execute("SELECT pg_advisory_lock(20251107);")


                cur.execute(f"""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM pg_tables WHERE tablename = '{part_name}'
                        ) THEN
                            EXECUTE format('
                                CREATE TABLE IF NOT EXISTS {part_name}
                                PARTITION OF {FINGERPRINTS_TABLENAME}
                                FOR VALUES FROM (%L) TO (%L);
                            ', '{start}', '{end}');
                        END IF;
                    END $$;
                """)
            finally:
                # Release the lock
                cur.execute("SELECT pg_advisory_unlock(20251107);")

        
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
        retried = False
        while True:
            if cur is None:
                with self.cursor() as db_cur:
                    try:
                        db_cur.execute(self.INSERT_SONG, (song_name, file_hash, total_hashes))
                        return db_cur.fetchone()[0]
                    except psycopg2.errors.UniqueViolation as e:
                        constraint_name = getattr(getattr(e, "diag", None), "constraint_name", "")
                        is_song_id_pk_collision = (
                            constraint_name == PK_SONG_ID_CONSTRAINT
                            or PK_SONG_ID_CONSTRAINT in str(e)
                        )
                        if not is_song_id_pk_collision or retried:
                            raise

                        # Sequence drift can cause PK collision on song_id. Realign and retry once.
                        db_cur.connection.rollback()
                        next_song_id = self._sync_song_id_sequence(db_cur)
                        logger.warning(
                            "[FP][DB] synced {} sequence to {} after PK collision; retry insert for song_name={}",
                            FIELD_SONG_ID,
                            next_song_id,
                            song_name,
                        )
                        retried = True
                continue

            try:
                cur.execute(self.INSERT_SONG, (song_name, file_hash, total_hashes))
                return cur.fetchone()[0]
            except psycopg2.errors.UniqueViolation as e:
                constraint_name = getattr(getattr(e, "diag", None), "constraint_name", "")
                is_song_id_pk_collision = (
                    constraint_name == PK_SONG_ID_CONSTRAINT
                    or PK_SONG_ID_CONSTRAINT in str(e)
                )
                if not is_song_id_pk_collision or retried:
                    raise

                # Sequence drift can cause PK collision on song_id. Realign and retry once.
                cur.connection.rollback()
                next_song_id = self._sync_song_id_sequence(cur)
                logger.warning(
                    "[FP][DB] synced {} sequence to {} after PK collision; retry insert for song_name={}",
                    FIELD_SONG_ID,
                    next_song_id,
                    song_name,
                )
                retried = True

    def _sync_song_id_sequence(self, cur) -> int:
        cur.execute(f'SELECT COALESCE(MAX("{FIELD_SONG_ID}"), 0) + 1 FROM "{SONGS_TABLENAME}"')
        next_song_id = int(cur.fetchone()[0] or 1)
        cur.execute(
            "SELECT setval(pg_get_serial_sequence(%s, %s), %s, false)",
            (SONGS_TABLENAME, FIELD_SONG_ID, next_song_id),
        )
        return next_song_id

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
        while conn is None:
            try:
                cached_conn = Cursor._cache.get_nowait()
            except queue.Empty:
                break

            try:
                if cached_conn.closed:
                    cached_conn.close()
                    continue

                tx_status = cached_conn.get_transaction_status()
                if tx_status == extensions.TRANSACTION_STATUS_UNKNOWN:
                    cached_conn.close()
                    continue

                if tx_status != extensions.TRANSACTION_STATUS_IDLE:
                    cached_conn.rollback()

                conn = cached_conn
            except Exception:
                try:
                    cached_conn.close()
                except Exception:
                    pass

        if conn is None:
            conn = psycopg2.connect(**options)

        self.conn = conn
        self.dictionary = dictionary

    @classmethod
    def clear_cache(cls):
        while True:
            try:
                conn = cls._cache.get_nowait()
            except queue.Empty:
                break
            try:
                conn.close()
            except Exception:
                pass
        cls._cache = queue.Queue(maxsize=5)

    def __enter__(self):
        if self.dictionary:
            self.cursor = self.conn.cursor(cursor_factory=DictCursor)
        else:
            self.cursor = self.conn.cursor()
        return self.cursor

    def __exit__(self, extype, exvalue, traceback):
        keep_connection = False
        try:
            self.cursor.close()
            if extype is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            keep_connection = not self.conn.closed
        except Exception:
            try:
                self.conn.close()
            except Exception:
                pass
            raise

        if not keep_connection:
            return

        # Put it back on the queue
        try:
            Cursor._cache.put_nowait(self.conn)
        except queue.Full:
            self.conn.close()
