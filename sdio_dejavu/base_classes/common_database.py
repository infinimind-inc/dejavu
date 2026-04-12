import abc
from typing import Dict, List, Tuple
from collections import defaultdict
from sdio_dejavu.base_classes.base_database import BaseDatabase
from loguru import logger
from psycopg2.extras import execute_batch
import time
from functools import lru_cache
from sdio_dejavu.config.settings import (
    FIELD_FILE_SHA1, 
    FIELD_FINGERPRINTED,
    FIELD_HASH, 
    FIELD_OFFSET, 
    FIELD_SONG_ID,
    FIELD_SONGNAME, 
    FIELD_TOTAL_HASHES,
    FINGERPRINTS_TABLENAME, 
    SONGS_TABLENAME,
    DAILY_PARTITION,
    BLACKLISTED_HASH64_COUNT,
    FP_LOAD_BATCHSIZE,
    )

class CommonDatabase(BaseDatabase, metaclass=abc.ABCMeta):
    # Since several methods across different databases are actually just the same
    # I've built this class with the idea to reuse that logic instead of copy pasting
    # over and over the same code.

    def __init__(self):
        super().__init__()
        self.blacklisted_hashes:set[int] = []

    def set_blacklisted_hashes(self,blacklisted_hashes:set[int]):
        self.blacklisted_hashes = blacklisted_hashes

    def before_fork(self) -> None:
        """
        Called before the database instance is given to the new process
        """
        pass

    def after_fork(self) -> None:
        """
        Called after the database instance has been given to the new process

        This will be called in the new process.
        """
        pass

    def setup_old(self) -> None:
        """
        Called on creation or shortly afterwards.
        """
        with self.cursor() as cur:
            cur.execute(self.CREATE_SONGS_TABLE)
            cur.execute(self.CREATE_FINGERPRINTS_TABLE)
            # Skip DELETE_UNFINGERPRINTED to avoid deadlocks
            #cur.execute(self.DELETE_UNFINGERPRINTED)
        self.ensure_daily_partition()
    
    def setup(self) -> None:
        """Safely create tables if missing."""
        with self.cursor() as cur:
            cur.execute(f"""
                SELECT to_regclass('public.{SONGS_TABLENAME}'),
                    to_regclass('public.{FINGERPRINTS_TABLENAME}');
            """)
            songs, fps = cur.fetchone()
            if songs and fps:
                logger.info(f"Fingerprint tables {SONGS_TABLENAME} already exist — skipping DDL.")
                logger.info(f"Fingerprint tables {FINGERPRINTS_TABLENAME} already exist — skipping DDL.")
                return
            logger.info("Creating fingerprint tables...")
            cur.execute(self.CREATE_SONGS_TABLE)
            cur.execute(self.CREATE_FINGERPRINTS_TABLE_SQL)
            #cur.execute(self.CREATE_FINGERPRINTS_TABLE_INDEX_HASH64)
            #cur.execute(self.CREATE_FINGERPRINTS_TABLE_INDEX_SONGID)
        self.ensure_daily_partition()
    
    def empty(self) -> None:
        """
        Called when the database should be cleared of all data.
        """
        with self.cursor() as cur:
            cur.execute(self.DROP_FINGERPRINTS)
            cur.execute(self.DROP_SONGS)

        self.setup()

    def delete_unfingerprinted_songs(self) -> None:
        """
        Called to remove any song entries that do not have any fingerprints
        associated with them.
        """
        with self.cursor() as cur:
            cur.execute(self.DELETE_UNFINGERPRINTED)

    def get_num_songs(self) -> int:
        """
        Returns the song's count stored.

        :return: the amount of songs in the database.
        """
        with self.cursor(buffered=True) as cur:
            cur.execute(self.SELECT_UNIQUE_SONG_IDS)
            count = cur.fetchone()[0] if cur.rowcount != 0 else 0

        return count

    @lru_cache(maxsize=1)
    def get_blacklisted_hashes(
        self, 
        threshold: int = BLACKLISTED_HASH64_COUNT,
    ) -> set[int]:
        """
        缓存高频哈希黑名单。
        这些哈希在数据库中对应过多的 song_id，会导致查询 IO 爆炸且无实际辨识度。
        
        Args:
            threshold: 频率阈值，count 超过此值的 hash 将被过滤。
            
        Returns:
            set: 包含所有垃圾 hash64 的集合，O(1) 查询效率。
        """
        # 这里的查询要针对你的单列索引优化

        with self.cursor() as cur:
            logger.info(f"Loading blacklisted hashes (threshold > {threshold})...")
            cur.execute(self.SELECT_BLACKLISTED_HASHED_VIEW, (threshold,))
            # fetchall 返回的是 list[tuple]，转换成 set 加速后续对比
            rows = cur.fetchall()
            blacklist = {row[0] for row in rows}
            
        logger.info(f"Blacklist loaded: {len(blacklist)} noisy hashes filtered.")
        return blacklist

    def get_num_fingerprints(self) -> int:
        """
        Returns the fingerprints' count stored.

        :return: the number of fingerprints in the database.
        """
        with self.cursor(buffered=True) as cur:
            cur.execute(self.SELECT_NUM_FINGERPRINTS)
            count = cur.fetchone()[0] if cur.rowcount != 0 else 0

        return count

    def set_song_fingerprinted(self, song_id, cur=None):
        """
        Sets a specific song as having all fingerprints in the database.

        :param song_id: song identifier.
        """
        if cur is not None:
            cur.execute(self.UPDATE_SONG_FINGERPRINTED, (song_id,))
            return

        with self.cursor() as db_cur:
            db_cur.execute(self.UPDATE_SONG_FINGERPRINTED, (song_id,))

    def get_songs(self) -> List[Dict[str, str]]:
        """
        Returns all fully fingerprinted songs in the database

        :return: a dictionary with the songs info.
        """
        with self.cursor(dictionary=True) as cur:
            cur.execute(self.SELECT_SONGS)
            return list(cur)
    
    def get_songs_by_ids(self, song_ids: List[int]) -> List[Dict]:
        if not song_ids: return []
        format_strings = ','.join(['%s'] * len(song_ids))
        query = self.SELECT_SONGS_BY_IDS + f" WHERE {FIELD_SONG_ID} IN ({format_strings})"
        with self.cursor(dictionary=True) as cur:
            cur.execute(query, song_ids)
            return list(cur)

    def get_song_by_id(self, song_id: int) -> Dict[str, str]:
        """
        Brings the song info from the database.

        :param song_id: song identifier.
        :return: a song by its identifier. Result must be a Dictionary.
        """
        with self.cursor(dictionary=True) as cur:
            cur.execute(self.SELECT_SONG, (song_id,))
            return cur.fetchone()

    def get_fingerprints_by_song_name(
        self,
        cm_id: str
    ) -> list[Tuple[int, int]]:
        """
        Fetch fingerprints for a given cm_id.

        Returns:
            [(hex_hash, hash64, offset), ...]
        """

        results: list[Tuple[int, int]] = []

        with self.cursor() as cur:
            cur.execute(
                self.SELECT_FINGERPRINTS_BY_SONG_NAME,
                (cm_id,)
            )

            for hash64, offset in cur:
                # defensive: hash64 must exist
                if hash64 is None:
                    continue

                results.append(
                    (int(hash64), int(offset))
                )

        return results
    
    def get_fingerprints_by_song_name_list(
        self,
        cm_ids: list[str],
        batch_size:int = FP_LOAD_BATCHSIZE,
    ) -> dict[str,list[Tuple[int, int]]]:
        """
        Fetch fingerprints for a given cm_id.

        Returns:
            [(hex_hash, hash64, offset), ...]
        """
        all_fps = defaultdict(list)
        total = len(cm_ids)
        logger.info(f"Starting to load fingerprints for {total} CMs...")
        for i in range(0, total, batch_size):
            batch = cm_ids[i:i + batch_size]
            placeholders = ','.join(['%s'] * len(batch))
            current_sql = self.SELECT_FINGERPRINTS_BY_SONG_NAME_LIST.format(placeholders)
            try:
                with self.cursor() as cur:
                    cur.execute(
                        current_sql,
                        batch
                    )
                    rows_fetched = 0
                    for cm_name, hash64, offset in cur:
                        # defensive: hash64 must exist
                        if hash64 is not None:
                            all_fps[cm_name].append((int(hash64), int(offset)))
                            rows_fetched += 1
                    logger.debug(f"Batch {i//batch_size + 1}: Queried {len(batch)} CMs, Found {rows_fetched} fingerprint rows.")
            except Exception as e:
                logger.error(f"Error in batch {i}: {e}")
                raise e
        logger.success(f"Fingerprint loading complete. Total unique CMs in map: {len(all_fps)}")

        missing = set(cm_ids) - set(all_fps.keys())
        if missing:
            logger.warning(f"{len(missing)} CMs had no fingerprints found in DB. Sample: {list(missing)[:3]}")
        return all_fps

    def insert(self, fingerprint: str, song_id: int, offset: int):
        """
        Inserts a single fingerprint into the database.

        :param fingerprint: Part of a sha1 hash, in hexadecimal format
        :param song_id: Song identifier this fingerprint is off
        :param offset: The offset this fingerprint is from.
        """
        with self.cursor() as cur:
            cur.execute(self.INSERT_FINGERPRINT, (fingerprint, song_id, offset))

    @abc.abstractmethod
    def insert_song(self, song_name: str, file_hash: str, total_hashes: int, cur=None) -> int:
        """
        Inserts a song name into the database, returns the new
        identifier of the song.

        :param song_name: The name of the song.
        :param file_hash: Hash from the fingerprinted file.
        :param total_hashes: amount of hashes to be inserted on fingerprint table.
        :return: the inserted id.
        """
        pass

    @abc.abstractmethod
    def ensure_daily_partition(self) -> None:
        """Ensures that a daily partition exists for the current date."""
        pass


    def query(self, fingerprint: str = None) -> List[Tuple]:
        """
        Returns all matching fingerprint entries associated with
        the given hash as parameter, if None is passed it returns all entries.

        :param fingerprint: part of a sha1 hash, in hexadecimal format
        :return: a list of fingerprint records stored in the db.
        """
        with self.cursor() as cur:
            if fingerprint:
                cur.execute(self.SELECT, (fingerprint,))
            else:  # select all if no key
                cur.execute(self.SELECT_ALL)
            return list(cur)

    def get_iterable_kv_pairs(self) -> List[Tuple]:
        """
        Returns all fingerprints in the database.

        :return: a list containing all fingerprints stored in the db.
        """
        return self.query(None)

    def insert_hashes(
        self,
        song_id: int,
        hashes: list[Tuple[str, int, int]],
        batch_size: int = 1000,
        cur=None,
    ) -> None:
        """
        Insert a multitude of fingerprints.

        :param song_id: Song identifier the fingerprints belong to
        :param hashes: A sequence of tuples in the format (hash, offset)
            - hash: Part of a sha1 hash, in hexadecimal format
            - offset: Offset this hash was created from/at.
        :param batch_size: insert batches.
        """
        self.ensure_daily_partition()
        values = [(song_id, hsh, hsh_64,int(offset)) for hsh, hsh_64,offset in hashes]

        if cur is not None:
            for index in range(0, len(values), batch_size):
                execute_batch(cur, self.INSERT_FINGERPRINT, values[index: index + batch_size], batch_size)
            return

        with self.cursor() as db_cur:
            for index in range(0, len(values), batch_size):
                execute_batch(db_cur, self.INSERT_FINGERPRINT, values[index: index + batch_size], batch_size)

    def insert_song_with_hashes(
        self,
        song_name: str,
        file_hash: str,
        hashes: list[Tuple[str, int, int]],
        batch_size: int = 1000,
    ) -> int:
        """
        Insert the song row and all fingerprint rows in a single DB transaction.
        """
        with self.cursor() as cur:
            sid = self.insert_song(song_name, file_hash, len(hashes), cur=cur)
            self.insert_hashes(sid, hashes, batch_size=batch_size, cur=cur)
            self.set_song_fingerprinted(sid, cur=cur)
            return sid

    def return_matches(self, hashes: List[Tuple[str, int]],
                       batch_size: int = 1000) -> Tuple[List[Tuple[int, int]], Dict[int, int]]:
        """
        Searches the database for pairs of (hash, offset) values.

        :param hashes: A sequence of tuples in the format (hash, offset)
            - hash: Part of a sha1 hash, in hexadecimal format
            - offset: Offset this hash was created from/at.
        :param batch_size: number of query's batches.
        :return: a list of (sid, offset_difference) tuples and a
        dictionary with the amount of hashes matched (not considering
        duplicated hashes) in each song.
            - song id: Song identifier
            - offset_difference: (database_offset - sampled_offset)
        """
        # Create a dictionary of hash => offset pairs for later lookups
        # Normalize all hashes to uppercase once
        mapper = defaultdict(list)
        for hsh, offset in hashes:
            mapper[hsh.upper()].append(offset)

        values = list(mapper.keys())
        dedup_hashes = defaultdict(int)
        # in order to count each hash only once per db offset we use the dic below
        results = []
        
        with self.cursor() as cur:
            for index in range(0, len(values), batch_size):
                # Create our IN part of the query
                query = self.SELECT_MULTIPLE % ', '.join([self.IN_MATCH] * len(values[index: index + batch_size]))

                cur.execute(query, values[index: index + batch_size])

                # Iterate over all DB matches
                for hsh, sid, db_offset in cur:
                    dedup_hashes[sid] += 1
                    # vectorized offset diff append (faster than nested loop append)
                    sample_offsets = mapper[hsh]
                    diff = db_offset - sample_offsets[0]
                    if len(sample_offsets) == 1:
                        results.append((sid, diff))
                    else:
                        results.extend((sid, db_offset - s_off) for s_off in sample_offsets)

            return results, dedup_hashes
    
    def return_matches_hash64_unnest(
        self,
        hashes: list[tuple[int, int]],
        verbose:bool = False,
    ) -> tuple[list[tuple[int, int, int]], dict[int, int]]:

        if not hashes:
            return [], {}

        hash64_list = []
        offset_list = []

        for hash64, offset in hashes:
            hash64_list.append(hash64)
            offset_list.append(offset)

        results = []
        dedup_hashes = defaultdict(int)

        with self.cursor() as cur:
            cur.execute(self.MATCHES_HASH64_UNNEST_GROUPED, (hash64_list, offset_list))

            for song_id, offset_diff, vote_count in cur:
                results.append((song_id, offset_diff, vote_count))
                dedup_hashes[song_id] += vote_count
        return results, dedup_hashes


    def return_matches_hash64(
            self, 
            hashes: list[Tuple[int, int]], 
            batch_size: int = 5000,
            verbose:bool = False,
        ) -> tuple[list[tuple[int, int]], dict[int, int]]:
        t_start = time.perf_counter()
        blocked = 0
        # 1. 预处理
        mapper = defaultdict(list)
        for hash64, offset in hashes:
            if hash64 not in self.blacklisted_hashes:
                mapper[hash64].append(offset)
            else:
                blocked+=1
        values = list(mapper.keys())
        
        t_preprocessed = time.perf_counter()
        
        dedup_hashes = defaultdict(int)
        results = []
        
        total_sql_time = 0
        total_fetch_time = 0
        total_post_time = 0
        total_rows = 0

        with self.cursor() as cur:
            for index in range(0, len(values), batch_size):
                batch = values[index:index + batch_size]
                placeholders = ', '.join(['%s'] * len(batch))
                query = self.SELECT_MULTIPLE_INT64 % placeholders

                # 测量 SQL 执行（发送到接收响应）
                t1 = time.perf_counter()
                cur.execute(query, batch)
                t2 = time.perf_counter()
                total_sql_time += (t2 - t1)

                # 测量数据抓取（内存反序列化）
                rows = cur.fetchall()
                t3 = time.perf_counter()
                total_fetch_time += (t3 - t2)
                
                total_rows += len(rows)

                # 测量业务计算
                for hash64, sid, db_offset in rows:
                    dedup_hashes[sid] += 1
                    sample_offsets = mapper[hash64]
                    for s_off in sample_offsets:
                        results.append((sid, db_offset - s_off))
                t4 = time.perf_counter()
                total_post_time += (t4 - t3)

        t_end = time.perf_counter()

        if verbose:
            logger.info(f"--- Performance Report ---")
            logger.info(f"Input Hashes: {len(hashes)} | Unique Hashes: {len(values)}")
            logger.info(f"Blocked Hashes: {blocked} | Unique Hashes: {len(values)}")
            logger.info(f"Total Rows Found: {total_rows} | Result Size: {len(results)}")
            logger.info(f"Total Time: {t_end - t_start:.4f}s")
            logger.info(f"  - Preprocessing: {t_preprocessed - t_start:.4f}s")
            logger.info(f"  - DB Execute (Pure SQL): {total_sql_time:.4f}s")
            logger.info(f"  - DB Fetch (Serialization): {total_fetch_time:.4f}s")
            logger.info(f"  - Post-processing (Python Loop): {total_post_time:.4f}s")
            logger.info(f"--------------------------")

        return results, dedup_hashes

    def return_matches_by_table(
            self, 
            hashes: List[Tuple[str, int]],
            table_name:str,
            batch_size: int = 1000
        ) -> Tuple[List[Tuple[int, int]], Dict[int, int]]:
        """
        Searches the database for pairs of (hash, offset) values.

        :param hashes: A sequence of tuples in the format (hash, offset)
            - hash: Part of a sha1 hash, in hexadecimal format
            - offset: Offset this hash was created from/at.
        :param batch_size: number of query's batches.
        :return: a list of (sid, offset_difference) tuples and a
        dictionary with the amount of hashes matched (not considering
        duplicated hashes) in each song.
            - song id: Song identifier
            - offset_difference: (database_offset - sampled_offset)
        """
        # Create a dictionary of hash => offset pairs for later lookups
        # Normalize all hashes to uppercase once
        mapper = defaultdict(list)
        for hsh, offset in hashes:
            mapper[hsh.upper()].append(offset)

        values = list(mapper.keys())
        dedup_hashes = defaultdict(int)
        # in order to count each hash only once per db offset we use the dic below
        results = []
        
        with self.cursor() as cur:
            for index in range(0, len(values), batch_size):
                # Create our IN part of the query
                query = self.SELECT_MULTIPLE1 + table_name + self.SELECT_MULTIPLE2 % ', '.join([self.IN_MATCH] * len(values[index: index + batch_size]))

                cur.execute(query, values[index: index + batch_size])

                # Iterate over all DB matches
                for hsh, sid, db_offset in cur:
                    dedup_hashes[sid] += 1
                    # vectorized offset diff append (faster than nested loop append)
                    sample_offsets = mapper[hsh]
                    diff = db_offset - sample_offsets[0]
                    if len(sample_offsets) == 1:
                        results.append((sid, diff))
                    else:
                        results.extend((sid, db_offset - s_off) for s_off in sample_offsets)

            return results, dedup_hashes

    def delete_songs_by_id(self, song_ids: List[int], batch_size: int = 1000) -> None:
        """
        Given a list of song ids it deletes all songs specified and their corresponding fingerprints.

        :param song_ids: song ids to be deleted from the database.
        :param batch_size: number of query's batches.
        """
        with self.cursor() as cur:
            for index in range(0, len(song_ids), batch_size):
                # Create our IN part of the query
                query = self.DELETE_SONGS % ', '.join(['%s'] * len(song_ids[index: index + batch_size]))

                cur.execute(query, song_ids[index: index + batch_size])
