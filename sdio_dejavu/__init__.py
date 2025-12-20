import multiprocessing
import os
import sys
import traceback
from itertools import groupby
import time
from typing import Dict, List, Tuple
import numpy as np
from hashlib import sha1
import concurrent
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import date, timedelta
import sdio_dejavu.logic.decoder as decoder
from sdio_dejavu.base_classes.base_database import get_database
from sdio_dejavu.config.settings import (DEFAULT_FS, DEFAULT_OVERLAP_RATIO,
                                    DEFAULT_WINDOW_SIZE, FIELD_FILE_SHA1,
                                    FIELD_TOTAL_HASHES,
                                    FINGERPRINTED_CONFIDENCE,
                                    FINGERPRINTED_HASHES, HASHES_MATCHED,
                                    INPUT_CONFIDENCE, INPUT_HASHES, OFFSET,
                                    OFFSET_SECS, SONG_ID, SONG_NAME, TOPN)
from sdio_dejavu.logic.fingerprint import fingerprint
from loguru import logger

class Dejavu:
    def __init__(self, config):
        self.config = config

        # initialize db
        db_cls = get_database(config.get("database_type", "mysql").lower())

        self.db = db_cls(**config.get("database", {}))
        self.db.setup()

        # if we should limit seconds fingerprinted,
        # None|-1 means use entire track
        self.limit = self.config.get("fingerprint_limit", None)
        if self.limit == -1:  # for JSON compatibility
            self.limit = None
        self.__load_fingerprinted_audio_hashes()

    def __load_fingerprinted_audio_hashes(self) -> None:
        """
        Keeps a dictionary with the hashes of the fingerprinted songs, in that way is possible to check
        whether or not an audio file was already processed.
        """
        # get songs previously indexed
        self.songs = self.db.get_songs()
        self.songhashes_set = set()  # to know which ones we've computed before
        for song in self.songs:
            song_hash = song[FIELD_FILE_SHA1]
            self.songhashes_set.add(song_hash)

    def get_fingerprinted_songs(self) -> List[Dict[str, any]]:
        """
        To pull all fingerprinted songs from the database.

        :return: a list of fingerprinted audios from the database.
        """
        return self.db.get_songs()

    def delete_songs_by_id(self, song_ids: List[int]) -> None:
        """
        Deletes all audios given their ids.

        :param song_ids: song ids to delete from the database.
        """
        self.db.delete_songs_by_id(song_ids)
    
    def fingerprint_media_list(
        self,
        media_list: list[str],
        nprocesses: int | None = None   # kept for compatibility but unused
    ):
        # No parallelism → always sequential
        failed_files = []

        # Build work items early
        worker_input = [
            (filename, self.limit)
            for filename in media_list
            if decoder.unique_hash(filename) not in self.songhashes_set
        ]
        logger.info(f"[FP] sequential fingerprinting {len(worker_input)} files")

        start_time = time.perf_counter()
        completed = 0
        timeout_s = 120  # per-file guard

        for filename, limit in worker_input:
            try:
                logger.debug(f"[FP] processing: {filename}")

                # Run worker directly (no executor)
                # Wrap inside a timeout using signal (UNIX only)
                result = Dejavu._fingerprint_worker((filename, limit))

                # song_name, hashes, file_hash
                song_name, hashes, file_hash = result

                # DB operations
                with self.db.cursor() as cur:
                    sid = self.db.insert_song(song_name, file_hash, len(hashes))
                    self.db.insert_hashes(sid, hashes)
                    self.db.set_song_fingerprinted(sid)

                completed += 1
                if completed % 50 == 0:
                    logger.info(
                        f"[FP] progress: {completed}/{len(worker_input)} "
                        f"(elapsed {time.perf_counter() - start_time:.1f}s)"
                    )

            except Exception as e:
                logger.exception(f"[FP] failed: {filename} | {e}")
                failed_files.append(filename)

        logger.info(
            f"[FP] done. ok={completed} fail={len(failed_files)} "
            f"elapsed={time.perf_counter()-start_time:.1f}s"
        )
        return failed_files


    def fingerprint_media_list_multiprocess(
        self, 
        media_list: list[str], 
        nprocesses: int | None = None
        ):
        nprocesses = nprocesses or max(1, min(4, os.cpu_count() or 2))
        failed_files = []

        # Build work items early to avoid surprises from generator laziness
        worker_input = [
            (filename, self.limit)
            for filename in media_list
            if decoder.unique_hash(filename) not in self.songhashes_set
        ]
        logger.info(f"[FP] submitting {len(worker_input)} files with {nprocesses} processes")

        start_time = time.perf_counter()
        submitted = {}
        completed = 0

        # Small chunks keep latency predictable
        timeout_s = 120  # per-file guard; tune to your media
        with ProcessPoolExecutor(max_workers=nprocesses, mp_context=multiprocessing.get_context("spawn")) as ex:
            futures = []
            for item in worker_input:
                fn = item[0]
                fut = ex.submit(Dejavu._fingerprint_worker, item)
                submitted[fut] = fn
                futures.append(fut)
                logger.debug(f"[FP] submitted: {fn}")

            for fut in as_completed(futures, timeout=None):
                fn = submitted[fut]
                try:
                    song_name, hashes, file_hash = fut.result(timeout=timeout_s)
                    # DB writes in parent only (good). Wrap in retry + timeout.
                    with self.db.cursor() as cur:
                        sid = self.db.insert_song(song_name, file_hash, len(hashes))
                        self.db.insert_hashes(sid, hashes)
                        self.db.set_song_fingerprinted(sid)
                    completed += 1
                    if completed % 50 == 0:
                        logger.info(f"[FP] progress: {completed}/{len(futures)} (elapsed {time.perf_counter()-start_time:.1f}s)")
                except concurrent.futures.TimeoutError:
                    logger.error(f"[FP] timeout: {fn}")
                    failed_files.append(fn)
                except Exception as e:
                    logger.exception(f"[FP] failed: {fn} | {e}")
                    failed_files.append(fn)

        logger.info(f"[FP] done. ok={completed} fail={len(failed_files)} elapsed={time.perf_counter()-start_time:.1f}s")
        return failed_files



    def fingerprint_directory(self, path: str, extensions: str, nprocesses: int = None) -> None:
        """
        Given a directory and a set of extensions it fingerprints all files that match each extension specified.

        :param path: path to the directory.
        :param extensions: list of file extensions to consider.
        :param nprocesses: amount of processes to fingerprint the files within the directory.
        """
        # Try to use the maximum amount of processes if not given.
        try:
            nprocesses = nprocesses or multiprocessing.cpu_count()
        except NotImplementedError:
            nprocesses = 1
        else:
            nprocesses = 1 if nprocesses <= 0 else nprocesses

        pool = multiprocessing.Pool(nprocesses)

        filenames_to_fingerprint = []
        for filename, _ in decoder.find_files(path, extensions):
            # don't refingerprint already fingerprinted files
            if decoder.unique_hash(filename) in self.songhashes_set:
                print(f"{filename} already fingerprinted, continuing...")
                continue

            filenames_to_fingerprint.append(filename)

        # Prepare _fingerprint_worker input
        worker_input = list(zip(filenames_to_fingerprint, [self.limit] * len(filenames_to_fingerprint)))

        # Send off our tasks
        iterator = pool.imap_unordered(Dejavu._fingerprint_worker, worker_input)

        # Loop till we have all of them
        while True:
            try:
                song_name, hashes, file_hash = next(iterator)
            except multiprocessing.TimeoutError:
                continue
            except StopIteration:
                break
            except Exception:
                print("Failed fingerprinting")
                # Print traceback because we can't reraise it here
                traceback.print_exc(file=sys.stdout)
            else:
                sid = self.db.insert_song(song_name, file_hash, len(hashes))

                self.db.insert_hashes(sid, hashes)
                self.db.set_song_fingerprinted(sid)
                self.__load_fingerprinted_audio_hashes()

        pool.close()
        pool.join()

    def get_fingerprint_hash(
            self,
            file_path:str,
            song_name:str = ""
            ):
        try:
            _, hashes, _ = Dejavu._fingerprint_worker(
                     (file_path, self.limit)
                )
        except Exception as e:
            logger.exception(f"Failed generating fingerprint for file {file_path} {e}")
            return None
        return hashes

    def fingerprint_file(self, file_path: str, song_name: str = None) -> None:
        """
        Given a path to a file the method generates hashes for it and stores them in the database
        for later be queried.

        :param file_path: path to the file.
        :param song_name: song name associated to the audio file.
        """
        song_name_from_path = decoder.get_audio_name_from_path(file_path)
        song_hash = decoder.unique_hash(file_path)
        song_name = song_name or song_name_from_path
        # don't refingerprint already fingerprinted files
        if song_hash in self.songhashes_set:
            print(f"{song_name} already fingerprinted, continuing...")
        else:
            song_name, hashes, file_hash = Dejavu._fingerprint_worker(
                file_path,
                self.limit,
                song_name=song_name
            )
            sid = self.db.insert_song(song_name, file_hash)

            self.db.insert_hashes(sid, hashes)
            self.db.set_song_fingerprinted(sid)
            self.__load_fingerprinted_audio_hashes()

    def generate_fingerprints(self, samples: List[int], Fs=DEFAULT_FS) -> Tuple[List[Tuple[str, int]], float]:
        f"""
        Generate the fingerprints for the given sample data (channel).

        :param samples: list of ints which represents the channel info of the given audio file.
        :param Fs: sampling rate which defaults to {DEFAULT_FS}.
        :return: a list of tuples for hash and its corresponding offset, together with the generation time.
        """
        t = time()
        hashes = fingerprint(samples, Fs=Fs)
        fingerprint_time = time() - t
        return hashes, fingerprint_time

    def find_matches(self, hashes: List[Tuple[str, int]]) -> Tuple[List[Tuple[int, int]], Dict[str, int], float]:
        """
        Finds the corresponding matches on the fingerprinted audios for the given hashes.

        :param hashes: list of tuples for hashes and their corresponding offsets
        :return: a tuple containing the matches found against the db, a dictionary which counts the different
         hashes matched for each song (with the song id as key), and the time that the query took.

        """
        t = time.time()
        matches, dedup_hashes = self.db.return_matches(hashes)
        query_time = time.time() - t

        return matches, dedup_hashes, query_time

    def find_matches_by_table(self, hashes: List[Tuple[str, int]],table_name:str) -> Tuple[List[Tuple[int, int]], Dict[str, int], float]:
        """
        Finds the corresponding matches on the fingerprinted audios for the given hashes.

        :param hashes: list of tuples for hashes and their corresponding offsets
        :return: a tuple containing the matches found against the db, a dictionary which counts the different
         hashes matched for each song (with the song id as key), and the time that the query took.

        """
        t = time.time()
        matches, dedup_hashes = self.db.return_matches_by_table(hashes,table_name)
        query_time = time.time() - t

        return matches, dedup_hashes, query_time

    def find_similar_ads_by_days(
        self,
        song_name: str,
        days: int,
        threshold: float = 0.1,
        target_day: date | None = None,
    ) -> list[str]:

        start_day = target_day or date.today()
        matched_songs = set()

        hashes = self.get_fingerprints_for_song(song_name)
        if not hashes:
            return []

        for i in range(days):
            d = start_day - timedelta(days=i)
            table_name = f"fingerprints_{d.strftime('%Y_%m_%d')}"

            try:
                results = self.find_similar_ads_by_hashes(
                    hashes=hashes,
                    table_name=table_name,
                    confidence_threshold=threshold,
                )
            except Exception as e:
                logger.debug(f"Skip table {table_name}: {e}")
                continue

            for r in results:
                if r != song_name: 
                    matched_songs.add(r)

        return sorted(matched_songs)

    def _parse_day_from_song_name(song_name: str) -> date | None:
        """
        Extract yyyyMMdd from song_name like:
        xx_yyyymmdd_hhmmss_xx_xx
        """
        try:
            parts = song_name.split("_")
            ymd = parts[1]            # yyyymmdd
            return date(
                int(ymd[0:4]),
                int(ymd[4:6]),
                int(ymd[6:8]),
            )
        except Exception:
            return None

    def _candidate_fingerprint_tables(song_name: str) -> list[str]:
        d = _parse_day_from_song_name(song_name)
        if not d:
            return []

        days = [d, d + timedelta(days=1), d - timedelta(days=1)]
        return [
            f"fingerprints_{day.strftime('%Y_%m_%d')}"
            for day in days
        ]

    @lru_cache(maxsize=1)
    def _get_song_map(self) -> dict[str, dict]:
        """
        Cache song_name -> song row mapping.

        Returns:
            {
              song_name: {
                song_id: ...,
                song_name: ...,
                ...
              }
            }
        """
        with self.db.cursor(dictionary=True) as cur:
            cur.execute(
                'SELECT * FROM songs;'
            )
            rows = cur.fetchall()

        return {row["song_name"]: row for row in rows}

    def refresh_song_map(self) -> None:
        """Call this if songs table is updated."""
        self._get_song_map.cache_clear()

    def get_fingerprints_for_song(self, song_name: str) -> list[tuple[str, int]]:
        """
        Fast path: only search 1–3 daily partitions inferred from song_name.
        """
        songs = self._get_song_map()   # 强烈建议缓存
        if song_name not in songs:
            return []

        song_id = songs[song_name][SONG_ID]
        tables = _candidate_fingerprint_tables(song_name)

        if not tables:
            return []

        with self.db.cursor(dictionary=True) as cur:
            for table in tables:
                try:
                    cur.execute(
                        f'''
                        SELECT upper(encode("hash",'hex')) AS hash, "offset"
                        FROM {table}
                        WHERE song_id = %s
                        ''',
                        (song_id,),
                    )
                    rows = cur.fetchall()
                    if rows:
                        return [(r["hash"], r["offset"]) for r in rows]
                except Exception:
                    # table may not exist
                    continue

        return []


    def find_similar_ads_by_table_name(
        self,
        song_name: str,
        table_name:str,
        threshold: float = 0.1,
    ) -> list[str]:
        """
        Find similar ads by reusing find_similar_ads across multiple daily tables.

        - If target_day is None: search from today backwards
        - If target_day is set: search from target_day backwards

        Returns deduplicated list of similar song_name.
        """
        logger.debug(
            f"Searching similar ads for {song_name} in {table_name}"
        )

        try:
            results = self.find_similar_ads(
                song_name=song_name,
                table_name=table_name,
                confidence_threshold=threshold,
            )
        except Exception as e:
            # table not exist / query failed
            logger.debug(f"Skip table {table_name}: {e}")

        return results

    def find_similar_cms(
        self,
        media_path: str,
        days: int,
        threshold: float = 0.1,
        target_day: date | None = None,
        enable_align: bool = True,
    ) -> List[str]:
        """
        Find similar CMs by fingerprinting a media file and
        searching fingerprints_yyyy_mm_dd tables.

        - If target_day is None: search from today backwards
        - If target_day is set: search from target_day backwards
        - If enable_align is True: use align_matches (default, high precision)
        - If enable_align is False: return songs with any hash match (high recall)

        Returns a list of matched song_name (deduplicated).
        """

        # --------------------------------------------------
        # 1. Generate fingerprint hashes ONCE
        # --------------------------------------------------
        logger.info(f"Generating fingerprint for {media_path}")

        hashes = self.get_fingerprint_hash(media_path)
        if not hashes:
            logger.warning("No fingerprint hashes generated")
            return []

        logger.info(f"Fingerprint hashes: {len(hashes)}")

        matched_songs = set()

        # --------------------------------------------------
        # 2. Decide start day
        # --------------------------------------------------
        start_day = target_day or date.today()

        # --------------------------------------------------
        # 3. Iterate over days
        # --------------------------------------------------
        for i in range(days):
            d = start_day - timedelta(days=i)
            table_name = f"fingerprints_{d.strftime('%Y_%m_%d')}"

            logger.debug(f"Searching table {table_name}")

            try:
                matches, dedup_hashes, _ = self.find_matches_by_table(
                    hashes,
                    table_name,
                )
            except Exception as e:
                logger.debug(f"Skip table {table_name}: {e}")
                continue

            if not matches:
                continue

            # --------------------------------------------------
            # 4A. Precision mode (align_matches)
            # --------------------------------------------------
            if enable_align:
                results = self.align_matches(
                    matches,
                    dedup_hashes,
                    queried_hashes=len(hashes),
                    confidence_threshold=threshold,
                )

                for res in results:
                    try:
                        song_name = res[SONG_NAME].decode("utf8")
                    except Exception:
                        song_name = str(res[SONG_NAME])

                    matched_songs.add(song_name)

            # --------------------------------------------------
            # 4B. Recall mode (no align)
            # --------------------------------------------------
            else:
                for song_id in dedup_hashes.keys():
                    try:
                        song_name = self.db.get_song_by_id(song_id)[SONG_NAME]
                        if isinstance(song_name, bytes):
                            song_name = song_name.decode("utf8")
                    except Exception:
                        continue

                    matched_songs.add(song_name)


        return sorted(matched_songs)

    def get_fingerprints_by_songs(self, song_names: list[str]):
        with self.db.cursor(dictionary=True) as cur:
            cur.execute(
                f'''
                SELECT s.song_name,
                    upper(encode(f."hash",'hex')) AS hash,
                    f."offset"
                FROM fingerprints f
                JOIN songs s ON f.song_id = s.song_id
                WHERE s.song_name = ANY(%s)
                ''',
                (song_names,)
            )
            rows = cur.fetchall()

        fp_map = {}
        for r in rows:
            fp_map.setdefault(r["song_name"], []).append(
                (r["hash"], r["offset"])
            )
        return fp_map


    def find_similar_ads(
        self, 
        song_name: str, 
        table_name:str,
        confidence_threshold=0.05
    ):

        songs_list = self.db.get_songs() 
        
        songs = {row["song_name"]: row for row in songs_list}

        if song_name not in songs:
            return []

        
        song_id = songs[song_name][SONG_ID]
        #print(f"Retrieved song_id {song_id}")

        
        with self.db.cursor(dictionary=True) as cur:
            cur.execute(
                f'SELECT upper(encode("hash", \'hex\')) AS hash, "offset" '
                f'FROM fingerprints WHERE "song_id" = %s;',
                (song_id,)
            )
            hashes = [(r["hash"], r["offset"]) for r in cur.fetchall()]
        #print(f"Getting FP {len(hashes)}")

        #print("find_matches")
        matches, dedup_hashes, _ = self.find_matches_by_table(hashes,table_name)

        #print("align_matches")
        results = self.align_matches(
            matches,
            dedup_hashes,
            queried_hashes=len(hashes),
            confidence_threshold=confidence_threshold
        )


        return [res[SONG_NAME].decode("utf8") for res in results if res[SONG_ID] != song_id]

    def align_matches(self, matches: List[Tuple[int, int]], dedup_hashes: Dict[str, int], queried_hashes: int,
                      topn: int = TOPN,confidence_threshold:float = 0.05) -> List[Dict[str, any]]:
        """
        Finds hash matches that align in time with other matches and finds
        consensus about which hashes are "true" signal from the audio.

        :param matches: matches from the database
        :param dedup_hashes: dictionary containing the hashes matched without duplicates for each song
        (key is the song id).
        :param queried_hashes: amount of hashes sent for matching against the db
        :param topn: number of results being returned back.
        :return: a list of dictionaries (based on topn) with match information.
        """
        # count offset occurrences per song and keep only the maximum ones.
        sorted_matches = sorted(matches, key=lambda m: (m[0], m[1]))
        counts = [(*key, len(list(group))) for key, group in groupby(sorted_matches, key=lambda m: (m[0], m[1]))]
        songs_matches = sorted(
            [max(list(group), key=lambda g: g[2]) for key, group in groupby(counts, key=lambda count: count[0])],
            key=lambda count: count[2], reverse=True
        )

        songs_result = []
        #print(f"total {len(songs_matches)} songs matches found")
        # Preload all songs into a dictionary
        all_songs = {s[SONG_ID]: s for s in self.db.get_songs()}

        for song_id, offset, _ in songs_matches:  # consider topn elements in the result
            song = all_songs.get(song_id)
            if not song:
                continue
            song_name = song.get(SONG_NAME, None)
            song_hashes = song.get(FIELD_TOTAL_HASHES, None)
            nseconds = round(float(offset) / DEFAULT_FS * DEFAULT_WINDOW_SIZE * DEFAULT_OVERLAP_RATIO, 5)
            hashes_matched = dedup_hashes[song_id]
            fingerprinted_confidence = round(hashes_matched / song_hashes, 2)
            
            if fingerprinted_confidence < confidence_threshold:
                continue

            song = {
                SONG_ID: song_id,
                SONG_NAME: song_name.encode("utf8"),
                INPUT_HASHES: queried_hashes,
                FINGERPRINTED_HASHES: song_hashes,
                HASHES_MATCHED: hashes_matched,
                # Percentage regarding hashes matched vs hashes from the input.
                INPUT_CONFIDENCE: round(hashes_matched / queried_hashes, 2),
                # Percentage regarding hashes matched vs hashes fingerprinted in the db.
                FINGERPRINTED_CONFIDENCE: fingerprinted_confidence,
                OFFSET: offset,
                OFFSET_SECS: nseconds,
                FIELD_FILE_SHA1: song.get(FIELD_FILE_SHA1, None).encode("utf8")
            }

            songs_result.append(song)

        return songs_result

    def recognize(self, recognizer, *options, **kwoptions) -> Dict[str, any]:
        r = recognizer(self)
        return r.recognize(*options, **kwoptions)

    @staticmethod
    def _fingerprint_worker(arguments):
        # Pool.imap sends arguments as tuples so we have to unpack
        # them ourself.
        try:
            file_name, limit = arguments
        except ValueError:
            pass

        song_name, extension = os.path.splitext(os.path.basename(file_name))

        fingerprints, file_hash = Dejavu.get_file_fingerprints(file_name, limit, print_output=True)

        return song_name, fingerprints, file_hash

    @staticmethod
    def get_file_fingerprints(file_name: str, limit: int, print_output: bool = False):
        channels, fs, file_hash = decoder.read(file_name, limit)
        fingerprints = set()
        channel_amount = len(channels)
        for channeln, channel in enumerate(channels, start=1):
            if print_output:
                print(f"Fingerprinting channel {channeln}/{channel_amount} for {file_name}")

            hashes = fingerprint(channel, Fs=fs)

            if print_output:
                print(f"Finished channel {channeln}/{channel_amount} for {file_name}")

            fingerprints |= set(hashes)

        return fingerprints, file_hash
    
    @staticmethod
    def get_np_fingerprints(
        channels: list[np.ndarray],
        fs: int,
        file_name: str = "in_memory_audio",
        limit: int = None,
        print_output: bool = False
    ):
        """
        Generate fingerprints directly from in-memory NumPy audio data.

        :param channels: list of NumPy arrays, one per audio channel
        :param fs: sampling rate of the audio data
        :param file_name: optional name tag for logger or hash generation
        :param limit: optional limit in seconds (truncate data if set)
        :param print_output: whether to print progress messages
        :return: (fingerprints, file_hash)
        """
        # Optionally limit audio length
        if limit:
            samples_limit = int(limit * fs)
            channels = [ch[:samples_limit] for ch in channels]

        fingerprints = set()
        channel_amount = len(channels)

        for channeln, channel in enumerate(channels, start=1):
            if print_output:
                print(f"Fingerprinting channel {channeln}/{channel_amount} for {file_name}")

            hashes = fingerprint(channel, Fs=fs)

            if print_output:
                print(f"Finished channel {channeln}/{channel_amount} for {file_name}")

            fingerprints |= set(hashes)

        # Generate a unique hash for the in-memory audio
        # based on data content (for deduplication)
        s = sha1()
        for ch in channels:
            s.update(np.ascontiguousarray(ch).tobytes())
        file_hash = s.hexdigest().upper()

        return fingerprints, file_hash
