import multiprocessing
import os
import sys
from functools import lru_cache
import traceback
from itertools import groupby
import time
from typing import Dict, List, Tuple
import numpy as np
from hashlib import sha1
import concurrent
from collections import defaultdict, Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import date, timedelta
import sdio_dejavu.logic.decoder as decoder
from tqdm import tqdm
from sdio_dejavu.base_classes.base_database import get_database
import time
from sdio_dejavu.config.settings import (DEFAULT_FS, DEFAULT_OVERLAP_RATIO,
                                    DEFAULT_WINDOW_SIZE, FIELD_FILE_SHA1,
                                    FIELD_TOTAL_HASHES,
                                    FINGERPRINTED_CONFIDENCE,
                                    FINGERPRINTED_HASHES, HASHES_MATCHED,
                                    INPUT_CONFIDENCE, INPUT_HASHES, OFFSET,
                                    OFFSET_SECS, SONG_ID, SONG_NAME, TOPN,SONGS_TABLENAME)
from sdio_dejavu.logic.fingerprint import fingerprint,filter_result,enrich_hash64
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
        nprocesses: int | None = None,
    ):
        """
        Multiprocess fingerprinting (CPU-bound).
        DB writes are executed in the parent process only.
        """

        nprocesses = nprocesses or max(1, min(4, os.cpu_count() or 2))
        failed_files: list[str] = []

        worker_input = [
            (filename, self.limit)
            for filename in media_list
            if decoder.unique_hash(filename) not in self.songhashes_set
        ]

        total = len(worker_input)
        if total == 0:
            logger.info("[FP] no new files to fingerprint")
            return []

        logger.info(f"[FP] submitting {total} files with {nprocesses} processes")

        start_time = time.perf_counter()
        timeout_s = 120

        submitted: dict[concurrent.futures.Future, str] = {}

        with ProcessPoolExecutor(
            max_workers=nprocesses,
            mp_context=multiprocessing.get_context("spawn"),
        ) as executor, tqdm(
            total=total,
            desc="[FP] fingerprinting",
            unit="file",
            smoothing=0.1,
        ) as pbar:

            for item in worker_input:
                filename = item[0]
                fut = executor.submit(Dejavu._fingerprint_worker, item)
                submitted[fut] = filename

            for fut in as_completed(submitted):
                filename = submitted[fut]
                try:
                    song_name, hashes, file_hash = fut.result(timeout=timeout_s)

                    with self.db.cursor():
                        sid = self.db.insert_song(song_name, file_hash, len(hashes))
                        self.db.insert_hashes(sid, hashes)
                        self.db.set_song_fingerprinted(sid)

                except concurrent.futures.TimeoutError:
                    logger.error(f"[FP] timeout: {filename}")
                    failed_files.append(filename)

                except Exception as e:
                    logger.exception(f"[FP] failed: {filename} | {e}")
                    failed_files.append(filename)

                finally:
                    pbar.update(1)

        logger.info(
            f"[FP] done. ok={total - len(failed_files)} "
            f"fail={len(failed_files)} "
            f"elapsed={time.perf_counter() - start_time:.1f}s"
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
            logger.info(f"{song_name} already fingerprinted, continuing...")
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
        t = time.time()
        hashes = fingerprint(samples, Fs=Fs)
        hashes_int64 = enrich_hash64(hashes)
        fingerprint_time = time.time() - t
        return hashes_int64, fingerprint_time

    
    def parse_duration(self, cm_id: str) -> int:
        """
        cm_id format: xxx_YYYYMMDD_start_end
        """
        parts = cm_id.split("_")
        start = int(parts[-2])
        end = int(parts[-1])
        return end - start
    
    def is_duration_compatible(self, d1: int, d2: int,
                           min_ratio: float = 0.9,
                           max_ratio: float = 1.1) -> bool:
        r = min(d1, d2) / max(d1, d2)
        return min_ratio <= r <= max_ratio

    """
    def get_similar_cm_ids_hash64(
            self, 
            cm_id:str,
            threshold:float = 0.3,
            use_unnest:bool = False,
            verbose:bool = False,
            ) -> list[str]:
        
        time = time.ti
        duration = self.parse_duration(cm_id)
        hashes = self.db.get_fingerprints_by_song_name(cm_id)
        matches, dedup_hashes, _ = self.find_matches_hash64(hashes,use_unnest)
        final_results = self.align_matches(matches, dedup_hashes, len(hashes),confidence_threshold=threshold,use_unnest=use_unnest)
        final_results = filter_result(final_results)
        
        match_names = []

        for item in final_results:
            other = item["cm_name"]
            if other == cm_id:
                continue

            duration_other = self.parse_duration(other)

            if self.is_duration_compatible(duration, duration_other):
                match_names.append(other)

        return match_names
        """
    
    def get_similar_cm_ids_hash64(
            self, 
            cm_id: str,
            threshold: float = 0.3,
            use_unnest: bool = False,
            verbose: bool = False,
            ) -> list[str]:
        
        metrics = {}
        
        start = time.time()
        duration = self.parse_duration(cm_id)
        metrics["parse_origin_duration"] = time.time() - start
        
        t_now = time.time()
        hashes = self.db.get_fingerprints_by_song_name(cm_id)
        metrics["get_fingerprints"] = time.time() - t_now
        
        t_now = time.time()
        matches, dedup_hashes, _ = self.find_matches_hash64(hashes, use_unnest,verbose)
        metrics["find_matches"] = time.time() - t_now
        
        t_now = time.time()
        final_results = self.align_matches(
            matches, 
            dedup_hashes, 
            len(hashes), 
            confidence_threshold=threshold, 
            use_unnest=False,
            verbose=verbose,
        )
        metrics["align_matches"] = time.time() - t_now
        
        t_now = time.time()
        final_results = filter_result(final_results)
        
        match_names = []
        for item in final_results:
            other = item["cm_name"]
            if other == cm_id:
                continue

            duration_other = self.parse_duration(other)
            if self.is_duration_compatible(duration, duration_other):
                match_names.append(other)
        metrics["post_process_filter"] = time.time() - t_now
        
        if verbose:
            log_msg = " | ".join([f"{k}: {v:.3f}s" for k, v in metrics.items()])
            logger.debug(f"Performance Metrics: {log_msg}")
            
        return match_names

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
    

    def find_matches_hash64(
            self, 
            hashes: list[Tuple[int , int]],
            use_unnest:bool = False,
            verbose:bool = False,
        ) -> Tuple[list[Tuple[int, int]], dict[str, int], float]:
        """
        Finds the corresponding matches on the fingerprinted audios for the given hashes.

        :param hashes: list of tuples for hashes and their corresponding offsets
        :return: a tuple containing the matches found against the db, a dictionary which counts the different
         hashes matched for each song (with the song id as key), and the time that the query took.

        """
        t = time.time()
        matches = []
        dedup_hashes = {}
        if use_unnest:
            matches, dedup_hashes = self.db.return_matches_hash64_unnest(hashes,verbose = verbose)
        else:
            matches, dedup_hashes = self.db.return_matches_hash64(hashes,verbose = verbose)
        query_time = time.time() - t

        return matches, dedup_hashes, query_time

    def _parse_day_from_song_name(self,song_name: str) -> date | None:
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

    def _candidate_fingerprint_tables(self,song_name: str) -> list[str]:
        d = self._parse_day_from_song_name(song_name)
        if not d:
            return []

        days = [d, d + timedelta(days=1), d - timedelta(days=1)]
        return [
            f"fingerprints_{day.strftime('%Y_%m_%d')}"
            for day in days
        ]

    @lru_cache(maxsize=1)
    def _get_song_map_int(self) -> dict[int, dict]:
        query = f'SELECT * FROM {SONGS_TABLENAME} WHERE fingerprinted = 1;'
        # 强制使用传统的迭代方式，触发驱动的类型转换逻辑
        with self.db.cursor(dictionary=True) as cur:
            cur.execute(query)
            # 模仿以前“没问题”的做法：迭代游标而非 fetchall
            rows = [dict(row) for row in cur] 

        processed_map = {}
        for row in rows:
            # 二次保险：如果还是 memoryview，手动转 str
            name = row[SONG_NAME]
            if hasattr(name, "tobytes"):
                row[SONG_NAME] = name.tobytes().decode("utf-8")
            
            # 存入 map
            processed_map[row[SONG_ID]] = row
            
        return processed_map

    @lru_cache(maxsize=1)
    def _get_song_map_name_str(self) -> dict[str, dict]:
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
        query = f'SELECT * FROM {SONGS_TABLENAME}  WHERE fingerprinted = 1 ;'
        with self.db.cursor(dictionary=True) as cur:
            cur.execute(
                query
            )
            rows = cur.fetchall()

        return {row[SONG_NAME]: row for row in rows}

    def refresh_song_map(self) -> None:
        """Call this if songs table is updated."""
        self._get_song_map_name_str.cache_clear()
        self._get_song_map_int.cache_clear()

    def align_matches_unnest(
        self,
        matches: list[tuple[int, int]],
        dedup_hashes: dict[int, int],
        queried_hashes: int,
        topn: int = TOPN,
        confidence_threshold: float = 0.05,
    ) -> list[dict]:

        # ----------------------------------------
        # 1.song_id -> Counter(offset_diff)
        # ----------------------------------------
        offset_votes: dict[int, Counter] = defaultdict(Counter)

        for song_id, offset_diff in matches:
            offset_votes[song_id][offset_diff] += 1

        # ----------------------------------------
        # 2. 对每个 song，取票数最多的 offset
        # ----------------------------------------
        song_best = []  # (song_id, best_offset, vote_count)

        for song_id, counter in offset_votes.items():
            best_offset, vote_count = max(
                counter.items(),
                key=lambda x: (x[1], -abs(x[0]))
            )
            song_best.append((song_id, best_offset, vote_count))

        # ----------------------------------------
        # 3. 按 vote_count 排序，提前截断 topn
        # ----------------------------------------
        song_best.sort(key=lambda x: x[2], reverse=True)
        if topn:
            song_best = song_best[:topn]

        # ----------------------------------------
        # 4. 只加载需要的 song metadata
        # ----------------------------------------
        """
        song_ids = [sid for sid, _, _ in song_best]
        songs_meta = {
            s[SONG_ID]: s
            for s in self.db.get_songs_by_ids(song_ids)
        }
        """
        songs_meta = {s[SONG_ID]: s for s in self.db.get_songs()}

        # ----------------------------------------
        # 5. 组装最终结果 + confidence 过滤
        # ----------------------------------------
        results = []

        for song_id, offset, _ in song_best:
            song = songs_meta.get(song_id)
            if not song:
                continue

            song_hashes = song.get(FIELD_TOTAL_HASHES)
            if not song_hashes:
                continue

            hashes_matched = dedup_hashes.get(song_id, 0)
            fingerprinted_conf = hashes_matched / song_hashes

            if fingerprinted_conf < confidence_threshold:
                continue

            nseconds = round(
                float(offset) / DEFAULT_FS
                * DEFAULT_WINDOW_SIZE
                * DEFAULT_OVERLAP_RATIO,
                5
            )

            results.append({
                SONG_ID: song_id,
                SONG_NAME: song.get(SONG_NAME).encode("utf8"),
                INPUT_HASHES: queried_hashes,
                FINGERPRINTED_HASHES: song_hashes,
                HASHES_MATCHED: hashes_matched,
                INPUT_CONFIDENCE: round(hashes_matched / queried_hashes, 2),
                FINGERPRINTED_CONFIDENCE: round(fingerprinted_conf, 2),
                OFFSET: offset,
                OFFSET_SECS: nseconds,
                FIELD_FILE_SHA1: song.get(FIELD_FILE_SHA1).encode("utf8"),
            })

        return results


    def align_matches_hash64(self, matches, dedup_hashes, queried_hashes, topn=TOPN, confidence_threshold=0.05):
        """
        Finds hash matches that align in time and consensus using in-memory metadata.
        """
        songs_result = []
        
        # Get pre-loaded song metadata from cache (O(1) access)
        # Note: Ensure _get_song_map returns {song_id: row} for this lookup
        all_songs_cache = self._get_song_map_int() 

        # 1. Aggregate matches by song and relative offset (O(N))
        # match_counts structure: {song_id: {diff_offset: count}}
        match_counts = defaultdict(lambda: defaultdict(int))
        for song_id, diff_offset in matches:
            match_counts[song_id][diff_offset] += 1

        # 2. Find the strongest alignment (consensus) for each song
        songs_matches = []
        for song_id, offsets in match_counts.items():
            # Find the offset with the highest occurrence for this specific song
            best_offset = max(offsets, key=offsets.get)
            max_count = offsets[best_offset]
            songs_matches.append((song_id, best_offset, max_count))

        # 3. Sort candidates by match strength (highest count first)
        songs_matches.sort(key=lambda x: x[2], reverse=True)

        # 4. Build results using in-memory cache (Eliminating DB Roundtrips)
        for song_id, offset, _ in songs_matches:
            # Retrieve metadata from memory - no SQL executed here
            song = all_songs_cache.get(song_id) or all_songs_cache.get(str(song_id))
            
            if not song:
                continue
                
            song_hashes = song.get(FIELD_TOTAL_HASHES)
            hashes_matched = dedup_hashes.get(song_id, 0)
            
            # Calculate confidence ratios
            fingerprinted_confidence = round(hashes_matched / song_hashes, 2)
            
            # Filter by threshold to remove weak/false matches early
            if fingerprinted_confidence < confidence_threshold:
                continue
                
            # Convert frame offset to absolute seconds
            nseconds = round(float(offset) / DEFAULT_FS * DEFAULT_WINDOW_SIZE * DEFAULT_OVERLAP_RATIO, 5)
            
            # Construct the final result object
            result = {
                SONG_ID: song_id,
                SONG_NAME: song.get(SONG_NAME),
                INPUT_HASHES: queried_hashes,
                FINGERPRINTED_HASHES: song_hashes,
                HASHES_MATCHED: hashes_matched,
                INPUT_CONFIDENCE: round(hashes_matched / queried_hashes, 2),
                FINGERPRINTED_CONFIDENCE: fingerprinted_confidence,
                OFFSET: offset,
                OFFSET_SECS: nseconds,
                #FIELD_FILE_SHA1: song.get(FIELD_FILE_SHA1, "").encode("utf8")
            }

            songs_result.append(result)

            # Respect TOPN constraint
            if topn and len(songs_result) >= topn:
                break

        return songs_result

    def align_matches(
            self, 
            matches: list[Tuple[int, int]], 
            dedup_hashes: dict[str, int], 
            queried_hashes: int,
            topn: int = TOPN,
            confidence_threshold:float = 0.05,
            use_unnest:bool = False,
            verbose:bool = False,
        ) -> list[dict[str, any]]:

        if verbose:
            song_ids = [m[0] for m in matches]
            unique_songs = len(set(song_ids))
            total_matches = len(matches)
            
            top_3_songs = Counter(song_ids).most_common(3)
            
            logger.debug(
                f"\n[Align Analysis]\n"
                f"- Input Queried Hashes: {queried_hashes}\n"
                f"- Total Matches (N): {total_matches}\n"
                f"- Unique Songs: {unique_songs}\n"
                f"- Avg Matches per Song: {total_matches/unique_songs:.2f}\n"
                f"- Top 3 Match Heavy Songs: {top_3_songs}\n"
                f"- Use Unnest Mode: {use_unnest}"
            )

        counts = Counter(m[0] for m in matches)
        valid_song_ids = {s_id for s_id, count in counts.items() if count > 5}
        filtered_matches = [m for m in matches if m[0] in valid_song_ids]
        if verbose:
            logger.debug(f"- Filtered_matches {len(filtered_matches)}")
        if use_unnest:
            return self.align_matches_unnest(filtered_matches,dedup_hashes,queried_hashes,topn,confidence_threshold)
        else:
            return self.align_matches_hash64(filtered_matches,dedup_hashes,queried_hashes,topn,confidence_threshold)

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

        fingerprints, file_hash = Dejavu.get_file_fingerprints(file_name, limit, print_output=False)

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

        return hashes, file_hash
    
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
