import abc
from time import time
from typing import Dict, List, Tuple

import numpy as np

from sdio_dejavu import Dejavu
from sdio_dejavu.config.settings import DEFAULT_FS
from sdio_dejavu.logic.fingerprint import enrich_hash64

class BaseRecognizer(object, metaclass=abc.ABCMeta):
    def __init__(self, dejavu:Dejavu):
        self.dejavu:Dejavu = dejavu
        self.Fs = DEFAULT_FS

    def _recognize(self, *data) -> Tuple[List[Dict[str, any]], int, int, int]:
        fingerprint_times = []
        hashes = set()  # to remove possible duplicated fingerprints we built a set.
        for channel in data:
            fingerprints, fingerprint_time = self.dejavu.generate_fingerprints(channel, Fs=self.Fs)
            fingerprint_times.append(fingerprint_time)
            hashes |= set(fingerprints)

        matches, dedup_hashes, query_time = self.dejavu.find_matches(hashes)

        t = time()
        final_results = self.dejavu.align_matches(matches, dedup_hashes, len(hashes))
        align_time = time() - t

        return final_results, np.sum(fingerprint_times), query_time, align_time
    
    def _recognize_hash64(self, *data) -> Tuple[List[Dict[str, any]], int, int, int]:
        fingerprint_times = []
        hashes = set()  # to remove possible duplicated fingerprints we built a set.
        for channel in data:
            fingerprints, fingerprint_time = self.dejavu.generate_fingerprints(channel, Fs=self.Fs)
            fingerprint_times.append(fingerprint_time)
            hashes |= set(fingerprints)


        hashes = enrich_hash64(hashes)
        matches, dedup_hashes, query_time = self.dejavu.find_matches_hash64(hashes)

        t = time()
        final_results = self.dejavu.align_matches(matches, dedup_hashes, len(hashes))
        align_time = time() - t

        return final_results, np.sum(fingerprint_times), query_time, align_time
    
    def _recognize_cmid_hash64(self, cm_id:str) -> Tuple[List[Dict[str, any]], int, int, int]:
        fingerprint_times = []
        hashes = set()  # to remove possible duplicated fingerprints we built a set.
        for channel in data:
            fingerprints, fingerprint_time = self.dejavu.generate_fingerprints(channel, Fs=self.Fs)
            fingerprint_times.append(fingerprint_time)
            hashes |= set(fingerprints)


        hashes = enrich_hash64(hashes)
        matches, dedup_hashes, query_time = self.dejavu.find_matches_hash64(hashes)

        t = time()
        final_results = self.dejavu.align_matches(matches, dedup_hashes, len(hashes))
        align_time = time() - t

        return final_results, np.sum(fingerprint_times), query_time, align_time

    @abc.abstractmethod
    def recognize(self) -> Dict[str, any]:
        pass  # base class does nothing
