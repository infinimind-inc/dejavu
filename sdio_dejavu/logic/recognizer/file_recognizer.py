from time import time
from typing import Dict
from typing import  Dict, Optional
import math
import sdio_dejavu.logic.decoder as decoder
from sdio_dejavu.logic.fingerprint import filter_result
from sdio_dejavu.base_classes.base_recognizer import BaseRecognizer
from sdio_dejavu.config.settings import (ALIGN_TIME, FINGERPRINT_TIME, QUERY_TIME,
                                    RESULTS, TOTAL_TIME)


class FileRecognizer(BaseRecognizer):
    def __init__(self, dejavu):
        super().__init__(dejavu)


    def recognize_file(self, filename: str) -> Dict[str, any]:
        channels, self.Fs, _ = decoder.read(filename, self.dejavu.limit)

        t = time()
        matches, fingerprint_time, query_time, align_time = self._recognize(*channels)
        t = time() - t

        results = {
            TOTAL_TIME: t,
            FINGERPRINT_TIME: fingerprint_time,
            QUERY_TIME: query_time,
            ALIGN_TIME: align_time,
            RESULTS: filter_result(matches)
        }

        return results
    

    def recognize_file_hash64(self, filename: str) -> Dict[str, any]:
        channels, self.Fs, _ = decoder.read(filename, self.dejavu.limit)

        t = time()
        matches, fingerprint_time, query_time, align_time = self._recognize_hash64(*channels)
        t = time() - t

        results = {
            TOTAL_TIME: t,
            FINGERPRINT_TIME: fingerprint_time,
            QUERY_TIME: query_time,
            ALIGN_TIME: align_time,
            RESULTS: filter_result(matches)
        }

        return results

    def recognize(self, filename: str) -> Dict[str, any]:
        return self.recognize_file(filename)
    
    def recognize_hash64(self, filename: str) -> Dict[str, any]:
        return self.recognize_file_hash64(filename)
