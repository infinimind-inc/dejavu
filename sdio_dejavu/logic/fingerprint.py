import hashlib
from operator import itemgetter
from typing import List, Tuple,Optional

import matplotlib.mlab as mlab
import matplotlib.pyplot as plt
import numpy as np
from scipy.ndimage.filters import maximum_filter
from scipy.ndimage.morphology import (binary_erosion,
                                      generate_binary_structure,
                                      iterate_structure)

from sdio_dejavu.config.settings import (CONNECTIVITY_MASK, DEFAULT_AMP_MIN,
                                    DEFAULT_FAN_VALUE, DEFAULT_FS,
                                    DEFAULT_OVERLAP_RATIO, DEFAULT_WINDOW_SIZE,
                                    FINGERPRINT_REDUCTION, MAX_HASH_TIME_DELTA,
                                    MIN_HASH_TIME_DELTA,
                                    PEAK_NEIGHBORHOOD_SIZE, PEAK_SORT)


def fingerprint(channel_samples: List[int],
                Fs: int = DEFAULT_FS,
                wsize: int = DEFAULT_WINDOW_SIZE,
                wratio: float = DEFAULT_OVERLAP_RATIO,
                fan_value: int = DEFAULT_FAN_VALUE,
                amp_min: int = DEFAULT_AMP_MIN) -> List[Tuple[str, int]]:
    """
    FFT the channel, log transform output, find local maxima, then return locally sensitive hashes.

    :param channel_samples: channel samples to fingerprint.
    :param Fs: audio sampling rate.
    :param wsize: FFT windows size.
    :param wratio: ratio by which each sequential window overlaps the last and the next window.
    :param fan_value: degree to which a fingerprint can be paired with its neighbors.
    :param amp_min: minimum amplitude in spectrogram in order to be considered a peak.
    :return: a list of hashes with their corresponding offsets.
    """
    # FFT the signal and extract frequency components
    arr2D = mlab.specgram(
        channel_samples,
        NFFT=wsize,
        Fs=Fs,
        window=mlab.window_hanning,
        noverlap=int(wsize * wratio))[0]

    # Apply log transform since specgram function returns linear array. 0s are excluded to avoid np warning.
    arr2D = 10 * np.log10(arr2D, out=np.zeros_like(arr2D), where=(arr2D != 0))

    local_maxima = get_2D_peaks(arr2D, plot=False, amp_min=amp_min)

    # return hashes
    return generate_hashes(local_maxima, fan_value=fan_value)


def get_2D_peaks(arr2D: np.array, plot: bool = False, amp_min: int = DEFAULT_AMP_MIN)\
        -> List[Tuple[List[int], List[int]]]:
    """
    Extract maximum peaks from the spectogram matrix (arr2D).

    :param arr2D: matrix representing the spectogram.
    :param plot: for plotting the results.
    :param amp_min: minimum amplitude in spectrogram in order to be considered a peak.
    :return: a list composed by a list of frequencies and times.
    """
    # Original code from the repo is using a morphology mask that does not consider diagonal elements
    # as neighbors (basically a diamond figure) and then applies a dilation over it, so what I'm proposing
    # is to change from the current diamond figure to a just a normal square one:
    #       F   T   F           T   T   T
    #       T   T   T   ==>     T   T   T
    #       F   T   F           T   T   T
    # In my local tests time performance of the square mask was ~3 times faster
    # respect to the diamond one, without hurting accuracy of the predictions.
    # I've made now the mask shape configurable in order to allow both ways of find maximum peaks.
    # That being said, we generate the mask by using the following function
    # https://docs.scipy.org/doc/scipy/reference/generated/scipy.ndimage.generate_binary_structure.html
    struct = generate_binary_structure(2, CONNECTIVITY_MASK)

    #  And then we apply dilation using the following function
    #  http://docs.scipy.org/doc/scipy/reference/generated/scipy.ndimage.iterate_structure.html
    #  Take into account that if PEAK_NEIGHBORHOOD_SIZE is 2 you can avoid the use of the scipy functions and just
    #  change it by the following code:
    #  neighborhood = np.ones((PEAK_NEIGHBORHOOD_SIZE * 2 + 1, PEAK_NEIGHBORHOOD_SIZE * 2 + 1), dtype=bool)
    neighborhood = iterate_structure(struct, PEAK_NEIGHBORHOOD_SIZE)

    # find local maxima using our filter mask
    local_max = maximum_filter(arr2D, footprint=neighborhood) == arr2D

    # Applying erosion, the dejavu documentation does not talk about this step.
    background = (arr2D == 0)
    eroded_background = binary_erosion(background, structure=neighborhood, border_value=1)

    # Boolean mask of arr2D with True at peaks (applying XOR on both matrices).
    detected_peaks = local_max != eroded_background

    # extract peaks
    amps = arr2D[detected_peaks]
    freqs, times = np.where(detected_peaks)

    # filter peaks
    amps = amps.flatten()

    # get indices for frequency and time
    filter_idxs = np.where(amps > amp_min)

    freqs_filter = freqs[filter_idxs]
    times_filter = times[filter_idxs]

    if plot:
        # scatter of the peaks
        fig, ax = plt.subplots()
        ax.imshow(arr2D)
        ax.scatter(times_filter, freqs_filter)
        ax.set_xlabel('Time')
        ax.set_ylabel('Frequency')
        ax.set_title("Spectrogram")
        plt.gca().invert_yaxis()
        plt.show()

    return list(zip(freqs_filter, times_filter))


def generate_hashes(peaks: List[Tuple[int, int]], fan_value: int = DEFAULT_FAN_VALUE) -> List[Tuple[str, int, int]]:
    """
    Hash list structure:
       sha1_hash[0:FINGERPRINT_REDUCTION]    time_offset
        [(e05b341a9b77a51fd26, 32), ... ]

    :param peaks: list of peak frequencies and times.
    :param fan_value: degree to which a fingerprint can be paired with its neighbors.
    :return: a list of hashes with their corresponding offsets.
    """
    # frequencies are in the first position of the tuples
    idx_freq = 0
    # times are in the second position of the tuples
    idx_time = 1

    if PEAK_SORT:
        peaks.sort(key=itemgetter(1))

    hashes = []
    for i in range(len(peaks)):
        for j in range(1, fan_value):
            if (i + j) < len(peaks):

                freq1 = peaks[i][idx_freq]
                freq2 = peaks[i + j][idx_freq]
                t1 = peaks[i][idx_time]
                t2 = peaks[i + j][idx_time]
                t_delta = t2 - t1

                if MIN_HASH_TIME_DELTA <= t_delta <= MAX_HASH_TIME_DELTA:
                    h = hashlib.sha1(f"{str(freq1)}|{str(freq2)}|{str(t_delta)}".encode('utf-8'))
                    hash_tmp = h.hexdigest()[0:FINGERPRINT_REDUCTION]
                    hash64 = hex2int64(hash_tmp)
                    hashes.append((hash_tmp,hash64, t1))

    return hashes

def hex2int64(hex_str: str) -> int:
    """
    Convert hex string to signed int64.
    Logic is IDENTICAL to:
    ('x' || substring(hex FROM 1 FOR 16))::bit(64)::bigint
    """
    if len(hex_str) < 16:
        raise ValueError("hex string too short for int64")

    # take first 64 bits (16 hex chars)
    h = hex_str[:16]

    val = int(h, 16)

    # convert to signed int64 (two's complement)
    if val >= 1 << 63:
        val -= 1 << 64

    return val


def filter_result(
        results_list: list[dict],
        threshold: float = 0.3,
        min_matched_hashes: Optional[int] = None,
        max_offset_abs: Optional[int] = None,
        top_k: Optional[int] = None,
    ) -> list[dict]:
        """
        Filter and sort fingerprint matching results.

        Args:
            results_list: raw dejavu results (list of dict)
            threshold: minimum input_confidence
            min_matched_hashes: minimum hashes_matched_in_input
            max_offset_abs: max absolute offset (in frames, not seconds)
            top_k: return only top K results after sorting

        Returns:
            List[dict]: filtered & sorted results
        """

        filtered = []

        for r in results_list:
            # ---- normalize & extract ----
            input_conf = float(r.get("input_confidence", 0.0))
            matched = int(r.get("hashes_matched_in_input", 0))
            offset = int(r.get("offset", 0))
            offset_sec = float(r.get("offset_seconds", 0.0))

            # ---- basic filters ----
            if input_conf < threshold:
                continue

            if min_matched_hashes is not None and matched < min_matched_hashes:
                continue

            if max_offset_abs is not None and abs(offset) > max_offset_abs:
                continue
            cm_name = r.get("song_name")
            if isinstance(cm_name, (bytes, bytearray)):
                cm_name = cm_name.decode("utf-8", errors="ignore")
            # ---- normalized record ----
            filtered.append({
                "cm_id": r.get("song_id"),
                "cm_name": cm_name,
                "matched_hashes": matched,
                "input_total_hashes": int(r.get("input_total_hashes", 0)),
                "input_confidence": input_conf,
                "fingerprinted_confidence": float(r.get("fingerprinted_confidence", 0.0)),
                "offset": offset,
                "offset_seconds": offset_sec,
                "file_sha1": r.get("file_sha1"),
            })

        # ---- sorting strategy ----
        # 1. highest confidence first
        # 2. then highest matched hashes
        # 3. then smallest |offset|
        filtered.sort(
            key=lambda x: (
                -x["input_confidence"],
                -x["matched_hashes"],
                abs(x["offset"]),
            )
        )

        if top_k is not None:
            filtered = filtered[:top_k]

        return filtered

def enrich_hash64(
    items: list[Tuple[str, int]]
) -> list[Tuple[str, int, int]]:
    """
    Input:  [(hex_hash, offset), ...]
    Output: [(hex_hash, hash64, offset), ...]
    """
    out = []

    for hex_hash, offset in items:
        hash64 = hex2int64(hex_hash)
        out.append((hex_hash, hash64, int(offset)))

    return out
