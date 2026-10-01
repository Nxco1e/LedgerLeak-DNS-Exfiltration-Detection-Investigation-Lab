"""Entropy and related DNS feature calculations."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy for a string.

    High entropy is useful for identifying random-looking or algorithmically
    generated strings because encoded payloads and tunnelled DNS labels often
    contain a broad distribution of characters, rather than human-readable
    words with repeated vowels and consonants.
    """
    if not value:
        return 0.0

    counts = Counter(value)
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def character_ratio(value: str, character_type: str) -> float:
    """Return the ratio of characters in a given category."""
    if not value:
        return 0.0
    if character_type == "numeric":
        matching = sum(1 for ch in value if ch.isdigit())
    elif character_type == "alphabetic":
        matching = sum(1 for ch in value if ch.isalpha())
    elif character_type == "unique":
        return len(set(value)) / len(value)
    else:
        raise ValueError(f"Unsupported character type: {character_type}")
    return matching / len(value)
