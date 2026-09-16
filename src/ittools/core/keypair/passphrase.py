"""Cryptographically secure passphrase generation."""

from __future__ import annotations

import secrets
import string

# Embedded curated list of common, friendly English words (256 words)
WORDLIST: tuple[str, ...] = (
    "ability", "above", "absent", "absorb", "abstract", "academy", "accent", "accept",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "action", "active", "actor", "actress", "actual", "adapt", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford",
    "afraid", "again", "agency", "agent", "agree", "ahead", "aim", "airport",
    "alarm", "album", "alcohol", "alert", "alien", "allow", "almost", "alone",
    "alpha", "already", "alter", "always", "amateur", "amazing", "among", "amount",
    "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal",
    "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety",
    "any", "apart", "apology", "appear", "apple", "approve", "april", "arch",
    "arctic", "area", "arena", "argue", "armor", "army", "around", "arrange",
    "arrest", "arrive", "arrow", "artist", "artwork", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude",
    "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn",
    "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful",
    "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance",
    "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty",
    "because", "become", "beef", "before", "begin", "behave", "behind", "believe",
    "below", "belt", "bench", "benefit", "best", "betray", "better", "between",
    "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth",
    "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board",
    "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost",
    "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy",
    "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick",
    "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
    "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo",
    "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger",
    "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage",
    "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera",
    "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
    "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo",
    "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual",
    "cat", "catalog", "catch", "category", "cattle", "cause", "caution", "cave",
)

SPECIAL_CHARACTERS: str = "!@#$%^&*?"


def generate_passphrase(
    words_count: int = 4,
    separator: str = "-",
    capitalize: bool = False,
    include_numbers: bool = False,
    include_special: bool = False,
) -> str:
    """Generate a cryptographically secure passphrase from an embedded wordlist.

    Args:
        words_count: Number of words in the passphrase (minimum 1).
        separator: String delimiter placed between words.
        capitalize: If True, capitalize each word.
        include_numbers: If True, append a random digit (0-9).
        include_special: If True, append a random special character.

    Returns:
        The generated passphrase string.

    Raises:
        ValueError: If words_count is less than 1.
    """
    if words_count < 1:
        raise ValueError("words_count must be at least 1")

    chosen_words = [secrets.choice(WORDLIST) for _ in range(words_count)]
    if capitalize:
        chosen_words = [w.capitalize() for w in chosen_words]
    else:
        chosen_words = [w.lower() for w in chosen_words]

    suffix = ""
    if include_numbers:
        suffix += secrets.choice(string.digits)
    if include_special:
        safe_specials = [c for c in SPECIAL_CHARACTERS if c != separator] or ["!"]
        suffix += secrets.choice(safe_specials)

    return separator.join(chosen_words) + suffix
