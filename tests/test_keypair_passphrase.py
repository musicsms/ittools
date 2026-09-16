from ittools.core.keypair.passphrase import generate_passphrase
import pytest


def test_generate_passphrase_defaults():
    phrase = generate_passphrase(words_count=4, separator="-")
    words = phrase.split("-")
    assert len(words) == 4
    assert phrase == phrase.lower()


def test_generate_passphrase_options():
    phrase = generate_passphrase(
        words_count=3,
        separator="_",
        capitalize=True,
        include_numbers=True,
        include_special=True,
    )
    words = phrase.split("_")
    assert len(words) == 3
    assert any(c.isupper() for c in phrase)
    assert any(c.isdigit() for c in phrase)


def test_generate_passphrase_zero_or_negative_words():
    with pytest.raises(ValueError, match="words_count must be at least 1"):
        generate_passphrase(words_count=0)
    with pytest.raises(ValueError, match="words_count must be at least 1"):
        generate_passphrase(words_count=-3)


def test_generate_passphrase_randomness():
    p1 = generate_passphrase()
    p2 = generate_passphrase()
    assert p1 != p2
