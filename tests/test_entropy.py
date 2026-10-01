from src.entropy import shannon_entropy


def test_entropy_zero_for_repeated_string():
    assert shannon_entropy("aaaa") == 0.0


def test_entropy_increases_for_diverse_string():
    assert shannon_entropy("abcd1234") > 2.0


def test_empty_string_entropy_zero():
    assert shannon_entropy("") == 0.0
