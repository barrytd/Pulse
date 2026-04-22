# tests/test_ref_id.py
# --------------------
# Covers the short reference ID helpers added in v1.5 for the Findings UI.
# compute_ref_prefix() turns a rule name into a 3-letter uppercase tag,
# compute_ref_id() stitches that prefix with the row's integer id into the
# "PTH-0142" format rendered as a pill in the table.

from pulse.database import compute_ref_id, compute_ref_prefix


class TestComputeRefPrefix:
    def test_three_or_more_words_takes_one_initial_each(self):
        # "Pass-the-Hash Attempt" splits into 4 words; prefix is P+T+H.
        assert compute_ref_prefix("Pass-the-Hash Attempt") == "PTH"

    def test_two_words_pads_first_word(self):
        # "Brute Force" -> B + r (second char of first word) + F.
        assert compute_ref_prefix("Brute Force") == "BRF"

    def test_two_words_short_first_word_uses_x(self):
        # Single-letter first word can't provide a second char, so we fall
        # back to X so the prefix is still 3 characters.
        assert compute_ref_prefix("A Bomber") == "AXB"

    def test_single_word_takes_first_three_chars(self):
        assert compute_ref_prefix("Kerberoasting") == "KER"

    def test_short_single_word_is_padded(self):
        assert compute_ref_prefix("Go") == "GOX"

    def test_empty_rule_falls_back_to_rul(self):
        assert compute_ref_prefix("") == "RUL"
        assert compute_ref_prefix(None) == "RUL"

    def test_non_alpha_is_ignored_as_separator(self):
        # Commas, slashes, numbers all count as word separators.
        assert compute_ref_prefix("RDP / Logon, 4624") == "RDL"


class TestComputeRefId:
    def test_zero_pads_to_four_digits(self):
        assert compute_ref_id("Brute Force", 9) == "BRF-0009"
        assert compute_ref_id("Brute Force", 89) == "BRF-0089"
        assert compute_ref_id("Brute Force", 1234) == "BRF-1234"

    def test_does_not_truncate_large_ids(self):
        # Pulse may eventually carry more than 9999 findings — the ID should
        # just grow past the four-digit pad rather than roll over.
        assert compute_ref_id("Kerberoasting", 12345) == "KER-12345"

    def test_coerces_numeric_strings(self):
        # executemany paths call this with ints from the DB, but the helper
        # should be robust if a caller passes a str.
        assert compute_ref_id("Pass-the-Hash Attempt", "42") == "PTH-0042"
