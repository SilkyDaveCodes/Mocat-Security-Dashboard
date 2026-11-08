"""Tests for agent.detectors.dga_features: the DGA feature extractor (CLAUDE.md §6.3, §7).

Pure functions only: no network, no files, no OS-specific code.
"""

from __future__ import annotations

import math

import pytest

from agent.detectors import dga_features
from agent.detectors.dga_features import (
    BIGRAM_VOCABULARY_SIZE,
    FEATURE_NAMES,
    REFERENCE_BIGRAM_COUNTS,
    bigram_rarity,
    features,
    registered_label,
)

# --- AC1: features are computed on the registered-domain label -------------------------------


def test_www_google_com_is_computed_on_google() -> None:
    assert registered_label("www.google.com") == "google"
    assert features("www.google.com") == features("google")
    assert features("www.google.com")["length"] == 6  # "google", not "www.google.com" (14)


@pytest.mark.parametrize(
    ("hostname", "label"),
    [
        ("news.bbc.co.uk", "bbc"),
        ("bbc.co.uk", "bbc"),
        ("www.abc.net.au", "abc"),
        ("shop.example.co.jp", "example"),
        ("mail.example.com.br", "example"),
        ("a.b.c.example.org", "example"),
    ],
)
def test_multi_part_suffix_gives_label_left_of_suffix(hostname: str, label: str) -> None:
    assert registered_label(hostname) == label


@pytest.mark.parametrize(
    ("hostname", "label"),
    [
        ("google.com.", "google"),  # trailing dot (fully qualified name)
        ("WWW.Google.COM", "google"),  # uppercase
        ("  google.com  ", "google"),  # surrounding whitespace
        ("localhost", "localhost"),  # bare label, no dot
        ("LOCALHOST.", "localhost"),
        ("co.uk", "co"),  # the hostname is itself a public suffix
        ("a..example.com", "example"),  # doubled dot -> empty label ignored
        ("cdn-77.my-site2.com", "my-site2"),  # digits and hyphens kept
        ("xn--bcher-kva.example", "xn--bcher-kva"),  # punycode kept as-is
        ("_ldap._tcp.example.com", "example"),
        ("", ""),
        (".", ""),
        ("...", ""),
        ("   ", ""),
        ("192.168.56.20", ""),  # IPv4 literal has no domain label
        ("::1", ""),  # IPv6 literal
        ("[2001:db8::1]", ""),  # bracketed IPv6 literal
    ],
)
def test_registered_label_edge_cases(hostname: str, label: str) -> None:
    assert registered_label(hostname) == label


def test_none_hostname_gives_empty_label() -> None:
    assert registered_label(None) == ""


@pytest.mark.parametrize("hostname", ["", ".", "192.168.56.20", "[::1]", None])
def test_no_label_gives_all_zero_features(hostname: str | None) -> None:
    assert features(hostname) == {name: 0.0 for name in FEATURE_NAMES}


def test_ip_literal_features_never_use_the_digits() -> None:
    # §7: never use IP addresses as features. An IP literal must not leak its digits.
    assert features("203.0.113.5")["digit_ratio"] == 0.0


# --- AC2: hand-checked value per feature -----------------------------------------------------


def test_length_hand_checked() -> None:
    # "example.com" -> label "example" = e,x,a,m,p,l,e = 7 characters.
    assert features("example.com")["length"] == 7
    assert features("a")["length"] == 1


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("aaaa", 0.0),  # one symbol, p=1: -1*log2(1) = 0
        ("ab", 1.0),  # p(a)=p(b)=1/2: -2*(1/2*log2(1/2)) = 1 bit
        ("aabb", 1.0),  # same distribution as "ab"
        ("abcd", 2.0),  # four symbols at 1/4: -4*(1/4*log2(1/4)) = 2 bits
        # "google": g=2/6, o=2/6, l=1/6, e=1/6
        # = 2*(1/3*log2 3) + 2*(1/6*log2 6) = (2/3)*1.58496 + (1/3)*2.58496 = 1.91830
        ("google", 1.9182958),
    ],
)
def test_entropy_hand_checked(label: str, expected: float) -> None:
    assert features(label)["entropy"] == pytest.approx(expected, abs=1e-6)


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("hello", 0.4),  # e, o = 2 vowels / 5
        ("rhythm", 0.0),  # y is not a vowel
        ("aeiou", 1.0),
        ("a1-2", 0.25),  # 1 vowel / 4 characters (digits and hyphen count in the length)
    ],
)
def test_vowel_ratio_hand_checked(label: str, expected: float) -> None:
    assert features(label)["vowel_ratio"] == pytest.approx(expected)


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("a1b2", 0.5),  # 2 digits / 4
        ("google", 0.0),
        ("123", 1.0),
        ("xjq7vzk2pq", 0.2),  # 7 and 2 = 2 digits / 10
    ],
)
def test_digit_ratio_hand_checked(label: str, expected: float) -> None:
    assert features(label)["digit_ratio"] == pytest.approx(expected)


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("strength", 4),  # s-t-r (3), e, n-g-t-h (4) -> 4
        ("rhythm", 6),  # y counts as a consonant: r-h-y-t-h-m
        ("aeiou", 0),
        ("bc1dfg", 3),  # digit breaks the run: b-c (2), d-f-g (3)
        ("bc-dfg", 3),  # hyphen breaks the run too
        ("xjq7vzk2pq", 3),  # x-j-q (3), v-z-k (3), p-q (2)
    ],
)
def test_longest_consonant_run_hand_checked(label: str, expected: int) -> None:
    assert features(label)["longest_consonant_run"] == expected


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("google", 4),  # g, o, l, e
        ("aaaa", 1),
        ("a1-b1", 4),  # a, 1, -, b
    ],
)
def test_unique_chars_hand_checked(label: str, expected: int) -> None:
    assert features(label)["unique_chars"] == expected


def test_bigram_rarity_hand_checked_with_small_table() -> None:
    # Table chosen so N + V = 2727 + 1369 = 4096 = 2**12.
    # p(ab) = (2047 + 1) / 4096 = 1/2 -> 1 bit; an unseen bigram: 1/4096 -> 12 bits.
    table = {"ab": 2047, "zz": 680}
    assert BIGRAM_VOCABULARY_SIZE == 37**2 == 1369
    assert bigram_rarity("ab", table) == pytest.approx(1.0)
    assert bigram_rarity("abx", table) == pytest.approx((1.0 + 12.0) / 2)  # ab, bx -> 6.5
    assert bigram_rarity("qq", table) == pytest.approx(12.0)
    assert bigram_rarity("a", table) == 0.0  # no bigrams
    assert bigram_rarity("", table) == 0.0


def test_bigram_rarity_default_table_unseen_bigram_is_maximum() -> None:
    # "qq" never appears in the reference words, so p = 1 / (N + V) -> log2(N + V) bits.
    n_total = sum(REFERENCE_BIGRAM_COUNTS.values())
    assert "qq" not in REFERENCE_BIGRAM_COUNTS
    assert features("qq")["bigram_rarity"] == pytest.approx(math.log2(n_total + 1369))


def test_bigram_rarity_default_table_common_bigram() -> None:
    # "th" has count c in the reference: score = -log2((c + 1) / (N + V)).
    c = REFERENCE_BIGRAM_COUNTS["th"]
    n_total = sum(REFERENCE_BIGRAM_COUNTS.values())
    assert c > 0
    expected = -math.log2((c + 1) / (n_total + 1369))
    assert features("th")["bigram_rarity"] == pytest.approx(expected)
    assert features("th")["bigram_rarity"] < features("qq")["bigram_rarity"]


def test_reference_table_is_built_offline_and_deterministically() -> None:
    assert REFERENCE_BIGRAM_COUNTS == dga_features._count_bigrams(dga_features.REFERENCE_WORDS)


# --- AC3: random-looking label scores higher than google -------------------------------------


def test_random_label_has_higher_entropy_and_bigram_rarity_than_google() -> None:
    random_like = features("xjq7vzk2pq")
    google = features("google")
    assert random_like["entropy"] > google["entropy"]
    assert random_like["bigram_rarity"] > google["bigram_rarity"]


def test_random_label_with_suffix_still_scores_higher() -> None:
    assert features("xjq7vzk2pq.com")["bigram_rarity"] > features("www.google.com")["bigram_rarity"]


# --- AC4: same keys, same order, for every input ---------------------------------------------


@pytest.mark.parametrize(
    "hostname",
    [
        "www.google.com",
        "google",
        "xjq7vzk2pq.net",
        "news.bbc.co.uk",
        "",
        None,
        "localhost",
        "google.com.",
        "WWW.GOOGLE.COM",
        "192.168.56.20",
        "[::1]",
        "a",
        "my-site2.example",
        "xn--bcher-kva.example",
    ],
)
def test_feature_keys_and_order_are_fixed(hostname: str | None) -> None:
    result = features(hostname)
    assert list(result) == list(FEATURE_NAMES)
    assert all(isinstance(value, float) for value in result.values())


def test_feature_names_constant() -> None:
    assert FEATURE_NAMES == (
        "length",
        "entropy",
        "vowel_ratio",
        "digit_ratio",
        "longest_consonant_run",
        "unique_chars",
        "bigram_rarity",
    )
