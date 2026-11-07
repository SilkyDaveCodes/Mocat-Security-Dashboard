"""DGA feature extractor shared by training and the live detector (CLAUDE.md §6.3, §7).

``models/train_dga.py`` and ``agent/detectors/dga.py`` both call :func:`features`, so the model is
always scored on exactly the features it was trained on. This module is pure Python: no network,
no files, no OS-specific code, and nothing here is a tunable threshold (those live in
``config.yaml``). Never add IP addresses or ports as features (§7).

Registered-domain label
    :func:`registered_label` picks the label just left of the public suffix:
    ``www.google.com`` -> ``google``, ``news.bbc.co.uk`` -> ``bbc``. The hostname is stripped,
    lowercased and has trailing dots removed. Public-suffix awareness comes from the small
    built-in :data:`MULTI_PART_SUFFIXES` set (common two-label ccTLD suffixes such as ``co.uk``,
    ``com.au``, ``co.jp``); any other hostname falls back to its second-to-last label. Edge cases
    (none raise):

    * empty string, ``None``, only dots or whitespace -> ``""``
    * IP literals (``192.168.56.20``, ``::1``, ``[::1]``) -> ``""``: an IP has no domain label
    * a bare label with no dot (``localhost``) -> that label
    * a hostname that *is* a multi-part suffix (``co.uk``) -> its first label (``co``)
    * empty labels from doubled dots (``a..com``) are ignored
    * digits, hyphens, underscores and punycode (``xn--...``) are kept as-is

Features, all returned as ``float`` in :data:`FEATURE_NAMES` order, computed on the label ``s``
(``n = len(s)``). An empty label gives ``0.0`` for every feature.

``length``
    ``n``.
``entropy``
    Shannon entropy in bits over the characters of ``s``:
    ``-sum(p_c * log2(p_c))`` where ``p_c`` is the share of character ``c`` in ``s``.
``vowel_ratio``
    (number of ``a e i o u``) / ``n``. ``y`` is not a vowel.
``digit_ratio``
    (number of ``0-9``) / ``n``.
``longest_consonant_run``
    Length of the longest run of consecutive consonants. A consonant is an ASCII letter ``a-z``
    that is not ``a e i o u`` (so ``y`` *is* a consonant). Digits, hyphens and any other
    character are not consonants and break a run.
``unique_chars``
    Number of distinct characters in ``s``.
``bigram_rarity``
    Mean surprisal, in bits, of the label's character bigrams under a reference table built from
    :data:`REFERENCE_WORDS` (common English words plus generic web words, no brand names), using
    add-one (Laplace) smoothing::

        p(b)  = (count(b) + 1) / (N + V)
        score = mean over the n-1 overlapping bigrams b of s of -log2(p(b))

    ``count(b)`` is how often ``b`` occurs inside a reference word, ``N`` is the total number of
    reference bigrams and ``V = 37 ** 2`` is the number of possible bigrams over the hostname
    alphabet ``a-z 0-9 -``. A label shorter than 2 characters scores ``0.0``. Higher means less
    English-like; a bigram never seen in the reference scores the maximum, ``log2(N + V)``.
"""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from collections.abc import Mapping

FEATURE_NAMES: tuple[str, ...] = (
    "length",
    "entropy",
    "vowel_ratio",
    "digit_ratio",
    "longest_consonant_run",
    "unique_chars",
    "bigram_rarity",
)

VOWELS = frozenset("aeiou")
CONSONANTS = frozenset("abcdefghijklmnopqrstuvwxyz") - VOWELS
DIGITS = frozenset("0123456789")
HOSTNAME_ALPHABET_SIZE = 37  # a-z, 0-9 and "-"
BIGRAM_VOCABULARY_SIZE = HOSTNAME_ALPHABET_SIZE**2

# Common two-label public suffixes (ICANN section of the Public Suffix List, ccTLD second levels).
# Not exhaustive: unknown suffixes fall back to the second-to-last label.
MULTI_PART_SUFFIXES: frozenset[str] = frozenset(
    """
    co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk sch.uk nhs.uk police.uk
    com.au net.au org.au edu.au gov.au asn.au id.au
    co.nz org.nz net.nz govt.nz ac.nz school.nz
    co.jp ne.jp or.jp ac.jp go.jp ad.jp ed.jp gr.jp lg.jp
    co.kr or.kr ne.kr go.kr ac.kr re.kr
    com.cn net.cn org.cn gov.cn edu.cn ac.cn
    com.tw net.tw org.tw edu.tw gov.tw
    com.hk net.hk org.hk edu.hk gov.hk
    com.sg net.sg org.sg edu.sg gov.sg
    com.my net.my org.my edu.my gov.my
    co.in net.in org.in ac.in gov.in edu.in firm.in gen.in ind.in
    co.id or.id ac.id go.id web.id
    co.th in.th ac.th go.th or.th
    com.vn net.vn edu.vn gov.vn
    com.ph net.ph org.ph edu.ph gov.ph
    com.pk net.pk org.pk edu.pk gov.pk
    com.bd gov.bd com.np com.lk
    com.br net.br org.br gov.br edu.br
    com.mx org.mx gob.mx edu.mx net.mx
    com.ar gob.ar org.ar net.ar edu.ar
    com.co gov.co edu.co net.co org.co
    com.pe gob.pe com.ve com.ec gob.cl com.uy com.py com.bo
    com.tr net.tr org.tr edu.tr gov.tr gen.tr
    co.za org.za gov.za ac.za net.za web.za
    com.eg gov.eg edu.eg com.ng gov.ng edu.ng
    co.ke or.ke ac.ke go.ke
    co.il org.il ac.il gov.il net.il
    com.sa gov.sa edu.sa com.kw com.qa com.om com.bh ac.ae gov.ae co.ir ac.ir gov.ir
    com.ua gov.ua net.ua org.ua
    com.pl net.pl org.pl gov.pl edu.pl
    co.at or.at gv.at ac.at
    com.es org.es gob.es edu.es com.pt gov.pt com.gr gov.gr com.cy
    com.ru org.ru net.ru msk.ru spb.ru
    """.split()
)

# Reference vocabulary for the bigram table: common English words plus generic web words.
# Deliberately no brand names, so no test domain is scored against itself.
REFERENCE_WORDS: tuple[str, ...] = tuple(
    """
    the of and to in is it you that he was for on are with as his they be at one have this from
    or had by hot word but what some we can out other were all there when up use your how said an
    each she which do their time if will way about many then them write would like so these her
    long make thing see him two has look more day could go come did number sound no most people
    my over know water than call first who may down side been now find any new work part take get
    place made live where after back little only round man year came show every good me give our
    under name very through just form sentence great think say help low line differ turn cause
    much mean before move right boy old too same tell does set three want air well also play small
    end put home read hand port large spell add even land here must big high such follow act why
    ask men change went light kind off need house picture try us again animal point mother world
    near build self earth father head stand own page should country found answer school grow study
    still learn plant cover food sun four between state keep eye never last let thought city tree
    cross farm hard start might story saw far sea draw left late run while press close night real
    life few north open seem together next white children begin got walk example ease paper group
    always music those both mark often letter until mile river car feet care second book carry
    took science eat room friend began idea fish mountain stop once base hear horse cut sure watch
    color face wood main enough plain girl usual young ready above ever red list though feel talk
    bird soon body dog family direct pose leave song measure door product black short numeral
    class wind question happen complete ship area half rock order fire south problem piece told
    knew pass since top whole king space heard best hour better true during hundred five remember
    step early hold west ground interest reach fast verb sing listen six table travel less morning
    ten simple several vowel toward war lay against pattern slow center love person money serve
    appear road map rain rule govern pull cold notice voice unit power town fine certain fly fall
    lead cry dark machine note wait plan figure star box noun field rest correct able pound done
    beauty drive stood contain front teach week final gave green quick develop ocean warm free
    minute strong special mind behind clear tail produce fact street inch multiply nothing course
    stay wheel full force blue object decide surface deep moon island foot system busy test record
    boat common gold possible plane dry wonder laugh thousand ago ran check game shape miss
    brought heat snow tire bring yes distant fill east paint language among
    mail web online cloud net news shop store app service services data media info search video
    stream games bank secure login account update support center portal static content api images
    image photo blog forum wiki social market health sport sports tech digital global network host
    server office download files share connect mobile phone email chat tube maps translate docs
    calendar weather finance pay payment cart deals sale buy ads analytics tracking metrics status
    edge assets local site sites page pages link links client
    """.split()
)


def _count_bigrams(words: tuple[str, ...]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for word in words:
        counts.update(word[i : i + 2] for i in range(len(word) - 1))
    return counts


REFERENCE_BIGRAM_COUNTS: Mapping[str, int] = _count_bigrams(REFERENCE_WORDS)


def registered_label(hostname: str | None) -> str:
    """Return the registered-domain label of ``hostname`` (rules in the module docstring).

    Never raises.
    """
    if not hostname:
        return ""
    host = hostname.strip().lower().rstrip(".")
    if not host or _is_ip_literal(host):
        return ""
    labels = [label for label in host.split(".") if label]
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return labels[-3] if len(labels) >= 3 else labels[0]
    return labels[-2]


def _is_ip_literal(host: str) -> bool:
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def shannon_entropy(s: str) -> float:
    """Shannon entropy of ``s`` in bits over characters; 0.0 for an empty string."""
    n = len(s)
    if n == 0:
        return 0.0
    entropy = -sum((c / n) * math.log2(c / n) for c in Counter(s).values())
    return entropy + 0.0  # turn -0.0 (single repeated character) into 0.0


def vowel_ratio(s: str) -> float:
    """Share of ``a e i o u`` in ``s``; 0.0 for an empty string."""
    return sum(ch in VOWELS for ch in s) / len(s) if s else 0.0


def digit_ratio(s: str) -> float:
    """Share of ``0-9`` in ``s``; 0.0 for an empty string."""
    return sum(ch in DIGITS for ch in s) / len(s) if s else 0.0


def longest_consonant_run(s: str) -> int:
    """Longest run of consecutive consonants (``a-z`` minus ``aeiou``; ``y`` counts)."""
    longest = current = 0
    for ch in s:
        current = current + 1 if ch in CONSONANTS else 0
        longest = max(longest, current)
    return longest


def bigram_rarity(s: str, counts: Mapping[str, int] | None = None) -> float:
    """Mean bigram surprisal of ``s`` in bits, add-one smoothed (formula in the module docstring).

    Args:
        s: The label.
        counts: Reference bigram counts. Defaults to :data:`REFERENCE_BIGRAM_COUNTS`.
    """
    if len(s) < 2:
        return 0.0
    table = REFERENCE_BIGRAM_COUNTS if counts is None else counts
    denominator = sum(table.values()) + BIGRAM_VOCABULARY_SIZE
    bigrams = [s[i : i + 2] for i in range(len(s) - 1)]
    surprisal = sum(-math.log2((table.get(b, 0) + 1) / denominator) for b in bigrams)
    return surprisal / len(bigrams)


def features(hostname: str | None) -> dict[str, float]:
    """Return the DGA features of ``hostname``'s registered-domain label, in FEATURE_NAMES order.

    Never raises. A hostname with no usable label (empty, IP literal) gives all zeros.
    """
    label = registered_label(hostname)
    return {
        "length": float(len(label)),
        "entropy": shannon_entropy(label),
        "vowel_ratio": vowel_ratio(label),
        "digit_ratio": digit_ratio(label),
        "longest_consonant_run": float(longest_consonant_run(label)),
        "unique_chars": float(len(set(label))),
        "bigram_rarity": bigram_rarity(label),
    }
