"""Adversarial tests for the untrusted-JSON loader of the restricted broker.

GAP JUSTIFICATION (GAPS.md of the parent re-run t_3e22486c, §2): the row

    tools/restricted-broker/jsonparse.py | test che lo citano: 1 | categories
    assenti: boundary/size limits, canonicalization / determinism,
    collision / ambiguity, malformed/truncated input, path traversal / hostile
    names, resource exhaustion / amplification, rollback / atomicity,
    secret handling / redaction, timeout / liveness, unicode / normalization

is the gap this module closes: `jsonparse.load_object` is the first thing
untrusted bytes touch, so every refusal must be a typed ``EvidenceError``.

Deterministic and offline: fixed byte corpora, no network, no wall clock, no
unseeded randomness, no filesystem-order dependence.
"""

import inspect
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canonical  # noqa: E402
import jsonparse  # noqa: E402
from model import EvidenceError  # noqa: E402


def _valid_document():
    return b'{"schema":"x","operation":"push_task_branch","issue_number":53}'


class TestMalformedInput(unittest.TestCase):
    def test_every_strict_prefix_of_a_valid_document_is_refused(self):
        document = _valid_document()
        for length in range(len(document)):
            with self.assertRaises(EvidenceError):
                jsonparse.load_object(document[:length])

    def test_invalid_utf8_is_reported_as_evidence_error_not_unicode_decode_error(self):
        hostile = [
            b"\xff",
            b'{"a":"\xff"}',
            b'{"a":1}\xc3',  # truncated multi-byte sequence
            b"\xc0\xaf",  # overlong encoding
            b"\xed\xa0\x80",  # surrogate code point
            b"\xff\xfe{\x00",  # UTF-16 BOM bytes
            b'{"a":1}\x00',
            b"\xe2\x82",  # truncated 3-byte sequence
        ]
        for raw in hostile:
            with self.assertRaises(EvidenceError):
                jsonparse.load_object(raw)

    def test_non_object_roots_are_refused(self):
        for raw in (b"[]", b"[{}]", b'"s"', b"5", b"1.5", b"true", b"false", b"null", b""):
            with self.assertRaises(EvidenceError):
                jsonparse.load_object(raw)

    def test_whitespace_only_and_truncated_shapes_are_refused(self):
        for raw in (b" ", b"\n", b"\t\r\n", b"{", b"}", b'{"a":', b'{"a":1', b'{,}', b'{"a":1,}'):
            with self.assertRaises(EvidenceError):
                jsonparse.load_object(raw)


class TestCollisionAndCanonicalization(unittest.TestCase):
    def test_escaped_and_literal_keys_collide_and_are_both_refused(self):
        for raw in (
            b'{"a":1,"\\u0061":2}',
            b'{"\\u0061":1,"a":2}',
            b'{"x":{"a":1,"\\u0061":2}}',
            b'[{"a":1,"\\u0061":2}]',
            b'{"a":1,"a":2,"a":3}',
            b'{"\\u0041":1,"A":2}',
        ):
            with self.assertRaises(EvidenceError):
                jsonparse.load_object(raw)

    def test_unicode_normalization_is_not_applied(self):
        """NFC and NFD spellings are different keys and both must survive.

        A loader that normalized keys would silently merge two distinct
        attacker-visible fields into one (collision/ambiguity).
        """
        raw = '{"\u00f1":1,"n\u0303":2}'.encode("utf-8")
        value = jsonparse.load_object(raw)
        self.assertEqual(len(value), 2)
        self.assertEqual(value["\u00f1"], 1)
        self.assertEqual(value["n\u0303"], 2)

    def test_load_is_deterministic_and_order_preserving_for_once_seen_keys(self):
        raw = b'{"b":1,"a":2,"c":[3,{"z":4}]}'
        first = jsonparse.load_object(raw)
        second = jsonparse.load_object(raw)
        self.assertEqual(first, second)
        self.assertEqual(list(first), ["b", "a", "c"])
        self.assertIsNot(first, second)


class TestHostileNamesAndBoundaries(unittest.TestCase):
    def test_path_traversal_and_control_characters_are_preserved_verbatim(self):
        hostile = [
            "../../etc/passwd",
            "/etc/passwd",
            "..\\..\\windows\\system32",
            "x\u0000y",
            "a/b/../../c",
            "\u202e/link",
            "./.",
            "\\\\server\\share",
        ]
        for name in hostile:
            raw = ('{"%s":"%s"}' % (name.replace("\\", "\\\\").replace("\x00", "\\u0000"), "v")).encode(
                "utf-8", "surrogatepass"
            )
            # The loader must not interpret, normalize or strip anything: it is
            # a JSON reader, not a path resolver.
            value = jsonparse.load_object(raw)
            self.assertEqual(len(value), 1)
            self.assertEqual(list(value), [name])

    def test_no_silent_truncation_of_large_fields(self):
        big_key = "k" * 100000
        big_value = "v" * 500000
        raw = ('{"%s":"%s"}' % (big_key, big_value)).encode("utf-8")
        value = jsonparse.load_object(raw)
        self.assertEqual(list(value), [big_key])
        self.assertEqual(value[big_key], big_value)

    def test_deep_nesting_is_parsed_deterministically_with_no_depth_bound(self):
        """Observed (see FINDINGS.md): the loader applies no object-depth bound.

        A 20k-deep document is parsed in full and deterministically. This is a
        resource/amplification observation, not a silent-truncation hazard: the
        value is complete (the leaf is reachable and nothing was dropped), and
        the loader neither crashes nor returns a partial document.
        """
        depth = 20000
        raw = b'{"a":' * depth + b'1' + b'}' * depth
        first = jsonparse.load_object(raw)
        second = jsonparse.load_object(raw)
        self.assertEqual(first, second)
        node = first
        for _ in range(depth - 1):
            node = node["a"]
        self.assertEqual(node, {"a": 1})

    def test_source_carries_no_network_clock_or_randomness(self):
        source = inspect.getsource(jsonparse)
        for token in ("import socket", "urllib", "http.client", "subprocess", "time.", "random.", "datetime"):
            self.assertNotIn(token, source, token)


class TestSecretHandlingBoundary(unittest.TestCase):
    def test_loader_returns_secrets_verbatim_so_redaction_stays_in_audit(self):
        """jsonparse performs no redaction by contract; audit.sanitize owns it.

        This pins the layering: the loader must not mutate or drop payload
        bytes (that would break the canonical hash of the request), and the
        redaction duty is asserted in test_adversarial_boundaries.
        """
        token = "ghp_" + "a" * 36
        raw = ('{"evidence":{"token":"%s"}}' % token).encode("utf-8")
        value = jsonparse.load_object(raw)
        self.assertEqual(value["evidence"]["token"], token)
        self.assertNotIn("[redacted]", value["evidence"]["token"])


class TestUnicodeBoundaries(unittest.TestCase):
    def test_surrogate_escapes_and_bmp_boundaries_are_handled(self):
        value = jsonparse.load_object(b'{"emoji":"\\ud83d\\ude00","max":"\\uffff"}')
        self.assertEqual(value["emoji"], "\U0001f600")
        self.assertEqual(value["max"], "\uffff")

    def test_lone_surrogate_escape_is_preserved_then_fails_at_canonicalization(self):
        """Observed layering (see FINDINGS.md).

        The loader keeps the lone surrogate escape -- ``json.loads`` accepts it
        -- and the refusal happens one layer later, as a ``UnicodeEncodeError``
        raised by the canonical serializer. Fail-closed, but the loader's own
        typed-refusal contract does not hold for this input class.
        """
        value = jsonparse.load_object(b'{"a":"\\ud800"}')
        self.assertEqual(value["a"], "\ud800")
        with self.assertRaises(UnicodeEncodeError):
            canonical.canonical_bytes(value)

    def test_keys_are_never_regex_interpreted(self):
        raw = b'{"(a+)+$":"x","[a-z]*":"y"}'
        value = jsonparse.load_object(raw)
        self.assertEqual(set(value), {"(a+)+$", "[a-z]*"})
        self.assertIsNone(re.match(r"^$", "(a+)+$"))


if __name__ == "__main__":
    unittest.main()
