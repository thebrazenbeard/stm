"""Synthetic-only compatibility and hostile tests for opt-in V2 projection."""

from decimal import Decimal
import hashlib
import json
import unittest
from unittest.mock import patch

from chatgpt_decimal_codec_v2 import (
    CODEC_ID, DecimalCodecFailure, decode_decimal_record_v2,
    encode_decimal_record_v2, parse_decimal_record_v2,
)
from chatgpt_archive import ChatGPTArchive


class DecimalIndexCodecV2Tests(unittest.TestCase):
    def test_distinct_high_precision_source_decimals_are_not_rounded_together(self):
        a = parse_decimal_record_v2('{"id":"synthetic","value":0.12345678901234567890}')
        b = parse_decimal_record_v2('{"id":"synthetic","value":0.12345678901234567891}')
        self.assertIsInstance(a["value"], Decimal)
        self.assertEqual(str(a["value"]), "0.12345678901234567890")
        self.assertEqual(str(b["value"]), "0.12345678901234567891")
        self.assertNotEqual(encode_decimal_record_v2(a), encode_decimal_record_v2(b))
        self.assertEqual(decode_decimal_record_v2(encode_decimal_record_v2(a)), a)

    def test_legacy_v1_binary_float_projection_collides_but_v2_is_versioned(self):
        first = json.loads('{"n":0.12345678901234567890}')
        second = json.loads('{"n":0.12345678901234567891}')
        self.assertEqual(first, second)  # the V1 precision predecessor falsifier
        a = encode_decimal_record_v2(parse_decimal_record_v2('{"n":0.12345678901234567890}'))
        b = encode_decimal_record_v2(parse_decimal_record_v2('{"n":0.12345678901234567891}'))
        self.assertNotEqual(a, b)
        self.assertNotEqual(a[:1], b"{")  # explicit format marker, not V1 JSON
        self.assertTrue(CODEC_ID.endswith("_V2_CANDIDATE"))

    def test_legacy_v1_serializer_bytes_remain_an_explicit_compatibility_oracle(self):
        legacy_item = json.loads('{"n":0.12345678901234567890}')
        legacy_bytes = ChatGPTArchive._serialize(legacy_item)
        self.assertEqual(legacy_bytes, b'{"n":0.12345678901234568}')
        self.assertEqual(
            hashlib.sha256(legacy_bytes).hexdigest(),
            "e99bfba10da2e34883d4aa1977c29d1489ffa89e86e1685a5c143a3942280518",
        )
        v2_bytes = encode_decimal_record_v2(
            parse_decimal_record_v2('{"n":0.12345678901234567890}')
        )
        self.assertNotEqual(v2_bytes, legacy_bytes)

    def test_nested_object_order_unicode_and_json_scalar_types_are_deterministic(self):
        a = parse_decimal_record_v2('{"z":{"b":2.500,"a":[true,null,"caf\\u00e9",-0.01]},"a":1}')
        b = parse_decimal_record_v2('{"a":1,"z":{"a":[true,null,"caf\\u00e9",-0.01],"b":2.500}}')
        self.assertEqual(encode_decimal_record_v2(a), encode_decimal_record_v2(b))
        self.assertEqual(decode_decimal_record_v2(encode_decimal_record_v2(a)), a)
        self.assertIn(b'"b":2.500', encode_decimal_record_v2(a))

    def test_spelling_of_equivalent_exponents_is_not_claimed_source_exact(self):
        a = encode_decimal_record_v2(parse_decimal_record_v2('{"n":1e0}'))
        b = encode_decimal_record_v2(parse_decimal_record_v2('{"n":1e+00}'))
        self.assertEqual(a, b)  # original lexical spelling is NOT recoverable

    def test_negative_integer_zero_lexeme_is_not_claimed_byte_exact(self):
        self.assertEqual(
            encode_decimal_record_v2(parse_decimal_record_v2('{"n":-0}')),
            encode_decimal_record_v2(parse_decimal_record_v2('{"n":0}')),
        )
        self.assertNotEqual(
            encode_decimal_record_v2(parse_decimal_record_v2('{"n":-0.0}')),
            encode_decimal_record_v2(parse_decimal_record_v2('{"n":0.0}')),
        )

    def test_rejects_nonfinite_source_constants_and_unsupported_floats(self):
        for raw in ('{"n":NaN}', '{"n":Infinity}', '{"n":-Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(DecimalCodecFailure):
                parse_decimal_record_v2(raw)
        for value in (float("nan"), 0.1, Decimal("NaN"), Decimal("Infinity")):
            with self.subTest(type=type(value).__name__), self.assertRaises(DecimalCodecFailure):
                encode_decimal_record_v2({"n": value})

    def test_invalid_decimal_exponent_and_non_utf8_byte_source_fail_closed(self):
        with self.assertRaises(DecimalCodecFailure):
            parse_decimal_record_v2('{"n":1e99999999999999999999999999}')
        for encoding in ("utf-16", "utf-32"):
            with self.subTest(encoding=encoding), self.assertRaises(DecimalCodecFailure):
                parse_decimal_record_v2('{"n":3.25}'.encode(encoding))
        self.assertEqual(
            parse_decimal_record_v2(b'{"n":3.25}')["n"], Decimal("3.25")
        )

    def test_duplicate_object_keys_and_nonobject_top_level_fail_closed(self):
        for raw in ('{"n":1,"n":2}', '{"n":{"x":1,"x":2}}', '[1,2]'):
            with self.subTest(raw=raw), self.assertRaises(DecimalCodecFailure):
                parse_decimal_record_v2(raw)

    def test_v1_json_or_noncanonical_v2_payload_fails_closed(self):
        for blob in (b'{"n":1}', b'no magic', b'', b'STM_CGPT_DECIMAL_V2\x00{"b":2,"a":1}'):
            with self.subTest(blob=blob[:12]), self.assertRaises(DecimalCodecFailure):
                decode_decimal_record_v2(blob)

    def test_bounded_output_and_deep_or_cyclic_structure_fail_closed(self):
        with patch("chatgpt_decimal_codec_v2.MAX_V2_RECORD_BYTES", 64):
            with self.assertRaisesRegex(DecimalCodecFailure, "budget"):
                encode_decimal_record_v2({"text": "x" * 200})
            with self.assertRaisesRegex(DecimalCodecFailure, "budget"):
                parse_decimal_record_v2('{"text":"' + 'x' * 200 + '"}')
        recursive = []
        recursive.append(recursive)
        with self.assertRaisesRegex(DecimalCodecFailure, "budget"):
            encode_decimal_record_v2({"nested": recursive})

    def test_large_exponent_remains_scientific_not_expanded(self):
        record = parse_decimal_record_v2('{"x":1e+1000000}')
        raw = encode_decimal_record_v2(record)
        self.assertLess(len(raw), 200)
        self.assertIn(b'1E+1000000', raw)
        self.assertEqual(decode_decimal_record_v2(raw), record)

    def test_chunked_string_escaping_crosses_4096_character_boundary(self):
        # Source-controlled text with escapes and Unicode must round-trip even
        # when an internal chunk boundary bisects a JSON escape sequence.
        text = "x" * 4095 + '"\\\n\u2764\ufe0f' + "y" * 4098
        record = {"z": text, text: {"n": Decimal("0.10000000000000000001")}}
        payload = encode_decimal_record_v2(record)
        self.assertEqual(decode_decimal_record_v2(payload), record)
        self.assertEqual(encode_decimal_record_v2(record), payload)


if __name__ == "__main__":
    unittest.main()
