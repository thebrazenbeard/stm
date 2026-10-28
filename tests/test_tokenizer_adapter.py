"""Deterministic accounting tests; no real inference backend is claimed."""

import unittest

from stm.context import BudgetOverflow, ContextItem, ContextPacker, TokenBudget
from stm.models import SessionKey
from stm.tokenizer_adapter import (
    ModelTokenizerIdentity,
    RuntimeTokenCounter,
    TokenBudgetAdapter,
)


SCOPE = SessionKey("tenant", "owner", "agent", "conversation")
OTHER_SCOPE = SessionKey("tenant", "owner", "agent", "different")
IDENTITY = ModelTokenizerIdentity("mock-model", "mock-tokenizer", "chat-v1", "rev-a")


class MockExactTokenizer:
    """Fake tokenization semantics; not an inference engine or KV cache."""

    def __init__(self):
        self.seen = []

    def count_tokens(self, prompt, *, identity):
        self.seen.append((prompt, identity))
        # Token count deliberately non-additive relative to string length.
        return len(prompt.split())


class BadBackend:
    def __init__(self, result):
        self.result = result

    def count_tokens(self, prompt, *, identity):
        return self.result


class TestTokenBudgetAdapter(unittest.TestCase):
    def test_exact_backend_counts_and_boundary(self):
        backend = MockExactTokenizer()
        adapter = TokenBudgetAdapter(IDENTITY, backend=backend)
        measured = adapter.require_fit("one two three", scope=SCOPE, limit=4,
                                       reserved=1, unit="model_tokens")
        self.assertEqual(measured.measurement.quantity, 3)
        self.assertTrue(measured.measurement.exact_backend)
        self.assertTrue(measured.fits)
        self.assertEqual(measured.available, 3)
        self.assertEqual(backend.seen[-1][1], IDENTITY)
        with self.assertRaises(BudgetOverflow):
            adapter.require_fit("one two three", scope=SCOPE, limit=4,
                                reserved=1, guardband=1, unit="model_tokens")

    def test_byte_estimate_is_explicit_and_cannot_be_mislabeled(self):
        adapter = TokenBudgetAdapter(IDENTITY)
        result = adapter.measure("é 🦊", scope=SCOPE)
        self.assertEqual(result.quantity, len("é 🦊".encode("utf-8")))
        self.assertEqual(result.unit, "utf8_bytes")
        self.assertFalse(result.exact_backend)
        self.assertTrue(adapter.require_fit("é", scope=SCOPE, limit=2, unit="utf8_bytes").fits)
        with self.assertRaisesRegex(ValueError, "incompatible"):
            adapter.assess("hi", scope=SCOPE, limit=10, unit="model_tokens")
        with self.assertRaises(RuntimeError):
            adapter.exact_counter()

    def test_invalid_counts_fail_closed(self):
        for invalid in (-1, True, 1.4, "3", None):
            with self.subTest(invalid=invalid):
                adapter = TokenBudgetAdapter(IDENTITY, backend=BadBackend(invalid))
                with self.assertRaises(ValueError):
                    adapter.measure("text", scope=SCOPE)

    def test_scope_and_full_identity_change_application_key(self):
        adapter = TokenBudgetAdapter(IDENTITY, backend=MockExactTokenizer())
        key = adapter.cache_key(SCOPE, "a b")
        self.assertEqual(key, adapter.cache_key(SCOPE, "a b"))
        self.assertNotEqual(key, adapter.cache_key(OTHER_SCOPE, "a b"))
        self.assertNotEqual(key, adapter.cache_key(SCOPE, "b a"))
        for field in ("model", "tokenizer", "template", "revision"):
            modified = {"model": IDENTITY.model, "tokenizer": IDENTITY.tokenizer,
                        "template": IDENTITY.template, "revision": IDENTITY.revision}
            modified[field] += "-changed"
            other = TokenBudgetAdapter(ModelTokenizerIdentity(**modified), backend=MockExactTokenizer())
            with self.subTest(field=field):
                self.assertNotEqual(key, other.cache_key(SCOPE, "a b"))

    def test_budget_reserve_and_guardband_validation(self):
        adapter = TokenBudgetAdapter(IDENTITY)
        for limit, reserved, guardband in ((-1, 0, 0), (1, -1, 0),
                                           (1, 0, -1), (1, 2, 0),
                                           (1, 1, 1), (True, 0, 0),
                                           (1, False, 0), (1, 0, True)):
            with self.subTest(values=(limit, reserved, guardband)):
                with self.assertRaises(ValueError):
                    adapter.assess("x", scope=SCOPE, limit=limit,
                                   reserved=reserved, guardband=guardband,
                                   unit="utf8_bytes")
        with self.assertRaises(TypeError):
            adapter.cache_key("scope", "text")
        with self.assertRaises(TypeError):
            adapter.measure(None, scope=SCOPE)

    def test_context_packer_interop_with_exact_backend(self):
        adapter = TokenBudgetAdapter(IDENTITY, backend=MockExactTokenizer())
        counter = adapter.exact_counter()
        self.assertIsInstance(counter, RuntimeTokenCounter)
        result = ContextPacker(counter=counter).pack([
            ContextItem("a", "first", score=2, created_at=1),
            ContextItem("b", "second", score=1, created_at=2),
        ], TokenBudget(4))
        self.assertEqual(result.used_tokens, 4)
        self.assertEqual(set(result.included_ids), {"a", "b"})

    def test_identity_fields_required_and_exact_units(self):
        for field in ("model", "tokenizer", "template", "revision"):
            fields = {"model": "m", "tokenizer": "t", "template": "p", "revision": "r"}
            fields[field] = ""
            with self.subTest(field=field), self.assertRaises(ValueError):
                ModelTokenizerIdentity(**fields)
        with self.assertRaises(TypeError):
            TokenBudgetAdapter("not an identity")


if __name__ == "__main__":
    unittest.main()
