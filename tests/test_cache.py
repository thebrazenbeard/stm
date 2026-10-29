"""Offline cache unit tests; run: python -m unittest discover -s worker3/tests -v"""

import threading
import unittest

from stm.cache import (
    BoundedPromptPrefixCache,
    CacheIdentity,
    MockLocalBackend,
    OllamaUsage,
)


def identity(
    tenant="tenant-A", owner="user-A", agent="agent-A", session="conversation-A", model="llama:sha256:a",
    tokenizer="tokenizer-v1", template="system-policy-v1",
):
    return CacheIdentity(tenant, owner, agent, session, model, tokenizer, template)


class PrefixCacheTests(unittest.TestCase):
    def test_exact_match_hit_does_not_claim_backend_reuse(self):
        c = BoundedPromptPrefixCache()
        first = c.get_or_store(identity(), "system: safe", "revision-1")
        second = c.get_or_store(identity(), "system: safe", "revision-1")
        self.assertEqual((first.status, second.status), ("miss", "hit"))
        self.assertEqual(second.cache_kind, "application_prompt_prefix")
        self.assertEqual(second.prefix, "system: safe")
        self.assertEqual((c.stats().hits, c.stats().misses), (1, 1))
        self.assertFalse(hasattr(second, "kv_cache_hit"))

    def test_changed_prefix_invalidates_not_a_false_hit(self):
        c = BoundedPromptPrefixCache()
        c.get_or_store(identity(), "system: old", "r1")
        changed = c.get_or_store(identity(), "system: new", "r1")
        self.assertEqual(changed.status, "miss")
        self.assertEqual(changed.invalidation_reason, "rendered_prefix_changed")
        self.assertEqual(c.stats().invalidations, 1)
        self.assertEqual(c.get_or_store(identity(), "system: new", "r1").status, "hit")

    def test_compaction_or_correction_revision_invalidates_even_unchanged_text(self):
        c = BoundedPromptPrefixCache()
        c.get_or_store(identity(), "prefix", "before-compaction")
        result = c.get_or_store(identity(), "prefix", "after-compaction")
        self.assertEqual(result.status, "miss")
        self.assertEqual(result.invalidation_reason, "context_revision_changed")
        self.assertEqual(c.stats().invalidations, 1)

    def test_identity_scopes_users_agents_sessions_models_tokenizers_templates(self):
        c = BoundedPromptPrefixCache()
        variants = [
            identity(),
            identity(tenant="tenant-B"),
            identity(owner="user-B"),
            identity(agent="agent-B"),
            identity(session="conversation-B"),
            identity(model="llama:sha256:b"),
            identity(tokenizer="tokenizer-v2"),
            identity(template="new-policy"),
        ]
        for variant in variants:
            self.assertEqual(c.get_or_store(variant, "same prefix", "r1").status, "miss")
        self.assertEqual(c.stats().entries, len(variants))
        for variant in variants:
            self.assertEqual(c.get_or_store(variant, "same prefix", "r1").status, "hit")

    def test_lru_evicts_oldest_and_bounds_entry_count(self):
        c = BoundedPromptPrefixCache(max_entries=2)
        a, b, d = identity(session="a"), identity(session="b"), identity(session="d")
        for i in (a, b):
            c.get_or_store(i, "abc", "r1")
        c.get_or_store(a, "abc", "r1")  # most recently used
        c.get_or_store(d, "abc", "r1")
        self.assertEqual(c.stats().evictions, 1)
        self.assertEqual(c.get_or_store(a, "abc", "r1").status, "hit")
        self.assertEqual(c.get_or_store(b, "abc", "r1").status, "miss")
        self.assertLessEqual(c.stats().entries, 2)

    def test_payload_byte_bound_uses_utf8_not_characters(self):
        c = BoundedPromptPrefixCache(max_entries=20, max_bytes=8, max_prefix_bytes=8)
        c.get_or_store(identity(session="first"), "🌿", "r1")  # 4 bytes
        c.get_or_store(identity(session="second"), "🌿", "r1")
        self.assertEqual(c.stats().payload_bytes, 8)
        c.get_or_store(identity(session="third"), "🌿", "r1")
        self.assertEqual(c.stats().payload_bytes, 8)
        self.assertEqual(c.stats().evictions, 1)

    def test_oversized_prefix_does_not_displace_other_tenant(self):
        c = BoundedPromptPrefixCache(max_bytes=12, max_prefix_bytes=10)
        c.get_or_store(identity(session="good"), "small", "r1")
        decision = c.get_or_store(identity(session="oversized"), "x" * 11, "r1")
        self.assertFalse(decision.stored)
        self.assertEqual(decision.invalidation_reason, "prefix_too_large")
        self.assertEqual(c.get_or_store(identity(session="good"), "small", "r1").status, "hit")
        self.assertEqual(c.stats().oversized, 1)

    def test_fixed_age_expiration_and_explicit_prune(self):
        clock = [0.0]
        c = BoundedPromptPrefixCache(max_age_seconds=10, clock=lambda: clock[0])
        c.get_or_store(identity(), "a", "r1")
        clock[0] = 9.99
        self.assertEqual(c.get_or_store(identity(), "a", "r1").status, "hit")
        clock[0] = 10.0
        self.assertEqual(c.prune_expired(), 1)
        self.assertEqual(c.stats().entries, 0)
        self.assertEqual(c.stats().expired, 1)

    def test_session_invalidation_clears_all_model_variants_not_other_sessions(self):
        c = BoundedPromptPrefixCache()
        a, model_b = identity(), identity(model="updated-model")
        independent = identity(session="other")
        for key in (a, model_b, independent):
            c.get_or_store(key, "private content", "r1")
        self.assertEqual(c.invalidate_session("tenant-A", "user-A", "agent-A", "conversation-A"), 2)
        self.assertEqual(c.stats().entries, 1)
        self.assertEqual(c.get_or_store(independent, "private content", "r1").status, "hit")
        self.assertEqual(c.get_or_store(a, "private content", "r1").status, "miss")

    def test_concurrent_writes_do_not_corrupt_accounting(self):
        c = BoundedPromptPrefixCache(max_entries=16, max_bytes=1024, max_prefix_bytes=128)
        errors = []

        def worker(n):
            try:
                for step in range(100):
                    c.get_or_store(identity(session=f"s{n}"), f"value:{step % 5}", f"r{step % 5}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        stats = c.stats()
        self.assertLessEqual(stats.entries, 16)
        self.assertLessEqual(stats.payload_bytes, 1024)
        self.assertEqual(stats.hits + stats.misses, 800)

    def test_mock_backend_reuse_is_explicitly_application_only(self):
        cache = BoundedPromptPrefixCache()
        mock = MockLocalBackend()
        kwargs = dict(identity=identity(), rendered_prefix="policy", context_revision="r1", cache=cache)
        a = mock.generate(**kwargs, user_input="hello")
        b = mock.generate(**kwargs, user_input="again")
        self.assertEqual(a.application_cache.status, "miss")
        self.assertEqual(b.application_cache.status, "hit")
        self.assertEqual(b.backend_cache_evidence, "unverified")
        self.assertEqual(mock.calls, 2)

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            identity(owner="")
        with self.assertRaises(ValueError):
            BoundedPromptPrefixCache(max_entries=0)
        with self.assertRaises(ValueError):
            BoundedPromptPrefixCache(max_entries=True)
        with self.assertRaises(ValueError):
            BoundedPromptPrefixCache(max_age_seconds=0)
        with self.assertRaises(ValueError):
            BoundedPromptPrefixCache(max_age_seconds=float("nan"))
        c = BoundedPromptPrefixCache()
        with self.assertRaises(ValueError):
            c.get_or_store(identity(), "p", "")


class OllamaUsageTests(unittest.TestCase):
    def test_backend_reported_counts_not_app_cache_claims(self):
        data = {
            "done": True, "prompt_eval_count": 91,
            "prompt_eval_cached_count": 85, "prompt_eval_duration": 5_000_000,
        }
        usage = OllamaUsage.from_response(data)
        self.assertEqual(usage.cache_evidence, "cached_tokens_reported")
        self.assertEqual(usage.prompt_cached_tokens_reported, 85)

    def test_missing_metrics_remain_unknown(self):
        self.assertEqual(OllamaUsage.from_response({"done": False}).cache_evidence, "unreported")
        self.assertEqual(OllamaUsage.from_response({"done": True}).cache_evidence, "unreported")
        self.assertEqual(
            OllamaUsage.from_response({"done": True, "prompt_eval_cached_count": 0}).cache_evidence,
            "zero_cached_tokens_reported",
        )

    def test_invalid_backend_cached_count_rejected(self):
        with self.assertRaises(ValueError):
            OllamaUsage.from_response({"done": True, "prompt_eval_count": 5, "prompt_eval_cached_count": 6})


if __name__ == "__main__":
    unittest.main()
