"""Synthetic-only coverage of content-free historical catalog derivation."""
import unittest

from chatgpt_catalog import CatalogFailure, catalog_conversation, summarize_catalogs
from test_chatgpt_graph import SHA, sample


class CatalogTests(unittest.TestCase):
    def test_counts_inactive_branches_and_opaque_parts_without_asset_claim(self):
        result = catalog_conversation(sample(), SHA)
        self.assertEqual((result.total_nodes, result.message_nodes), (4, 3))
        self.assertEqual(result.active_path_nodes, 3)
        self.assertEqual(result.inactive_nodes, 1)
        self.assertEqual(result.branch_points, 1)
        self.assertEqual((result.text_parts, result.opaque_parts), (3, 1))
        self.assertEqual(dict(result.role_counts), {"assistant": 2, "user": 1})
        self.assertEqual(dict(result.content_type_counts), {"text": 2, "multimodal_text": 1})
        self.assertIn("branching-history", result.structural_tags)
        self.assertIn("opaque-multimodal-parts", result.structural_tags)
        self.assertFalse(result.authority_granted)

    def test_unknown_roles_and_content_types_cannot_leak_as_categories(self):
        conversation = sample()
        payload = conversation["mapping"]["old-answer"]["message"]
        payload["author"]["role"] = "private-secret-role"
        payload["content"]["content_type"] = "private-secret-content-type"
        result = catalog_conversation(conversation, SHA)
        self.assertEqual(dict(result.role_counts)["other"], 1)
        self.assertEqual(dict(result.content_type_counts)["other"], 1)
        self.assertNotIn("private-secret", repr(result) + str(result.role_counts) + str(result.content_type_counts))

    def test_does_not_copy_content_title_metadata_or_asset_pointer(self):
        conversation = sample()
        conversation["title"] = "PRIVATE TITLE"
        conversation["mapping"]["edited-answer"]["message"]["content"]["parts"][0] = {
            "asset_pointer": "SENSITIVE POINTER"}
        result = catalog_conversation(conversation, SHA)
        all_derived = str(result.__dict__)
        for secret in ("PRIVATE TITLE", "SECRET TEXT", "do not log", "SENSITIVE POINTER"):
            self.assertNotIn(secret, all_derived)

    def test_missing_current_node_does_not_invent_path(self):
        conversation = sample()
        del conversation["current_node"]
        result = catalog_conversation(conversation, SHA)
        self.assertEqual(result.active_path_nodes, 0)
        self.assertEqual(result.inactive_nodes, result.total_nodes)
        self.assertIn("active-path-unknown", result.structural_tags)

    def test_invalid_graph_and_parts_fail_closed(self):
        conversation = sample()
        conversation["mapping"]["question"]["children"] = ["unknown"]
        with self.assertRaises(CatalogFailure):
            catalog_conversation(conversation, SHA)
        conversation = sample()
        conversation["mapping"]["old-answer"]["message"]["content"]["parts"] = "bad"
        with self.assertRaises(CatalogFailure):
            catalog_conversation(conversation, SHA)

    def test_part_budget_is_bounded(self):
        conversation = sample()
        conversation["mapping"]["old-answer"]["message"]["content"]["parts"] = [""] * 100_001
        with self.assertRaises(CatalogFailure):
            catalog_conversation(conversation, SHA)

    def test_account_summary_is_explicitly_not_source_reconciliation(self):
        a = catalog_conversation(sample(), SHA)
        second = sample()
        second["id"] = "another-conversation"
        b = catalog_conversation(second, SHA)
        summary = summarize_catalogs(iter([a, b]), SHA)
        self.assertEqual(summary.conversation_count, 2)
        self.assertEqual(summary.total_nodes, 8)
        self.assertEqual(summary.message_nodes, 6)
        self.assertEqual(summary.branching_conversations, 2)
        self.assertEqual(summary.opaque_part_conversations, 2)
        self.assertFalse(summary.coverage_verified)
        self.assertFalse(summary.source_recount_performed)
        self.assertNotIn(SHA, repr(summary))

    def test_account_summary_refuses_duplicate_ids_or_mixed_exports(self):
        a = catalog_conversation(sample(), SHA)
        with self.assertRaises(CatalogFailure):
            summarize_catalogs([a, a], SHA)
        with self.assertRaises(CatalogFailure):
            summarize_catalogs([a], "b" * 64)

    def test_account_aggregate_rejects_unbounded_stream(self):
        from dataclasses import replace

        entry = catalog_conversation(sample(), SHA)
        oversized = (
            replace(entry, conversation_id=f"synthetic-{i}")
            for i in range(50_001)
        )
        with self.assertRaisesRegex(CatalogFailure, "budget"):
            summarize_catalogs(oversized, SHA)


if __name__ == "__main__":
    unittest.main()
