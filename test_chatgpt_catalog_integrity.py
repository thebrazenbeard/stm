"""Synthetic hostile inputs to the ephemeral catalog aggregation boundary."""

from dataclasses import replace
import unittest

from chatgpt_catalog import CatalogFailure, catalog_conversation, summarize_catalogs
from test_chatgpt_graph import SHA, sample


class CatalogIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.entry = catalog_conversation(sample(), SHA)

    def test_forged_negative_or_contradictory_counters_fail_closed(self):
        changes = (
            {"message_nodes": -1},
            {"total_nodes": 1},
            {"inactive_nodes": 900},
            {"active_path_nodes": -1},
            {"root_nodes": 0},
            {"branch_points": 900},
            {"text_parts": -4},
            {"opaque_parts": 100_001},
            {"role_counts": (("assistant", 900),)},
            {"content_type_counts": (("text", 900),)},
        )
        for changed in changes:
            with self.subTest(changed=changed):
                with self.assertRaises(CatalogFailure):
                    summarize_catalogs([replace(self.entry, **changed)], SHA)

    def test_untrusted_tags_and_authority_flags_fail_closed(self):
        changes = (
            {"authority_granted": True},
            {"requested_effect": "WRITE_MEMORY"},
            {"admission": "CURRENT_MEMORY"},
            {"evidence_class": "LIVE_EXPERIENCE"},
            {"structural_tags": ("historical-source", "private-instruction")},
            {"role_counts": (("private-role", 3),)},
            {"content_type_counts": (("private-kind", 3),)},
        )
        for changed in changes:
            with self.subTest(changed=changed):
                with self.assertRaises(CatalogFailure):
                    summarize_catalogs([replace(self.entry, **changed)], SHA)

    def test_bool_counters_and_bad_source_identity_fail_closed(self):
        changes = (
            {"total_nodes": True},
            {"message_nodes": True},
            {"conversation_id": ""},
            {"export_sha256": "not-an-export"},
        )
        for changed in changes:
            with self.subTest(changed=changed):
                with self.assertRaises(CatalogFailure):
                    summarize_catalogs([replace(self.entry, **changed)], SHA)


if __name__ == "__main__":
    unittest.main()
