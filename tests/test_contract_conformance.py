import copy
import datetime
import unittest

from deep_tests.contract_model import (
    Command,
    ContractViolation,
    IdempotencyConflict,
    ReferenceStore,
    generate_valid_trace,
    replay,
    validate_desktop_parity_record,
)


class ContractConformanceTests(unittest.TestCase):
    def test_stateful_model_replays_deterministically_across_many_seeds(self) -> None:
        for seed in range(32):
            commands = generate_valid_trace(seed, steps=240)
            first = replay(commands, duplicate_every=7)
            second = replay(commands, duplicate_every=5)
            self.assertEqual(first.snapshot(), second.snapshot(), f"seed={seed}")
            revisions = [outcome.revision for outcome in first.history]
            self.assertEqual(revisions, list(range(1, len(revisions) + 1)))

    def test_idempotency_key_reuse_with_different_intent_fails_closed(self) -> None:
        store = ReferenceStore()
        store.apply(Command("create", "a", "one", "same-key"))
        with self.assertRaises(IdempotencyConflict):
            store.apply(Command("update", "a", "two", "same-key"))

    def test_snapshot_is_canonical_independent_of_insertion_order(self) -> None:
        left = ReferenceStore()
        right = ReferenceStore()
        for entity_id in ("b", "a", "c"):
            left.apply(Command("create", entity_id, entity_id.upper(), f"l-{entity_id}"))
        for entity_id in ("c", "b", "a"):
            right.apply(Command("create", entity_id, entity_id.upper(), f"r-{entity_id}"))
        self.assertEqual(left.snapshot(), right.snapshot())

    def test_delete_creates_tombstone_and_duplicate_is_side_effect_free(self) -> None:
        store = ReferenceStore()
        store.apply(Command("create", "a", "one", "create-a"))
        delete = Command("delete", "a", None, "delete-a")
        first = store.apply(delete)
        duplicate = store.apply(delete)
        self.assertEqual(first, duplicate)
        self.assertEqual(store.revision, 2)
        self.assertIn('"tombstones":["a"]', store.snapshot())

    def test_desktop_parity_requires_current_evidence_for_both_clients(self) -> None:
        record = self._parity_record()
        validate_desktop_parity_record(
            record,
            today=datetime.date(2026, 8, 25),
        )
        self.assertEqual(
            set(record["implementations"]),
            {"rust_desktop", "flutter_desktop"},
        )

    def test_desktop_parity_rejects_missing_or_unknown_implementations(self) -> None:
        for implementations in (
            {"rust_desktop": self._parity_record()["implementations"]["rust_desktop"]},
            self._parity_record()["implementations"] | {"web_desktop": {}},
        ):
            record = self._parity_record() | {"implementations": implementations}
            with self.subTest(implementations=set(implementations)), self.assertRaises(
                ContractViolation
            ):
                validate_desktop_parity_record(record, today=datetime.date(2026, 8, 25))

    def test_desktop_parity_deferred_decisions_expire_and_need_issues(self) -> None:
        expired = copy.deepcopy(self._parity_record())
        expired["implementations"]["flutter_desktop"]["review_expires_on"] = "2026-08-24"
        missing_issue = copy.deepcopy(self._parity_record())
        del missing_issue["implementations"]["flutter_desktop"]["follow_up_issue"]
        for record in (expired, missing_issue):
            with self.assertRaises(ContractViolation):
                validate_desktop_parity_record(record, today=datetime.date(2026, 8, 25))

    def test_desktop_parity_implemented_status_needs_unique_evidence(self) -> None:
        for evidence in ([], ["test:one", "test:one"]):
            record = self._parity_record()
            record["implementations"]["rust_desktop"]["evidence"] = evidence
            with self.subTest(evidence=evidence), self.assertRaises(ContractViolation):
                validate_desktop_parity_record(record, today=datetime.date(2026, 8, 25))

    @staticmethod
    def _parity_record() -> dict:
        return {
            "contract_version": 1,
            "change_id": "proximity-v1",
            "changed_contracts": ["proximity", "desktop_companion"],
            "implementations": {
                "rust_desktop": {
                    "repository": "file-tunnel/ftnl-desktop-app.rs",
                    "status": "implemented",
                    "evidence": ["test:descriptor-validation"],
                },
                "flutter_desktop": {
                    "repository": "file-tunnel/ftnl-flutter",
                    "status": "blocked",
                    "rationale": "The companion repository does not exist yet.",
                    "follow_up_issue": "https://github.com/file-tunnel/.github/issues/11",
                    "review_expires_on": "2026-09-30",
                },
            },
        }


if __name__ == "__main__":
    unittest.main()
