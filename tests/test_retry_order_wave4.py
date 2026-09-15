import unittest

from deep_tests.contract_model import Command, ReferenceStore, generate_valid_trace, replay


class RetryOrderWave4Tests(unittest.TestCase):
    def test_128_duplicate_creates_preserve_single_revision_and_history_entry(self):
        store = ReferenceStore()
        command = Command("create", "alpha", "one", "create-alpha-wave4")
        first = store.apply(command)
        for _ in range(128):
            self.assertEqual(first, store.apply(command))
        self.assertEqual(store.revision, 1)
        self.assertEqual(store.history, (first,))

    def test_old_delete_retry_cannot_delete_later_reincarnation(self):
        store = ReferenceStore()
        store.apply(Command("create", "alpha", "v1", "create-alpha-v1-wave4"))
        deleted = store.apply(Command("delete", "alpha", None, "delete-alpha-v1-wave4"))
        recreated = store.apply(Command("create", "alpha", "v2", "create-alpha-v2-wave4"))

        self.assertEqual(
            deleted,
            store.apply(Command("delete", "alpha", None, "delete-alpha-v1-wave4")),
        )
        self.assertEqual(store.revision, 3)
        self.assertEqual(store.history, (store.history[0], deleted, recreated))
        self.assertIn('"alpha":"v2"', store.snapshot())

    def test_seven_prime_duplicate_schedules_converge_for_1200_steps(self):
        commands = generate_valid_trace(20260915, steps=1200)
        schedules = (2, 3, 5, 7, 11, 17, 29)
        snapshots = {replay(commands, duplicate_every=n).snapshot() for n in schedules}
        self.assertEqual(len(snapshots), 1)


if __name__ == "__main__":
    unittest.main()
