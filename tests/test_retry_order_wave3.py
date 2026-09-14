import unittest

from deep_tests.contract_model import Command, ReferenceStore, generate_valid_trace, replay


class RetryOrderWave3Tests(unittest.TestCase):
    def test_many_exact_duplicate_creates_do_not_advance_revision(self):
        store = ReferenceStore()
        command = Command("create", "alpha", "one", "create-alpha-wave3")
        first = store.apply(command)
        for _ in range(64):
            self.assertEqual(first, store.apply(command))
        self.assertEqual(store.revision, 1)

    def test_prime_interval_duplicate_schedules_converge(self):
        commands = generate_valid_trace(20260914, steps=900)
        snapshots = {replay(commands, duplicate_every=n).snapshot() for n in (2, 5, 13, 17, 31)}
        self.assertEqual(len(snapshots), 1)


if __name__ == "__main__":
    unittest.main()
