import unittest
from unittest.mock import patch

from hydralysis import jobowner


class JobOwners(unittest.TestCase):
    def test_only_the_starting_client_cancels(self):
        record = {"id": "overlay-1"}
        with patch("hydralysis.hydra.identity", return_value={"client": "rusticre:1", "harness": "codex"}):
            token = jobowner.issue(record)
        jobowner.check(record)                      # the process that started it
        jobowner._TOKENS.clear()                    # another client: a new process
        with self.assertRaisesRegex(PermissionError, "belongs to rusticre:1 \\(codex\\)"):
            jobowner.check(record)
        with self.assertRaises(PermissionError):
            jobowner.check(record, "not-the-token")
        jobowner.check(record, token)

    def test_jobs_from_before_owners_stay_open_and_status_hides_the_hash(self):
        jobowner.check({"id": "old-job"})
        record = {"job_id": "prepare-1"}
        jobowner.issue(record)
        shown = jobowner.public(record)
        self.assertNotIn("token_sha256", shown["owner"])
        self.assertIn("token_sha256", record["owner"])


if __name__ == "__main__":
    unittest.main()
