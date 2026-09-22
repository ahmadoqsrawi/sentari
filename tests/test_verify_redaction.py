# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari.phases.verify import _redact


class TestRedaction(unittest.TestCase):
    def test_env_values_masked(self):
        body = "DATABASE_URL=postgres://u:SECRET@db/prod\nAPI_KEY=sk-live-abc123\n"
        red = _redact(body)
        self.assertNotIn("SECRET", red)
        self.assertNotIn("sk-live-abc123", red)
        self.assertIn("DATABASE_URL=", red)
        self.assertIn("REDACTED", red)


if __name__ == "__main__":
    unittest.main()
