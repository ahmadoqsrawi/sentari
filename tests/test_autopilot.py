# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari.ai.providers import LLMProvider
from sentari.autopilot import _decide, _PHASE_ORDER


class _Stub(LLMProvider):
    name = "stub"

    def __init__(self, reply, usable=True):
        super().__init__(model="stub")
        self._reply = reply
        self._usable = usable

    def available(self):
        return (self._usable, "" if self._usable else "no key")

    def complete(self, system, user, max_tokens=1500):
        return self._reply


class TestAutopilotDecide(unittest.TestCase):
    def test_valid_action_from_llm(self):
        action, source, _ = _decide(_Stub('{"action":"recon","reason":"x"}'), True, [], [])
        self.assertEqual(action, "recon")
        self.assertEqual(source, "llm")

    def test_invalid_action_falls_back(self):
        action, source, _ = _decide(_Stub('{"action":"rm -rf /","reason":"x"}'), True, [], [])
        self.assertEqual(source, "fallback")
        self.assertIn(action, _PHASE_ORDER)   # a real phase, never the model's string

    def test_already_run_action_falls_back(self):
        done = ["recon"]
        action, source, _ = _decide(_Stub('{"action":"recon"}'), True, [], done)
        self.assertEqual(source, "fallback")
        self.assertNotEqual(action, None)
        self.assertNotIn(action, done)

    def test_unusable_provider_uses_order(self):
        action, source, _ = _decide(_Stub("", usable=False), False, [], [])
        self.assertEqual(source, "fallback")
        self.assertEqual(action, _PHASE_ORDER[0])

    def test_unparseable_reply_falls_back(self):
        action, source, _ = _decide(_Stub("not json"), True, [], [])
        self.assertEqual(source, "fallback")
        self.assertIn(action, _PHASE_ORDER)


if __name__ == "__main__":
    unittest.main()
