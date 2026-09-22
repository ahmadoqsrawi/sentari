import unittest

from sentari.ai.catalog import list_models
from sentari.ai.providers import OpenAICompatProvider, get_provider, list_providers
from sentari.agent.schema import OPENAI_TOOLS


class TestProviders(unittest.TestCase):
    def test_many_companies_registered(self):
        names = set(list_providers())
        for expected in ["openai", "anthropic", "google", "deepseek", "mistral",
                         "groq", "xai", "together", "fireworks", "perplexity",
                         "glm", "nvidia", "openrouter", "ollama"]:
            self.assertIn(expected, names)

    def test_compat_provider_has_base_and_name(self):
        p = get_provider("deepseek")
        self.assertIsInstance(p, OpenAICompatProvider)
        self.assertEqual(p.name, "deepseek")
        self.assertEqual(p.base_url, "https://api.deepseek.com")
        self.assertTrue(p.supports_tools())

    def test_unknown_name_is_openai_compatible(self):
        p = get_provider("acme-llm", base_url="https://api.acme.test/v1")
        self.assertIsInstance(p, OpenAICompatProvider)
        self.assertEqual(p.base_url, "https://api.acme.test/v1")

    def test_catalog_covers_new_providers(self):
        m = list_models()
        for prov in ["deepseek", "groq", "xai", "mistral", "perplexity", "nvidia"]:
            self.assertIn(prov, m)
            self.assertTrue(m[prov])


class TestToolSchema(unittest.TestCase):
    def test_tools_well_formed(self):
        names = {t["function"]["name"] for t in OPENAI_TOOLS}
        self.assertIn("record_finding", names)
        self.assertIn("finish", names)
        rf = [t for t in OPENAI_TOOLS if t["function"]["name"] == "record_finding"][0]
        self.assertIn("evidence_id", rf["function"]["parameters"]["required"])


if __name__ == "__main__":
    unittest.main()
