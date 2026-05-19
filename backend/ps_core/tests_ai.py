from django.test import TestCase
import os
from unittest.mock import patch
from ps_core.ai.providers import MockAIProvider, get_ai_provider, OpenAIProvider
from ps_core.ai.schema import validate_ai_output, ensure_valid_ai_output

class AILayerTests(TestCase):
    def test_mock_provider_schema(self):
        provider = MockAIProvider()
        output = provider.analyze_policy("We love advertising and profiling users.")
        
        # Will inherently pass schema since MockAIProvider calls ensure_valid_ai_output, 
        # but let's double check validate_ai_output directly.
        is_valid, err = validate_ai_output(output)
        self.assertTrue(is_valid)
        self.assertEqual(err, "")
        
        # Verify rules triggered
        flags = [f["flag"] for f in output["risk_flags"]]
        self.assertIn("profiling_ads", flags)
        
    def test_mock_provider_all_keywords(self):
        provider = MockAIProvider()
        text = "advertising third party share retain children minor duration"
        output = provider.analyze_policy(text)
        
        flags = [f["flag"] for f in output["risk_flags"]]
        self.assertIn("profiling_ads", flags)
        self.assertIn("third_party_sharing", flags)
        self.assertIn("sensitive_data", flags)
        # retention_unclear shouldn't trigger because "duration" is present
        self.assertNotIn("retention_unclear", flags)

    @patch.dict(os.environ, {"PRIVACYSHIELD_AI_PROVIDER": "openai", "OPENAI_API_KEY": ""}, clear=True)
    def test_get_ai_provider_fallback(self):
        # Even if asked for openai, missing key means we get mock
        provider = get_ai_provider()
        self.assertIsInstance(provider, MockAIProvider)
        
    @patch.dict(os.environ, {"PRIVACYSHIELD_AI_PROVIDER": "openai", "OPENAI_API_KEY": "test-key"}, clear=True)
    def test_get_ai_provider_openai(self):
        # With key, we get OpenAI
        provider = get_ai_provider()
        self.assertIsInstance(provider, OpenAIProvider)
        
    def test_schema_validator_catches_invalid(self):
        bad_data = {
            "policy_summary": {
                "data_collected": ["emails"],
                "purposes": ["spam"],
                "sharing": [],
                "retention": 12, # Invalid, must be string
                "user_rights": [],
                "security_measures": []
            },
            "risk_flags": [],
            "clause_categories": []
        }
        
        with self.assertRaises(ValueError) as context:
            ensure_valid_ai_output(bad_data)
        
        self.assertIn("retention must be a string", str(context.exception))
        
        bad_data_2 = {
            "policy_summary": {
                "data_collected": [], "purposes": [], "sharing": [],
                "retention": "unknown", "user_rights": [], "security_measures": []
            },
            "risk_flags": [{"flag": "fake_flag", "severity": "low", "evidence": "test"}],
            "clause_categories": []
        }
        
        with self.assertRaises(ValueError) as context:
            ensure_valid_ai_output(bad_data_2)
            
        self.assertIn("invalid flag: fake_flag", str(context.exception))
