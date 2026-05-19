from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch

from ps_core.models import Site, ScanSession, PolicyDocument, AIInsight, Finding, SitePreference

class PolicyAnalyzeTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.site = Site.objects.create(domain="test-analyze.com")
        self.scan = ScanSession.objects.create(
            site=self.site,
            url="https://test-analyze.com/",
            evidence_json={
                "third_party_domains": ["tracker.com", "ads.com"],
                "headers_meta": {"is_https": True},
                "cookies_meta": [{"name": "sessionid", "secure": True, "httpOnly": True, "sameSite": "Lax"}]
            }
        )

    @patch("ps_api.views.fetch_url")
    def test_analyze_success_with_fetch(self, mock_fetch):
        # Return fake HTML for both discovery and policy fetch
        mock_fetch.side_effect = [
            "<html><a href='/privacy'>Privacy</a><a href='/terms'>Terms</a></html>", # base HTML
            "<body><p>We do not share data. We retain for 1 year.</p></body>",      # policy HTML
            "<body><p>Terms of service.</p></body>"                                 # terms HTML might be fetched if needed
        ]

        response = self.client.post("/api/policies/analyze", {"scan_id": self.scan.id}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK, msg=response.content)
        data = response.json()
        
        self.assertEqual(data["scan_id"], self.scan.id)
        self.assertEqual(data["site_domain"], "test-analyze.com")
        self.assertIn("score_total", data)
        self.assertIn("severity_label", data)
        self.assertIn("insights", data)
        self.assertEqual(data["ai_provider"], "mock")

        # Verify DB records
        self.assertTrue(PolicyDocument.objects.filter(site=self.site).exists())
        self.assertTrue(AIInsight.objects.filter(policy__site=self.site).exists())
        
        # Verify ScanSession updated
        self.scan.refresh_from_db()
        self.assertIsNotNone(self.scan.score_total)
        self.assertIsNotNone(self.scan.severity_label)

    @patch("ps_api.views.fetch_url")
    def test_analyze_fetch_fails(self, mock_fetch):
        mock_fetch.return_value = None # Fails discovery/fetch

        response = self.client.post("/api/policies/analyze", {"scan_id": self.scan.id}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.json())

    @patch("ps_api.views.fetch_url")
    def test_analyze_no_preference_default_behavior(self, mock_fetch):
        # We simulate the site returning a policy with "advertising"
        mock_fetch.side_effect = [
            "<html><a href='/privacy'>Privacy</a></html>", 
            "<body><p>We do not share data. We show advertising. We retain for 1 year.</p></body>"
        ]

        response = self.client.post("/api/policies/analyze", {"scan_id": self.scan.id}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        
        self.assertIn("preference", data)
        self.assertEqual(data["preference"]["mode"], "balanced")
        
        # We expect profiling_ads to be in reasons/recs because it's balanced
        reasons_str = " ".join(data["reasons"]).lower()
        recs_str = " ".join(data["recommendations"]).lower()
        
        self.assertIn("profiling ads", reasons_str)
        self.assertIn("advertising", recs_str)

    @patch("ps_api.views.fetch_url")
    def test_analyze_custom_preference_disables_ads_profiling(self, mock_fetch):
        # Create a custom SitePreference disabling warn_ads_profiling
        SitePreference.objects.create(
            site=self.site,
            mode="custom",
            settings_json={"warn_ads_profiling": False, "warn_trackers": True, "warn_retention_unclear": True, "warn_cookie_flags": True}
        )
        
        # Returning same HTML with advertising mentions
        mock_fetch.side_effect = [
            "<html><a href='/privacy'>Privacy</a></html>", 
            "<body><p>We do not share data. We show advertising. We retain for 1 year.</p></body>"
        ]

        response = self.client.post("/api/policies/analyze", {"scan_id": self.scan.id}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        
        self.assertEqual(data["preference"]["mode"], "custom")
        self.assertFalse(data["preference"]["settings"]["warn_ads_profiling"])

        # We expect profiling_ads to be EXCLUDED from reasons and recs
        reasons_str = " ".join(data["reasons"]).lower()
        recs_str = " ".join(data["recommendations"]).lower()
        
        self.assertNotIn("profiling ads", reasons_str)
        self.assertNotIn("advertising", recs_str)
        
        # Test finding generation
        # Since we excluded ads profiling, there should not be a Finding with title "Policy Flag: profiling_ads"
        self.assertFalse(
            Finding.objects.filter(scan_id=self.scan.id, title="Policy Flag: profiling_ads").exists()
        )

    @patch("ps_api.views.fetch_url")
    def test_analyze_includes_ml_payload(self, mock_fetch):
        mock_fetch.return_value = "<html><body><p>We share data. We show ads.</p></body></html>"
        data = {
            "scan_id": self.scan.id,
            "policy_url": "https://ml-test.com/privacy"
        }
        res = self.client.post("/api/policies/analyze", data, format="json")
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        
        self.assertIn("ml", res.data)
        self.assertIn("ml_enabled", res.data["ml"])
        self.assertIn("ml_summary", res.data["ml"])
        self.assertIn("ml_predictions", res.data["ml"])
        
        # Verify it was saved natively to AIInsight
        from ps_core.models import AIInsight
        insight = AIInsight.objects.last()
        self.assertIn("ml", insight.output_json)


class MLPredictTests(TestCase):
    def test_chunk_text(self):
        from ps_core.ml.predict import _chunk_text
        text = "This is a short paragraph that will be skipped because it is under 80 chars.\n\n" \
               "This is a longer valid paragraph that is over 80 characters long so it should definitely map into the chunks array perfectly.\n\n" \
               "This is a much longer paragraph that should ideally be split if it exceeds 500 characters. " * 10 + "\n\n" \
               "Last updated today.\n\n" \
               "Jump to section 2."
        chunks = _chunk_text(text)
        self.assertTrue(len(chunks) >= 2)
        # Assert boilerplate is removed
        for c in chunks:
            self.assertNotIn("last updated", c.lower())
            self.assertNotIn("jump to", c.lower())

    @patch('ps_core.ml.predict._load_model')
    def test_run_ml_predictions_filtering(self, mock_load):
        from unittest.mock import Mock
        from ps_core.ml.predict import run_ml_predictions
        mock_model = Mock()
        mock_model.classes_ = ["ads_profiling", "other", "rights", "sharing"]
        import numpy as np
        
        # We need 4 chunks to pass into predict_proba
        text = "Valid chunk one over 80 chars. " * 3 + "\n\n" + \
               "Valid chunk two over 80 chars. " * 3 + "\n\n" + \
               "Valid chunk thr over 80 chars. " * 3 + "\n\n" + \
               "Valid chunk fou over 80 chars. " * 3
               
        # Make probas
        mock_model.predict_proba.return_value = np.array([
            [0.9, 0.05, 0.05, 0.0],  # argmax=0 'ads_profiling' (0.9) -> Keep
            [0.1, 0.2, 0.34, 0.0],   # argmax=2 'rights' (0.34) -> Drop (under 0.35)
            [0.1, 0.8, 0.05, 0.05],  # argmax=1 'other' (0.8) -> Drop 'other'
            [0.1, 0.1, 0.1, 0.7],    # argmax=3 'sharing' (0.7) -> Keep
        ])
        mock_load.return_value = mock_model
        
        res = run_ml_predictions(text)
        self.assertTrue(res["ml_enabled"])
        preds = res["ml_predictions"]
        
        self.assertEqual(len(preds), 2)
        self.assertEqual(preds[0]["label"], "ads_profiling")
        self.assertEqual(preds[1]["label"], "sharing")


class ScanPersistenceTests(TestCase):
    def test_scan_persists_reasons_and_recommendations(self):
        from ps_core.models import Site, ScanSession, PolicyDocument, AIInsight
        from django.urls import reverse
        
        site = Site.objects.create(domain="persist.example.com")
        scan = ScanSession.objects.create(
            site=site,
            url="https://persist.example.com",
            evidence_json={"cookies_meta": [], "storage_meta": {}},
        )
        
        doc = PolicyDocument.objects.create(
            site=site,
            policy_url="https://persist.example.com/privacy",
            extracted_text="Some text here"
        )
        AIInsight.objects.create(
            policy=doc,
            model_name="test_model",
            output_json={
                "risk_flags": [
                    {"flag": "profiling_ads", "severity": "high", "evidence": "We track you"}
                ]
            }
        )

        analyze_url = reverse('policy-analyze')
        # trigger analyze
        resp = self.client.post(analyze_url, {
            "scan_id": scan.id,
            "policy_url": doc.policy_url
        }, format='json')
        self.assertEqual(resp.status_code, 200)

        # check detail endpoint
        detail_url = reverse('scan-detail', args=[scan.id])
        resp2 = self.client.get(detail_url)
        self.assertEqual(resp2.status_code, 200)

        data = resp2.json()
        self.assertIn("reasons", data)
        self.assertIn("recommendations", data)
        self.assertTrue(len(data["reasons"]) > 0)
        self.assertTrue(len(data["recommendations"]) > 0)

