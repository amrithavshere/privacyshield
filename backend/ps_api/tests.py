from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch, Mock

from ps_core.models import Site, ScanSession, PolicyDocument

class PolicyFetchTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.site = Site.objects.create(domain="example.com")
        self.scan = ScanSession.objects.create(
            site=self.site,
            url="https://example.com",
            severity_label="Low"
        )
        self.url = reverse("policy-fetch")

    @patch("ps_core.policy_fetch.requests.get")
    def test_policy_fetch_success(self, mock_get):
        # Mock the discovery response
        mock_response_discovery = Mock()
        mock_response_discovery.text = '''
            <html>
                <body>
                    <a href="/privacy-policy">Privacy Policy</a>
                    <a href="/tos">Terms of Service</a>
                </body>
            </html>
        '''
        mock_response_discovery.raise_for_status.return_value = None

        # Mock the policy fetch response
        mock_response_policy = Mock()
        mock_response_policy.text = '''
            <html>
                <head><style>.hidden {display:none;}</style></head>
                <body>
                    <nav>Menu</nav>
                    <h1>Privacy Policy</h1>
                    <p>We care about your privacy. We collect some data.</p>
                    <footer>Copyright 2024</footer>
                </body>
            </html>
        '''
        mock_response_policy.raise_for_status.return_value = None

        # setup side_effect to return discovery first then policy
        mock_get.side_effect = [mock_response_discovery, mock_response_policy]

        data = {
            "scan_id": self.scan.id
        }
        
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.assertEqual(response.data["scan_id"], self.scan.id)
        self.assertEqual(response.data["site_domain"], "example.com")
        self.assertEqual(response.data["policy_url"], "https://example.com/privacy-policy")
        self.assertEqual(response.data["terms_url"], "https://example.com/tos")
        self.assertTrue("We care about your privacy" in response.data["extracted_text_preview"])

        # verify DB
        doc = PolicyDocument.objects.get(site=self.site)
        self.assertEqual(doc.policy_url, "https://example.com/privacy-policy")
        self.assertTrue(doc.text_hash)
        self.assertTrue("We care about" in doc.extracted_text)
        self.assertFalse("Menu" in doc.extracted_text) # nav should be removed

    @patch("ps_core.policy_fetch.requests.get")
    def test_policy_fetch_missing_scan(self, mock_get):
        data = {"scan_id": 999}
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    @patch("ps_core.policy_fetch.requests.get")
    def test_policy_fetch_discovery_fails(self, mock_get):
        # Even if discovery fails, we added fallbacks to /privacy and /terms.
        # So we mock those fetching to fail to trigger 400
        mock_response_fail = Mock()
        import requests
        mock_response_fail.raise_for_status.side_effect = requests.RequestException("Not Found")
        mock_get.return_value = mock_response_fail
        
        data = {"scan_id": self.scan.id}
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Policy fetch failed", response.data["error"])

class SitePreferenceTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("site-preferences")

    def test_get_default_preference_when_site_missing(self):
        response = self.client.get(self.url, {"domain": "missing.com"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["domain"], "missing.com")
        self.assertEqual(response.data["mode"], "balanced")
        self.assertEqual(response.data["settings"], {})
        self.assertFalse(response.data["exists"])

    def test_post_creates_and_get_returns_preference(self):
        # Initial create
        post_data = {
            "domain": "testpref.com",
            "mode": "custom",
            "settings": {"warn_trackers": True}
        }
        res_post = self.client.post(self.url, post_data, format="json")
        self.assertEqual(res_post.status_code, status.HTTP_200_OK)
        self.assertEqual(res_post.data["mode"], "custom")
        self.assertEqual(res_post.data["settings"]["warn_trackers"], True)
        self.assertTrue(res_post.data["updated"])

        # Fetch what was created
        res_get = self.client.get(self.url, {"domain": "testpref.com"})
        self.assertEqual(res_get.status_code, status.HTTP_200_OK)
        self.assertEqual(res_get.data["domain"], "testpref.com")
        self.assertEqual(res_get.data["mode"], "custom")
        self.assertEqual(res_get.data["settings"]["warn_trackers"], True)
        self.assertTrue(res_get.data["exists"])
        self.assertTrue(res_get.data["preference_exists"])

    def test_post_clears_settings_when_not_custom(self):
        post_data = {
            "domain": "strictmode.com",
            "mode": "strict",
            "settings": {"warn_trackers": True}
        }
        res_post = self.client.post(self.url, post_data, format="json")
        self.assertEqual(res_post.status_code, status.HTTP_200_OK)
        self.assertEqual(res_post.data["mode"], "strict")
        self.assertEqual(res_post.data["settings"], {})


class ScanDetailTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.site = Site.objects.create(domain="detail-test.com")
        self.scan = ScanSession.objects.create(
            site=self.site,
            url="https://detail-test.com",
            severity_label="Medium"
        )
        self.url = f"/api/scans/{self.scan.id}"

    def test_scan_detail_with_insights(self):
        from ps_core.models import AIInsight
        policy = PolicyDocument.objects.create(
            site=self.site,
            policy_url="https://detail-test.com/privacy"
        )
        insight_json = {"clause_categories": [{"category": "sharing", "risk": "medium", "text": "We share."}]}
        AIInsight.objects.create(
            policy=policy,
            model_name="mock",
            output_json=insight_json
        )

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["insights"], insight_json)
        self.assertEqual(response.data["policy_url"], "https://detail-test.com/privacy")
        self.assertEqual(response.data["ai_provider"], "mock")

    def test_scan_detail_without_insights(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data.get("insights"))
        self.assertIsNone(response.data.get("policy_url"))
        self.assertIsNone(response.data.get("ai_provider"))
class SitePreferenceImpactTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.site = Site.objects.create(domain="impact-test.com")
        self.scan = ScanSession.objects.create(
            site=self.site,
            url="https://impact-test.com",
            evidence_json={
                "third_party_domains": ["a.com", "b.com", "c.com", "d.com", "e.com", "f.com", "g.com"], # > 6
                "cookies_meta": [{"name": "sid", "secure": False, "httpOnly": False}],
                "consent_meta": {"banner_detected": True, "reject_available": False},
                "headers_meta": {"is_https": True}
            }
        )
        self.policy = PolicyDocument.objects.create(
            site=self.site,
            policy_url="https://impact-test.com/privacy",
            extracted_text="Some policy text about tracking for ads and keeping data forever."
        )
        # Mock AI Insights
        self.insights = {
            "policy_summary": {
                "data_collected": "Everything",
                "purposes": "Ads",
                "sharing": "Everyone",
                "retention": "unknown",
                "user_rights": False,
                "security_measures": "None"
            },
            "risk_flags": [
                {"flag": "profiling_ads", "severity": "high", "evidence": "We track you for ads."},
                {"flag": "retention_unclear", "severity": "medium", "evidence": "We keep data forever."}
            ],
            "clause_categories": [
                {"category": "collection", "risk": "high", "text": "We collect everything."},
                {"category": "sharing", "risk": "medium", "text": "We share some."}
            ]
        }
        self.analyze_url = reverse("policy-analyze")
        self.detail_url = reverse("scan-detail", kwargs={"pk": self.scan.id})

    def test_strict_mode_impact(self):
        from ps_core.models import SitePreference
        SitePreference.objects.create(site=self.site, mode="strict")
        
        with patch("ps_core.ai.providers.MockAIProvider.analyze_policy", return_value=self.insights):
            with patch("ps_core.ml.predict.run_ml_predictions", return_value=[]):
                response = self.client.post(self.analyze_url, {"scan_id": self.scan.id}, format="json")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify strict recommendation
        self.assertIn("Avoid entering sensitive information on this site.", response.data["recommendations"])
        self.assertIn("Use tracker blocking / private browsing for safer usage.", response.data["recommendations"])
        
        # Verify all reasons present (high flags + med flags + retention + trackers + cookies)
        self.assertTrue(any("ads" in r for r in response.data["reasons"]))
        self.assertTrue(any("retention" in r for r in response.data["reasons"]))
        
        # Verify penalty in score (should have +3 for strict consent)
        self.assertEqual(response.data["preference"]["mode"], "strict")

    def test_custom_mode_all_off_impact(self):
        from ps_core.models import SitePreference
        SitePreference.objects.create(
            site=self.site, 
            mode="custom", 
            settings_json={
                "warn_trackers": False,
                "warn_ads_profiling": False,
                "warn_retention_unclear": False,
                "warn_cookie_flags": False
            }
        )
        
        with patch("ps_core.ai.providers.MockAIProvider.analyze_policy", return_value=self.insights):
            with patch("ps_core.ml.predict.run_ml_predictions", return_value=[]):
                response = self.client.post(self.analyze_url, {"scan_id": self.scan.id}, format="json")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify generic fallback
        self.assertEqual(response.data["reasons"], ["Analysis completed with your saved preferences."])
        self.assertEqual(response.data["recommendations"], ["Review privacy settings if you want more detailed warnings."])

    def test_balanced_mode_baseline(self):
        # Default is balanced
        with patch("ps_core.ai.providers.MockAIProvider.analyze_policy", return_value=self.insights):
            with patch("ps_core.ml.predict.run_ml_predictions", return_value=[]):
                response = self.client.post(self.analyze_url, {"scan_id": self.scan.id}, format="json")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Should have reasons and recs but NO strict-only text
        self.assertNotIn("Avoid entering sensitive information on this site.", response.data["recommendations"])
        self.assertTrue(len(response.data["reasons"]) > 1)

    def test_delete_scan_success(self):
        from ps_core.models import Finding
        Finding.objects.create(scan=self.scan, type="tracker", severity="medium", title="Test Finding")
        
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(ScanSession.objects.filter(id=self.scan.id).exists())
        self.assertEqual(Finding.objects.filter(scan_id=self.scan.id).count(), 0)

    def test_delete_scan_leaves_policy(self):
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertTrue(PolicyDocument.objects.filter(id=self.policy.id).exists())
