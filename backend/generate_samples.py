import os
import sys
import django
import json
from unittest.mock import patch

# 1. Setup paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# 2. Django setup
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.conf import settings
if "testserver" not in settings.ALLOWED_HOSTS:
    settings.ALLOWED_HOSTS.append("testserver")

from rest_framework.test import APIClient
from ps_core.models import Site, ScanSession, PolicyDocument, SitePreference
from django.urls import reverse

def generate_samples():
    client = APIClient()
    
    # Setup data
    domain = "about.gitlab.com"
    site, _ = Site.objects.get_or_create(domain=domain)
    
    # Create a ScanSession with realistic evidence
    scan = ScanSession.objects.create(
        site=site,
        url=f"https://{domain}/privacy",
        evidence_json={
            "third_party_domains": ["google-analytics.com", "doubleclick.net", "facebook.com", "twitter.com", "linkedin.com", "hotjar.com", "segment.io"],
            "cookies_meta": [
                {"name": "_ga", "secure": False, "httpOnly": False},
                {"name": "session", "secure": True, "httpOnly": True}
            ],
            "consent_meta": {"banner_detected": True, "reject_available": False},
            "headers_meta": {"is_https": True}
        }
    )
    
    # Create a PolicyDocument with some text
    PolicyDocument.objects.update_or_create(
        site=site,
        defaults={
            "policy_url": f"https://{domain}/privacy",
            "extracted_text": "This is a sample privacy policy text that mentions we use cookies for advertising and track users across sites for profiling purposes. We keep data for an unspecified period."
        }
    )
    
    # Mock AI Insights for consistency
    mock_insights = {
        "policy_summary": {
            "data_collected": "Usage data, cookies, IP addresses",
            "purposes": "Analytics, advertising, profiling",
            "sharing": "Third party partners",
            "retention": "unknown",
            "user_rights": False,
            "security_measures": "Standard encryption"
        },
        "risk_flags": [
            {"flag": "profiling_ads", "severity": "high", "evidence": "used for advertising and profiling"},
            {"flag": "retention_unclear", "severity": "medium", "evidence": "unspecified period"}
        ],
        "clause_categories": [
            {"category": "ads_profiling", "risk": "high", "text": "cookies for advertising"},
            {"category": "retention", "risk": "medium", "text": "unspecified period"}
        ]
    }
    
    analyze_url = reverse("policy-analyze")
    
    modes = [
        ("BALANCED", "balanced", {}),
        ("STRICT", "strict", {}),
        ("CUSTOM ALL-OFF", "custom", {
            "warn_trackers": False,
            "warn_ads_profiling": False,
            "warn_retention_unclear": False,
            "warn_cookie_flags": False
        })
    ]
    
    print("=" * 60)
    print("SITE PREFERENCE MODE SAMPLES")
    print("=" * 60 + "\n")

    for label, mode, settings_json in modes:
        # Update preference
        SitePreference.objects.update_or_create(
            site=site,
            defaults={"mode": mode, "settings_json": settings_json}
        )
        
        # Trigger analyze via API
        with patch("ps_core.ai.providers.MockAIProvider.analyze_policy", return_value=mock_insights):
            with patch("ps_core.ml.predict.run_ml_predictions", return_value=[]):
                response = client.post(analyze_url, {"scan_id": scan.id}, format="json")
        
        print(f"--- {label} ---")
        print(f"HTTP Status: {response.status_code}")
        if response.status_code == 200:
            data = response.data
            print(f"Score Total: {data['score_total']} ({data['severity_label']})")
            print(f"Preference:  {json.dumps(data['preference'], indent=2)}")
            print(f"Reasons:      {data['reasons']}")
            print(f"Recommendations: {data['recommendations']}")
        else:
            print(f"Error: {response.data}")
        print("\n")

if __name__ == "__main__":
    generate_samples()
