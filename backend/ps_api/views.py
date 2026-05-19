from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, RetrieveDestroyAPIView

from ps_core.models import Site, ScanSession, PolicyDocument, AIInsight, Finding, SitePreference
from ps_core.policy_fetch import discover_policy_urls, fetch_url, html_to_text, sha256_text
from ps_core.ai.providers import get_ai_provider
from ps_core.ai.schema import ensure_valid_ai_output
from ps_core.scoring import calculate_score, build_reasons, build_recommendations

from .serializers import (
    ScanIngestSerializer, 
    ScanSessionSerializer,
    ScanSessionDetailSerializer,
    PolicyFetchRequestSerializer,
    PolicyFetchResponseSerializer,
    PolicyAnalyzeRequestSerializer,
    PolicyAnalyzeResponseSerializer,
    SitePreferencePostSerializer
)

class PolicyAnalyzeView(APIView):
    def post(self, request):
        ser = PolicyAnalyzeRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        scan_id = ser.validated_data["scan_id"]
        policy_url = ser.validated_data.get("policy_url")
        terms_url = ser.validated_data.get("terms_url")

        try:
            scan = ScanSession.objects.select_related('site').get(id=scan_id)
        except ScanSession.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

        site = scan.site
        base_url = scan.url or f"https://{site.domain}"

        # 1. Ensure PolicyDocument exists, otherwise fetch
        policy_doc = PolicyDocument.objects.filter(site=site).order_by("-fetched_at").first()
        
        # We need policy text. If missing or urls explicitly provided differ significantly, we fetch again
        if not policy_doc or not policy_doc.extracted_text or (policy_url and policy_url != policy_doc.policy_url):
            # Same logic as fetch endpoint
            if not policy_url or not terms_url:
                base_html = fetch_url(base_url)
                disc_policy, disc_terms = discover_policy_urls(base_url, base_html)
                if not policy_url: policy_url = disc_policy
                if not terms_url: terms_url = disc_terms

            if not policy_url:
                return Response({"error": "Policy URL not found"}, status=status.HTTP_400_BAD_REQUEST)

            policy_html = fetch_url(policy_url)
            if not policy_html:
                return Response({"error": "Policy fetch failed"}, status=status.HTTP_400_BAD_REQUEST)

            extracted_text = html_to_text(policy_html)
            if not extracted_text:
                return Response({"error": "Policy text extraction failed"}, status=status.HTTP_400_BAD_REQUEST)

            text_hash = sha256_text(extracted_text)

            policy_doc, _ = PolicyDocument.objects.update_or_create(
                site=site,
                defaults={
                    "policy_url": policy_url,
                    "terms_url": terms_url or "",
                    "fetched_at": timezone.now(),
                    "text_hash": text_hash,
                    "extracted_text": extracted_text,
                    "raw_html": policy_html
                }
            )

        # 2. Run AI
        provider = get_ai_provider()
        provider_name = provider.__class__.__name__.replace("AIProvider", "").lower()

        try:
            insights = provider.analyze_policy(policy_doc.extracted_text)
            ensure_valid_ai_output(insights)
        except Exception as e:
            return Response({"error": f"AI analysis failed or invalid schema: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Run ML predictions
        from ps_core.ml.predict import run_ml_predictions
        ml_result = run_ml_predictions(policy_doc.extracted_text)
        insights["ml"] = ml_result

        # Save AIInsight
        AIInsight.objects.create(
            policy=policy_doc,
            model_name=provider_name,
            output_json=insights
        )

        # 3. Compute score and recommendations
        try:
            pref_obj = SitePreference.objects.get(site=site)
            pref_dict = {
                "mode": pref_obj.mode,
                "settings": pref_obj.settings_json or {},
                "exists": True
            }
        except SitePreference.DoesNotExist:
            pref_dict = {
                "mode": "balanced",
                "settings": {},
                "exists": False
            }

        evidence = scan.evidence_json or {}
        score_data = calculate_score(insights, evidence, pref_dict)
            
        reasons = build_reasons(insights, evidence, score_data["score_breakdown"], pref_dict)
        recs = build_recommendations(insights, evidence, pref_dict, score_data["severity_label"])

        # Update ScanSession
        scan.score_total = score_data["score_total"]
        scan.score_breakdown_json = score_data["score_breakdown"]
        scan.severity_label = score_data["severity_label"]
        scan.reasons_json = reasons
        scan.recommendations_json = recs
        scan.save(update_fields=["score_total", "score_breakdown_json", "severity_label", "reasons_json", "recommendations_json"])

        # 4. Create Findings
        # Clear old findings for this scan if re-running
        scan.findings.all().delete()
        
        findings_to_create = []
        mode = pref_dict["mode"]
        settings = pref_dict["settings"]
        
        for flag in insights.get("risk_flags", []):
            f_type = flag.get('flag')
            if mode == "custom":
                if f_type == "profiling_ads" and not settings.get("warn_ads_profiling", True):
                    continue
                if f_type == "retention_unclear" and not settings.get("warn_retention_unclear", True):
                    continue
            # mode == "strict" or "balanced" shows all
                    
            findings_to_create.append(Finding(
                scan=scan,
                type="policy",
                severity=flag.get("severity", "low"),
                title=f"Policy Flag: {flag.get('flag')}",
                evidence_json={"quote": flag.get("evidence", "")}
            ))

        tpd = evidence.get("third_party_domains", [])
        if len(tpd) > 6:
            if mode != "custom" or settings.get("warn_trackers", True):
                findings_to_create.append(Finding(
                    scan=scan,
                    type="tracker",
                    severity="high" if len(tpd) > 12 else "medium",
                    title="Excessive Third-Party Trackers",
                    evidence_json={"count": len(tpd), "domains": tpd[:5]}
                ))

        if not evidence.get("headers_meta", {}).get("is_https", True):
            # HTTPS warning always shown? User said "Strict forces all warning categories ON regardless of settings_json".
            # Balanced usually shows the baseline.
            findings_to_create.append(Finding(
                scan=scan,
                type="session",
                severity="high",
                title="Insecure Connection",
                evidence_json={"is_https": False}
            ))
        elif mode != "custom" or settings.get("warn_cookie_flags", True):
            # Add cookie warnings if any
            cookies = evidence.get("cookies_meta", [])
            non_secure = sum(1 for c in cookies if not c.get("secure", False))
            if non_secure > 0:
                 findings_to_create.append(Finding(
                    scan=scan,
                    type="cookie",
                    severity="medium",
                    title=f"{non_secure} Insecure Cookies Detected",
                    evidence_json={"count": non_secure}
                ))
            
        Finding.objects.bulk_create(findings_to_create)

        # 5. Build response
        resp_data = {
            "scan_id": scan.id,
            "site_domain": site.domain,
            "policy_url": policy_doc.policy_url,
            "terms_url": policy_doc.terms_url,
            "ai_provider": provider_name,
            "insights": insights,
            "score_total": scan.score_total,
            "score_breakdown": scan.score_breakdown_json,
            "severity_label": scan.severity_label,
            "reasons": reasons,
            "recommendations": recs,
            "preference": pref_dict,
            "ml": ml_result
        }

        resp_ser = PolicyAnalyzeResponseSerializer(resp_data)
        return Response(resp_ser.data, status=status.HTTP_200_OK)


class ScanIngestView(APIView):
    def post(self, request):
        ser = ScanIngestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        domain = ser.validated_data["domain"].strip().lower()
        url = ser.validated_data.get("url", "")
        evidence = ser.validated_data["evidence"]

        site, _ = Site.objects.get_or_create(domain=domain)
        site.last_seen_at = timezone.now()
        site.save(update_fields=["last_seen_at"])

        scan = ScanSession.objects.create(
            site=site,
            url=url,
            evidence_json=evidence,
            score_total=0,
            score_breakdown_json={},
            severity_label="Low",
        )

        return Response({"scan_id": scan.id}, status=status.HTTP_201_CREATED)


class ScanListView(ListAPIView):
    queryset = ScanSession.objects.select_related("site").order_by("-created_at")
    serializer_class = ScanSessionSerializer


class ScanDetailView(RetrieveDestroyAPIView):
    queryset = ScanSession.objects.select_related("site")
    serializer_class = ScanSessionDetailSerializer


class PolicyFetchView(APIView):
    def post(self, request):
        ser = PolicyFetchRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        scan_id = ser.validated_data["scan_id"]
        policy_url = ser.validated_data.get("policy_url")
        terms_url = ser.validated_data.get("terms_url")

        try:
            scan = ScanSession.objects.select_related('site').get(id=scan_id)
        except ScanSession.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

        site = scan.site
        base_url = scan.url or f"https://{site.domain}"

        # 1. Discovery if urls not fully provided
        if not policy_url or not terms_url:
            # fetch base_url
            base_html = fetch_url(base_url)
            disc_policy_url, disc_terms_url = discover_policy_urls(base_url, base_html)
            
            if not policy_url:
                policy_url = disc_policy_url
            if not terms_url:
                terms_url = disc_terms_url

        if not policy_url:
            return Response({"error": "Policy URL not found"}, status=status.HTTP_400_BAD_REQUEST)

        # 2. Fetch and clean policy url
        policy_html = fetch_url(policy_url)
        if not policy_html:
            return Response({"error": "Policy fetch failed"}, status=status.HTTP_400_BAD_REQUEST)

        extracted_text = html_to_text(policy_html)
        if not extracted_text:
            return Response({"error": "Policy text extraction failed"}, status=status.HTTP_400_BAD_REQUEST)

        text_hash = sha256_text(extracted_text)

        # Save PolicyDocument
        policy_doc, _ = PolicyDocument.objects.update_or_create(
            site=site,
            defaults={
                "policy_url": policy_url,
                "terms_url": terms_url or "",
                "fetched_at": timezone.now(),
                "text_hash": text_hash,
                "extracted_text": extracted_text,
                "raw_html": policy_html  # Save raw HTML as requested
            }
        )

        resp_ser = PolicyFetchResponseSerializer(policy_doc, context={'request': request})
        return Response(resp_ser.data, status=status.HTTP_200_OK)


class SitePreferenceView(APIView):
    def get(self, request):
        domain = request.query_params.get('domain')
        if not domain:
            return Response({"error": "domain query parameter is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        domain = domain.strip().lower()
        
        try:
            site = Site.objects.get(domain=domain)
            if hasattr(site, 'preference'):
                pref = site.preference
                data = {
                    "domain": domain,
                    "mode": pref.mode,
                    "settings": pref.settings_json,
                    "exists": True,
                    "preference_exists": True
                }
            else:
                data = {
                    "domain": domain,
                    "mode": "balanced",
                    "settings": {},
                    "exists": True,
                    "preference_exists": False
                }
        except Site.DoesNotExist:
            data = {
                "domain": domain,
                "mode": "balanced",
                "settings": {},
                "exists": False,
                "preference_exists": False
            }
            
        return Response(data, status=status.HTTP_200_OK)

    def post(self, request):
        ser = SitePreferencePostSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        
        domain = ser.validated_data["domain"].strip().lower()
        mode = ser.validated_data["mode"]
        settings = ser.validated_data.get("settings", {})
        
        if mode != 'custom':
            settings = {}
            
        site, created = Site.objects.get_or_create(domain=domain)
        if created:
             site.last_seen_at = timezone.now()
             site.save(update_fields=["last_seen_at"])

        pref, _ = SitePreference.objects.update_or_create(
            site=site,
            defaults={
                "mode": mode,
                "settings_json": settings
            }
        )
        
        resp_data = {
            "domain": domain,
            "mode": pref.mode,
            "settings": pref.settings_json,
            "updated": True
        }
        return Response(resp_data, status=status.HTTP_200_OK)