from rest_framework import serializers
from ps_core.models import ScanSession, PolicyDocument


class ScanSessionSerializer(serializers.ModelSerializer):
    domain = serializers.CharField(source="site.domain", read_only=True)

    class Meta:
        model = ScanSession
        fields = [
            "id",
            "domain",
            "url",
            "created_at",
            "evidence_json",
            "score_total",
            "score_breakdown_json",
            "severity_label",
        ]


class ScanSessionDetailSerializer(ScanSessionSerializer):
    insights = serializers.SerializerMethodField()
    policy_url = serializers.SerializerMethodField()
    terms_url = serializers.SerializerMethodField()
    ai_provider = serializers.SerializerMethodField()
    reasons = serializers.JSONField(source="reasons_json", required=False)
    recommendations = serializers.JSONField(source="recommendations_json", required=False)

    class Meta(ScanSessionSerializer.Meta):
        fields = ScanSessionSerializer.Meta.fields + [
            "insights", "policy_url", "terms_url", "ai_provider",
            "reasons", "recommendations"
        ]

    def _get_latest_policy_insight(self, obj):
        if not hasattr(obj, '_latest_pi_data'):
            policy = obj.site.policies.order_by("-fetched_at").first()
            if policy:
                insight = policy.insights.order_by("-created_at").first()
                obj._latest_pi_data = (policy, insight)
            else:
                obj._latest_pi_data = (None, None)
        return obj._latest_pi_data

    def get_insights(self, obj):
        _, insight = self._get_latest_policy_insight(obj)
        return insight.output_json if insight else None

    def get_policy_url(self, obj):
        policy, _ = self._get_latest_policy_insight(obj)
        return policy.policy_url if policy else None

    def get_terms_url(self, obj):
        policy, _ = self._get_latest_policy_insight(obj)
        return policy.terms_url if policy else None

    def get_ai_provider(self, obj):
        _, insight = self._get_latest_policy_insight(obj)
        return insight.model_name if insight else None


class ScanIngestSerializer(serializers.Serializer):
    domain = serializers.CharField()
    url = serializers.CharField(required=False, allow_blank=True)
    evidence = serializers.JSONField()


class PolicyFetchRequestSerializer(serializers.Serializer):
    scan_id = serializers.IntegerField()
    policy_url = serializers.URLField(required=False, allow_blank=True)
    terms_url = serializers.URLField(required=False, allow_blank=True)


class PolicyFetchResponseSerializer(serializers.ModelSerializer):
    site_domain = serializers.CharField(source="site.domain", read_only=True)
    extracted_text_preview = serializers.SerializerMethodField()
    scan_id = serializers.SerializerMethodField()

    class Meta:
        model = PolicyDocument
        fields = [
            "scan_id",
            "site_domain",
            "policy_url",
            "terms_url",
            "fetched_at",
            "text_hash",
            "extracted_text_preview"
        ]

    def get_extracted_text_preview(self, obj):
        text = obj.extracted_text or ""
        return text[:200] + ("..." if len(text) > 200 else "")

    def get_scan_id(self, obj):
        # We process this based on context provided in view
        request = self.context.get('request')
        scan_id = request.data.get('scan_id') if request else None
        return scan_id


class PolicyAnalyzeRequestSerializer(serializers.Serializer):
    scan_id = serializers.IntegerField()
    policy_url = serializers.URLField(required=False, allow_blank=True)
    terms_url = serializers.URLField(required=False, allow_blank=True)


class PolicyAnalyzeResponseSerializer(serializers.Serializer):
    scan_id = serializers.IntegerField()
    site_domain = serializers.CharField()
    policy_url = serializers.URLField(allow_blank=True, required=False)
    terms_url = serializers.URLField(allow_blank=True, required=False)
    ai_provider = serializers.CharField()
    insights = serializers.JSONField()
    score_total = serializers.IntegerField()
    score_breakdown = serializers.JSONField()
    severity_label = serializers.CharField()
    reasons = serializers.ListField(child=serializers.CharField())
    recommendations = serializers.ListField(child=serializers.CharField())
    preference = serializers.JSONField(required=False)
    ml = serializers.JSONField(required=False)

class SitePreferenceGetSerializer(serializers.Serializer):
    domain = serializers.CharField()
    mode = serializers.ChoiceField(choices=['strict', 'balanced', 'custom'], default='balanced')
    settings = serializers.JSONField(default=dict)
    exists = serializers.BooleanField(default=False)
    preference_exists = serializers.BooleanField(default=False)

class SitePreferencePostSerializer(serializers.Serializer):
    domain = serializers.CharField()
    mode = serializers.ChoiceField(choices=['strict', 'balanced', 'custom'])
    settings = serializers.JSONField(required=False, default=dict)