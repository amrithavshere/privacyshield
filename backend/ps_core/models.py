from django.db import models

class Site(models.Model):
    domain = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.domain

class ScanSession(models.Model):
    SEVERITY_CHOICES = (
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
    )

    site = models.ForeignKey(Site, on_delete=models.CASCADE, related_name='scans')
    url = models.URLField(max_length=2000)
    created_at = models.DateTimeField(auto_now_add=True)
    evidence_json = models.JSONField(default=dict, blank=True)
    score_total = models.IntegerField(default=0)
    score_breakdown_json = models.JSONField(default=dict, blank=True)
    severity_label = models.CharField(max_length=20, choices=SEVERITY_CHOICES, blank=True)
    reasons_json = models.JSONField(default=list, blank=True)
    recommendations_json = models.JSONField(default=list, blank=True)

    def __str__(self):
        return f"{self.site.domain} - {self.created_at}"

class PolicyDocument(models.Model):
    site = models.ForeignKey(Site, on_delete=models.CASCADE, related_name='policies')
    policy_url = models.URLField(max_length=2000)
    terms_url = models.URLField(max_length=2000, blank=True, null=True)
    fetched_at = models.DateTimeField(auto_now_add=True)
    text_hash = models.CharField(max_length=255, blank=True)
    extracted_text = models.TextField(blank=True, null=True)
    raw_html = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Policy for {self.site.domain}"

class AIInsight(models.Model):
    policy = models.ForeignKey(PolicyDocument, on_delete=models.CASCADE, related_name='insights')
    model_name = models.CharField(max_length=100)
    output_json = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Insight for {self.policy.site.domain}"

class Finding(models.Model):
    TYPE_CHOICES = (
        ('policy', 'Policy'),
        ('tracker', 'Tracker'),
        ('cookie', 'Cookie'),
        ('consent', 'Consent'),
        ('session', 'Session'),
    )
    SEVERITY_CHOICES = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    )

    scan = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='findings')
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    title = models.CharField(max_length=255)
    evidence_json = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"{self.type} - {self.title}"

class Report(models.Model):
    scan = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='reports')
    generated_at = models.DateTimeField(auto_now_add=True)
    file_path = models.CharField(max_length=1024)

    def __str__(self):
        return f"Report for {self.scan.id}"


class SitePreference(models.Model):
    MODE_CHOICES = (
        ('strict', 'Strict'),
        ('balanced', 'Balanced'),
        ('custom', 'Custom'),
    )
    site = models.OneToOneField(Site, on_delete=models.CASCADE, related_name='preference')
    mode = models.CharField(max_length=20, choices=MODE_CHOICES, default='balanced')
    settings_json = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Preferences for {self.site.domain}"
