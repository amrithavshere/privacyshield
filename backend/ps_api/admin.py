from django.contrib import admin
from ps_core.models import Site, ScanSession, PolicyDocument, AIInsight, Finding, Report, SitePreference

admin.site.register(Site)
admin.site.register(ScanSession)
admin.site.register(PolicyDocument)
admin.site.register(AIInsight)
admin.site.register(Finding)
admin.site.register(Report)
admin.site.register(SitePreference)