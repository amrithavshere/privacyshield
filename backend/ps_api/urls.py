from django.urls import path
from .views import ScanIngestView, ScanListView, ScanDetailView, PolicyFetchView, PolicyAnalyzeView, SitePreferenceView

urlpatterns = [
    path("scans/ingest", ScanIngestView.as_view(), name="scan-ingest"),
    path("scans", ScanListView.as_view(), name="scan-list"),
    path("scans/<int:pk>", ScanDetailView.as_view(), name="scan-detail"),
    path("policies/fetch", PolicyFetchView.as_view(), name="policy-fetch"),
    path("policies/analyze", PolicyAnalyzeView.as_view(), name="policy-analyze"),
    path("preferences", SitePreferenceView.as_view(), name="site-preferences"),
]