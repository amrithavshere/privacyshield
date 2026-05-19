def calculate_score(insights: dict, evidence: dict, preference: dict = None) -> dict:
    """
    Computes policy_risk, evidence_risk, consent_session_risk, score_total and severity_label.
    Total max 100 points, higher = more risk.
    """
    policy_risk = 0
    pref = preference or {}
    mode = pref.get("mode", "balanced")
    
    # 1. Policy Risk (Max 50)
    flags = insights.get("risk_flags", [])
    for f in flags:
        sev = f.get("severity", "low")
        if sev == "high":
            policy_risk += 10
        elif sev == "medium":
            policy_risk += 6
        elif sev == "low":
            policy_risk += 3

    summary = insights.get("policy_summary", {})
    if summary.get("retention", "").lower() == "unknown":
        policy_risk += 5
    if not summary.get("user_rights"):
        policy_risk += 5

    policy_risk = min(policy_risk, 50)

    # 2. Evidence Risk (Max 30)
    evidence_risk = 0
    tpd = evidence.get("third_party_domains", [])
    tpd_count = len(tpd)
    if tpd_count <= 2:
        evidence_risk += 3
    elif tpd_count <= 6:
        evidence_risk += 10
    elif tpd_count <= 12:
        evidence_risk += 18
    else:
        evidence_risk += 25

    # Check cookies
    cookies = evidence.get("cookies_meta", [])
    non_secure_cookies = sum(1 for c in cookies if not c.get("secure", False))
    if non_secure_cookies > 0:
        evidence_risk += min(non_secure_cookies, 5)

    evidence_risk = min(evidence_risk, 30)

    # 3. Consent + Session Safety (Max 20)
    consent_session_risk = 0
    headers = evidence.get("headers_meta", {})
    if not headers.get("is_https", True):
        consent_session_risk += 10

    session_cookies_missing_flags = 0
    for c in cookies:
        if c.get("name", "").lower() in ["sessionid", "csrftoken", "sid"]:
            if not c.get("secure") or not c.get("httpOnly") or c.get("sameSite", "None").lower() == "none":
                session_cookies_missing_flags += 2

    consent_session_risk += min(session_cookies_missing_flags, 6)

    consent = evidence.get("consent_meta", {})
    if consent.get("banner_detected", False):
        if consent.get("reject_available") is False or (consent.get("clicks_to_reject") or 0) > 1:
            consent_session_risk += 4
        # Strict mode penalizes lack of easy reject even more
        if mode == "strict" and consent.get("reject_available") is False:
            consent_session_risk += 3

    consent_session_risk = min(consent_session_risk, 20)

    total_score = policy_risk + evidence_risk + consent_session_risk
    
    # Ensure total is capped at 100 just in case
    total_score = min(total_score, 100)

    if total_score <= 30:
        severity = "Low"
    elif total_score <= 60:
        severity = "Medium"
    else:
        severity = "High"

    return {
        "score_total": total_score,
        "score_breakdown": {
            "policy_risk": policy_risk,
            "evidence_risk": evidence_risk,
            "consent_session_risk": consent_session_risk
        },
        "severity_label": severity
    }

def build_reasons(insights: dict, evidence: dict, breakdown: dict, preference: dict = None) -> list[str]:
    reasons = []
    flags = insights.get("risk_flags", [])
    
    pref = preference or {}
    mode = pref.get("mode", "balanced")
    settings = pref.get("settings", {})
    
    # Grab top 2 risk flags
    high_flags = [f["flag"] for f in flags if f.get("severity") == "high"]
    med_flags = [f["flag"] for f in flags if f.get("severity") == "medium"]

    for f in (high_flags + med_flags):
        if mode == "custom":
            if f == "profiling_ads" and not settings.get("warn_ads_profiling", True):
                continue
            if f == "retention_unclear" and not settings.get("warn_retention_unclear", True):
                continue
        # strict and balanced see everything
        reasons.append(f"Policy indicates risk related to {f.replace('_', ' ')}.")
        if len(reasons) >= 2:
            break

    summary = insights.get("policy_summary", {})
    if summary.get("retention", "").lower() == "unknown":
        if mode != "custom" or settings.get("warn_retention_unclear", True):
            reasons.append("Data retention period is unspecified or unknown.")

    tpd_count = len(evidence.get("third_party_domains", []))
    if tpd_count > 6:
        if mode != "custom" or settings.get("warn_trackers", True):
            reasons.append(f"High number of third-party domains detected ({tpd_count}).")

    if not evidence.get("headers_meta", {}).get("is_https", True):
        reasons.append("Connection is not completely secure (missing HTTPS).")

    cookies = evidence.get("cookies_meta", [])
    non_secure = sum(1 for c in cookies if not c.get("secure", False))
    if non_secure > 0:
        if mode != "custom" or settings.get("warn_cookie_flags", True):
            reasons.append(f"Found {non_secure} cookies missing the Secure flag.")
            
    reasons = reasons[:6]

    if not reasons:
        reasons = ["Analysis completed with your saved preferences."]

    return reasons

def build_recommendations(insights: dict, evidence: dict, preference: dict = None, severity: str = "Low") -> list[str]:
    recs = []
    
    pref = preference or {}
    mode = pref.get("mode", "balanced")
    settings = pref.get("settings", {})
    
    tpd_count = len(evidence.get("third_party_domains", []))
    if tpd_count > 3:
        if mode != "custom" or settings.get("warn_trackers", True):
            recs.append("Consider using a privacy-focused browser or extension to block third-party trackers.")

    cookies = evidence.get("cookies_meta", [])
    non_secure = sum(1 for c in cookies if not c.get("secure", False))
    
    if not evidence.get("headers_meta", {}).get("is_https", True):
        recs.append("Avoid entering sensitive information on this site due to weak connection security.")
    elif non_secure > 0:
        if mode != "custom" or settings.get("warn_cookie_flags", True):
            recs.append("Avoid entering sensitive information on this site due to weak connection security.")

    flags = [f["flag"] for f in insights.get("risk_flags", [])]
    if "third_party_sharing" in flags:
        if mode != "custom" or settings.get("warn_trackers", True):
            recs.append("Review the sharing section of the policy to understand who receives your data.")
    if "profiling_ads" in flags:
        if mode != "custom" or settings.get("warn_ads_profiling", True):
            recs.append("Opt out of personalized advertising if the site provides a mechanism to do so.")
    if "retention_unclear" in flags:
        if mode != "custom" or settings.get("warn_retention_unclear", True):
            recs.append("Avoid providing more data than absolutely necessary as retention limits are unknown.")

    # Strict mode additions
    if mode == "strict":
        if severity in ["Medium", "High"]:
            recs.append("Avoid entering sensitive information on this site.")
        recs.append("Use tracker blocking / private browsing for safer usage.")

    recs = recs[:8]

    if not recs:
        recs = ["Review privacy settings if you want more detailed warnings."]

    return recs
