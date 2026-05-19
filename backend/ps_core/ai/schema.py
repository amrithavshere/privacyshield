def validate_ai_output(data: dict):
    """
    Validates the AI output schema based on SPEC.md.
    Returns (True, "") if valid, (False, error_message) if invalid.
    """
    if not isinstance(data, dict):
        return False, "Output must be a dictionary."

    required_keys = {"policy_summary", "risk_flags", "clause_categories"}
    if not required_keys.issubset(data.keys()):
        missing = required_keys - set(data.keys())
        return False, f"Missing required keys: {', '.join(missing)}"

    summary = data["policy_summary"]
    if not isinstance(summary, dict):
        return False, "policy_summary must be a dictionary."

    summary_keys = {"data_collected", "purposes", "sharing", "retention", "user_rights", "security_measures"}
    if not summary_keys.issubset(summary.keys()):
        missing = summary_keys - set(summary.keys())
        return False, f"policy_summary is missing keys: {', '.join(missing)}"

    if not isinstance(summary.get("retention"), str):
        return False, "policy_summary.retention must be a string."

    valid_flags = {
        "third_party_sharing", "profiling_ads", "retention_unclear",
        "rights_unclear", "weak_security_commitments", "sensitive_data"
    }
    valid_severities = {"low", "medium", "high"}

    flags = data["risk_flags"]
    if not isinstance(flags, list):
        return False, "risk_flags must be a list."

    for i, flag in enumerate(flags):
        if not isinstance(flag, dict):
            return False, f"risk_flags[{i}] must be a dictionary."
        for k in ["flag", "severity", "evidence"]:
            if k not in flag:
                return False, f"risk_flags[{i}] missing key: {k}"
        if flag["flag"] not in valid_flags:
            return False, f"risk_flags[{i}] has invalid flag: {flag['flag']}"
        if flag["severity"] not in valid_severities:
            return False, f"risk_flags[{i}] has invalid severity: {flag['severity']}"

    valid_categories = {
        "collection", "sharing", "retention", "rights",
        "security", "ads_profiling", "children"
    }
    categories = data["clause_categories"]
    if not isinstance(categories, list):
        return False, "clause_categories must be a list."

    for i, cat in enumerate(categories):
        if not isinstance(cat, dict):
            return False, f"clause_categories[{i}] must be a dictionary."
        for k in ["category", "risk", "text"]:
            if k not in cat:
                return False, f"clause_categories[{i}] missing key: {k}"
        if cat["category"] not in valid_categories:
            return False, f"clause_categories[{i}] has invalid category: {cat['category']}"
        if cat["risk"] not in valid_severities:
            return False, f"clause_categories[{i}] has invalid risk: {cat['risk']}"

    return True, ""


def ensure_valid_ai_output(data: dict):
    """
    Raises ValueError with a helpful message on invalid schema.
    """
    is_valid, err_msg = validate_ai_output(data)
    if not is_valid:
        raise ValueError(f"AI Output Schema Error: {err_msg}")
    return data
