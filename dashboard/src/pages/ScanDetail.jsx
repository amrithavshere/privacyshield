import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import HelpModal from '../components/HelpModal';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';

export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const [showJson, setShowJson] = useState(false);
  const [copied, setCopied] = useState(false);
  const [showHelp, setShowHelp] = useState(false);

  // Preference state
  const [prefMode, setPrefMode] = useState('balanced');
  const [prefSettings, setPrefSettings] = useState({
    warn_trackers: false,
    warn_ads_profiling: false,
    warn_retention_unclear: false,
    warn_cookie_flags: false
  });
  const [prefSaving, setPrefSaving] = useState(false);
  const [prefSaved, setPrefSaved] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/scans/${id}`)
      .then(res => {
        if (!res.ok) throw new Error('Failed to fetch scan details');
        return res.json();
      })
      .then(data => {
        setScan(data);
        if (data.preference) {
          setPrefMode(data.preference.mode);
          setPrefSettings({
            warn_trackers: data.preference.settings?.warn_trackers ?? true,
            warn_ads_profiling: data.preference.settings?.warn_ads_profiling ?? true,
            warn_retention_unclear: data.preference.settings?.warn_retention_unclear ?? true,
            warn_cookie_flags: data.preference.settings?.warn_cookie_flags ?? true
          });
          setLoading(false);
          return null; // Skip fetching pref if attached (backward compat)
        }
        return fetch(`${API_BASE}/api/preferences?domain=${data.domain}`);
      })
      .then(res => {
        if (!res) return null;
        if (!res.ok) throw new Error('Failed to fetch preferences');
        return res.json();
      })
      .then(prefData => {
        if (prefData) {
          setPrefMode(prefData.mode);
          setPrefSettings({
            warn_trackers: prefData.settings?.warn_trackers ?? true,
            warn_ads_profiling: prefData.settings?.warn_ads_profiling ?? true,
            warn_retention_unclear: prefData.settings?.warn_retention_unclear ?? true,
            warn_cookie_flags: prefData.settings?.warn_cookie_flags ?? true
          });
          setLoading(false);
        }
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, [id]);

  const handleSavePref = async () => {
    setPrefSaving(true);
    setPrefSaved(false);
    try {
      const res = await fetch(`${API_BASE}/api/preferences`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          domain: scan.domain,
          mode: prefMode,
          settings: prefSettings
        })
      });
      if (!res.ok) throw new Error('Failed to save preferences');
      setPrefSaved(true);
      setTimeout(() => setPrefSaved(false), 3000);
    } catch (err) {
      console.error(err);
      alert('Error saving preferences.');
    } finally {
      setPrefSaving(false);
    }
  };

  const handleReanalyze = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/policies/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scan_id: id
        })
      });
      if (!res.ok) throw new Error('Re-analysis failed');
      const data = await res.json();
      setScan(prev => ({ ...prev, ...data }));
    } catch (err) {
      console.error(err);
      alert('Error during re-analysis.');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteScan = async () => {
    if (!window.confirm("Delete this scan? This will remove stored evidence and results for this scan.")) {
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/scans/${id}`, {
        method: 'DELETE'
      });
      if (res.status === 204) {
        navigate("/");
      } else {
        const data = await res.json();
        alert(`Error deleting scan: ${data.detail || data.error || 'Unknown error'}`);
      }
    } catch (err) {
      console.error(err);
      alert('Error connecting to backend for deletion.');
    }
  };

  if (loading) return <div className="loading">Loading scan details...</div>;
  if (error) return <div className="error">Error: {error}</div>;
  if (!scan) return <div className="error">Scan not found.</div>;

  //edit
  const breakdown = scan?.score_breakdown || scan?.score_breakdown_json || {};
  const fmt = (v) => (v === 0 ? "0" : (v ?? "N/A"));

  const policyRisk = breakdown.policy_risk;
  const evidenceRisk = breakdown.evidence_risk;
  const consentRisk = breakdown.consent_session_risk;
  //edit

  // Compute cookie risks
  let missingSecure = 0;
  let missingHttpOnly = 0;
  let missingSameSite = 0;
  
  if (scan.evidence_json && scan.evidence_json.cookies_meta) {
    const cookies = scan.evidence_json.cookies_meta;
    cookies.forEach(c => {
      if (!c.secure) missingSecure++;
      if (!c.httpOnly) missingHttpOnly++;
      if (!c.sameSite || c.sameSite.toLowerCase() === 'none') missingSameSite++; // Assuming 'none' or missing is risk, or just if !c.sameSite
      // Actually standard extension logic usually just checks !c.sameSite, let's just do that to be safe
    });
    // Wait, let's refine SameSite: typically if it's missing or 'no_restriction'
    cookies.forEach(c => {
      // resetting because of previous loop
    });
    
    missingSecure = cookies.filter(c => !c.secure).length;
    missingHttpOnly = cookies.filter(c => !c.httpOnly).length;
    missingSameSite = cookies.filter(c => !c.sameSite || c.sameSite === 'no_restriction' || c.sameSite === 'unspecified').length;
  }

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(scan, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getConsentText = (val) => {
    if (val === true) return "Yes";
    if (val === false) return "No";
    return "-";
  };

  const getConsentDetectionText = (val) => {
    if (val === true) return "Detected";
    if (val === false) return "Not detected";
    return "Unknown";
  };

  const consentMeta = scan.evidence_json?.consent_meta || {};

  const getSeverityClass = (label) => {
    if (!label) return 'severity-all';
    return `severity-${label.toLowerCase()}`;
  };

  // ML Logic
  const ml = scan?.insights?.ml;
  const mlEnabled = ml?.ml_enabled === true;
  const preds = Array.isArray(ml?.ml_predictions) ? ml.ml_predictions : [];

  // Add Snippets Logic
  let topSnippets = [];
  const insights = scan.insights;
  
  if (insights) {
    let flags = insights.risk_flags || [];
    if (flags.length > 0) {
      const severityWeight = { high: 3, medium: 2, low: 1 };
      flags = [...flags].sort((a, b) => (severityWeight[b.severity || 'low'] || 0) - (severityWeight[a.severity || 'low'] || 0));
      topSnippets = flags.slice(0, 5).map(f => ({
        text: f.evidence,
        level: f.severity || 'low'
      }));
    } else {
      let categories = insights.clause_categories || [];
      const riskWeight = { high: 3, medium: 2, low: 1 };
      categories = [...categories].sort((a, b) => (riskWeight[b.risk || 'low'] || 0) - (riskWeight[a.risk || 'low'] || 0));
      topSnippets = categories.slice(0, 5).map(c => ({
        text: c.text,
        level: c.risk || 'low'
      }));
    }
  }

  const truncateText = (text, maxLength = 160) => {
    if (!text) return "";
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength).trim() + "...";
  };

  return (
    <div>
      <div style={{marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
        <Link to="/" className="btn btn-secondary">← Back to Scans</Link>
        <button className="btn btn-danger" onClick={handleDeleteScan}>Delete Scan</button>
      </div>
      
      <div className="surface">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <h2 className="title" style={{margin: 0}}>Scan Report: {scan.domain}</h2>
            <span className="severity-tag" style={{ backgroundColor: '#f3f4f6', color: '#374151', border: '1px solid #d1d5db' }} title="Current preference mode applied to this analysis.">
              Preference applied: {prefMode.charAt(0).toUpperCase() + prefMode.slice(1)}
              <span className="info-icon">ℹ</span>
            </span>
            <button className="btn btn-secondary" style={{padding: '0.25rem 0.75rem', fontSize: '0.8rem'}} onClick={() => setShowHelp(true)}>
              How to read this report?
            </button>
          </div>
          {scan.severity_label && (
            <span className={`severity-tag ${getSeverityClass(scan.severity_label)}`} style={{fontSize: '1rem', padding: '0.5rem 1rem'}}>
              {scan.severity_label} Severity
            </span>
          )}
        </div>

        <div className="detail-grid">
          <div className="stat-card">
            <div className="stat-value">{scan.score_total ?? 'N/A'}</div>
            <div className="stat-label">
              Total Risk Score
              <span className="info-icon" title="Overall privacy risk level (0-100). Higher = More Risk.">ℹ</span>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{fmt(policyRisk)}</div>
            <div className="stat-label">
              Policy Risk
              <span className="info-icon" title="Risk inferred from policy text: sharing, ads profiling, retention clarity, rights.">ℹ</span>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{fmt(evidenceRisk)}</div>
            <div className="stat-label">
              Evidence Risk
              <span className="info-icon" title="Risk inferred from cookies and tracker evidence.">ℹ</span>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{fmt(consentRisk)}</div>
            <div className="stat-label">
              Consent Risk
              <span className="info-icon" title="Risk inferred from consent banner and session safety signals.">ℹ</span>
            </div>
          </div>
        </div>

        {/* Preferences Section */}
        <h3 className="subtitle">Site Preferences</h3>
        <div style={{ padding: '1.5rem', border: '1px solid var(--border-color)', borderRadius: '0.5rem', marginBottom: '1.5rem', backgroundColor: '#f9fafb' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <label style={{ fontWeight: 600 }}>Mode:</label>
            <select 
              className="input-field" 
              value={prefMode} 
              onChange={(e) => setPrefMode(e.target.value)}
              style={{ minWidth: '150px' }}
            >
              <option value="strict">Strict</option>
              <option value="balanced">Balanced</option>
              <option value="custom">Custom</option>
            </select>

            <button 
              className="btn btn-secondary" 
              onClick={handleSavePref}
              disabled={prefSaving}
            >
              {prefSaving ? 'Saving...' : 'Save Preferences'}
            </button>
            <button 
              className="btn btn-secondary" 
              onClick={handleReanalyze}
              style={{ backgroundColor: 'var(--bg-color)' }}
            >
              🔄 Re-analyze
            </button>
            {prefSaved && <span style={{ color: 'var(--severity-low)', fontWeight: 500 }}>Saved!</span>}
          </div>

          {prefMode === 'custom' && (
            <div style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ color: '#4b5563', fontSize: '0.9rem', marginBottom: '0.5rem' }}>
                <strong style={{color: '#1f2937'}}>Filters Applied:</strong> Disabled warnings are explicitly excluded from analysis results and findings.
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input 
                  type="checkbox" 
                  checked={prefSettings.warn_trackers} 
                  onChange={(e) => setPrefSettings({...prefSettings, warn_trackers: e.target.checked})} 
                />
                Warn on Trackers
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input 
                  type="checkbox" 
                  checked={prefSettings.warn_ads_profiling} 
                  onChange={(e) => setPrefSettings({...prefSettings, warn_ads_profiling: e.target.checked})} 
                />
                Warn on Ads Profiling
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input 
                  type="checkbox" 
                  checked={prefSettings.warn_retention_unclear} 
                  onChange={(e) => setPrefSettings({...prefSettings, warn_retention_unclear: e.target.checked})} 
                />
                Warn Unclear Retention
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input 
                  type="checkbox" 
                  checked={prefSettings.warn_cookie_flags} 
                  onChange={(e) => setPrefSettings({...prefSettings, warn_cookie_flags: e.target.checked})} 
                />
                Warn Missing Cookie Flags
              </label>
            </div>
            </div>
          )}
        </div>

        <h3 className="subtitle">Top Risky Policy Snippets</h3>
        {!insights ? (
          <p style={{color: 'var(--text-secondary)'}}>No policy snippets available yet. Run Analyze first.</p>
        ) : topSnippets.length === 0 ? (
          <p style={{color: 'var(--text-secondary)'}}>No risky snippets identified.</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {topSnippets.map((snippet, idx) => (
              <div key={idx} style={{ padding: '1rem', backgroundColor: '#f9fafb', border: '1px solid var(--border-color)', borderRadius: '0.375rem', display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
                <span className={`severity-tag severity-${snippet.level.toLowerCase()}`} style={{flexShrink: 0, marginTop: '0.125rem'}}>
                  {snippet.level}
                </span>
                <span style={{color: 'var(--text-primary)', fontStyle: 'italic', lineHeight: '1.4'}}>
                  "{truncateText(snippet.text, 160)}"
                </span>
              </div>
            ))}
          </div>
        )}

        <h3 className="subtitle">ML Clause Labels</h3>
        {!mlEnabled ? (
          <p style={{color: 'var(--text-secondary)'}}>ML model not trained yet.</p>
        ) : preds.length === 0 ? (
          <p style={{color: 'var(--text-secondary)'}}>ML ran but no confident predictions.</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {preds.map((pred, idx) => (
              <div key={idx} style={{ padding: '1rem', backgroundColor: '#f9fafb', border: '1px solid var(--border-color)', borderRadius: '0.375rem', display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
                <span className="severity-tag severity-high" style={{flexShrink: 0, marginTop: '0.125rem', backgroundColor: 'var(--surface-color)', color: 'var(--primary-color)', border: '1px solid var(--primary-color)'}}>
                  {pred.label} ({Math.round(pred.confidence * 100)}%)
                </span>
                <span style={{color: 'var(--text-primary)', fontStyle: 'italic', lineHeight: '1.4'}}>
                  "{pred.text_snippet}"
                </span>
              </div>
            ))}
          </div>
        )}

        <h3 className="subtitle">Risk Factors & Recommendations</h3>
        {(!scan.reasons || scan.reasons.length === 0) && (!scan.recommendations || scan.recommendations.length === 0) ? (
          <p style={{color: 'var(--text-secondary)'}}>Not analyzed yet</p>
        ) : (
          <div style={{display: 'flex', gap: '2rem', flexWrap: 'wrap'}}>
            <div style={{flex: 1, minWidth: '300px'}}>
              <h4 style={{marginBottom: '0.5rem', color: 'var(--severity-high)'}}>Reasons</h4>
              <ul style={{paddingLeft: '1.5rem'}}>
                {scan.reasons && scan.reasons.map((r, i) => <li key={i} className="list-item">{r}</li>)}
              </ul>
            </div>
            <div style={{flex: 1, minWidth: '300px'}}>
              <h4 style={{marginBottom: '0.5rem', color: 'var(--severity-low)'}}>Recommendations</h4>
              <ul style={{paddingLeft: '1.5rem'}}>
                {scan.recommendations && scan.recommendations.map((r, i) => <li key={i} className="list-item">{r}</li>)}
              </ul>
            </div>
          </div>
        )}

        <h3 className="subtitle">Consent & Evidence Details</h3>
        <div style={{display: 'flex', gap: '2rem', flexWrap: 'wrap'}}>
          <div style={{flex: 1, minWidth: '220px'}}>
            <h4 style={{marginBottom: '0.5rem'}}>
              Consent Banner
              <span className="info-icon" title="Evaluates if a consent banner is present and its capabilities.">ℹ</span>
            </h4>
            <ul style={{listStyle: 'none', padding: 0}}>
              <li className="list-item">Status: <strong>{getConsentDetectionText(consentMeta.banner_detected)}</strong></li>
              <li className="list-item">Vendor: <strong style={{textTransform: 'capitalize'}}>{consentMeta.banner_vendor || "-"}</strong></li>
              <li className="list-item">Reject Available: <strong>{getConsentText(consentMeta.reject_available)}</strong></li>
              <li className="list-item">Manage Available: <strong>{getConsentText(consentMeta.manage_available)}</strong></li>
            </ul>
          </div>
          <div style={{flex: 1, minWidth: '220px'}}>
            <h4 style={{marginBottom: '0.5rem'}}>
              Cookie Risks
              <span className="info-icon" title="Technical risks associated with detected cookies (Secure, HttpOnly, SameSite).">ℹ</span>
            </h4>
            <ul style={{listStyle: 'none', padding: 0}}>
              <li className="list-item">Missing Secure: <strong>{missingSecure}</strong></li>
              <li className="list-item">Missing HttpOnly: <strong>{missingHttpOnly}</strong></li>
              <li className="list-item">Missing SameSite: <strong>{missingSameSite}</strong></li>
            </ul>
          </div>
          <div style={{flex: 1, minWidth: '220px'}}>
            <h4 style={{marginBottom: '0.5rem'}}>Discovered Links</h4>
            <ul style={{listStyle: 'none', padding: 0}}>
              <li className="list-item">
                Policy: {scan.policy_url ? <a href={scan.policy_url} target="_blank" rel="noreferrer">Link</a> : 'None'}
              </li>
              <li className="list-item">
                Terms: {scan.terms_url ? <a href={scan.terms_url} target="_blank" rel="noreferrer">Link</a> : 'None'}
              </li>
            </ul>
          </div>
        </div>

        <div className="accordion">
          <div className="accordion-header" onClick={() => setShowJson(!showJson)}>
            <span>Raw JSON Data</span>
            <div style={{display: 'flex', gap: '1rem', alignItems: 'center'}}>
              <button 
                className="btn btn-secondary" 
                style={{padding: '0.25rem 0.5rem', fontSize: '0.75rem'}}
                onClick={(e) => {
                  e.stopPropagation();
                  handleCopyJson();
                }}
              >
                {copied ? 'Copied!' : 'Copy JSON'}
              </button>
              <span>{showJson ? '▲' : '▼'}</span>
            </div>
          </div>
          {showJson && (
            <div className="accordion-content">
              <pre>{JSON.stringify(scan, null, 2)}</pre>
            </div>
          )}
        </div>

      </div>

      <HelpModal 
        open={showHelp} 
        onClose={() => setShowHelp(false)} 
        context="scanDetail"
      />
    </div>
  );
}
