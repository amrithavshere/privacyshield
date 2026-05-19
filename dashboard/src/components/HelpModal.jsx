import React from 'react';

const HelpModal = ({ open, onClose, context }) => {
  if (!open) return null;

  const handleBackdropClick = (e) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <div className="modal-overlay" onClick={handleBackdropClick}>
      <div className="modal-content">
        <button className="modal-close" onClick={onClose}>&times;</button>
        
        <h2 className="title">How to read this report</h2>
        
        <div className="help-section">
          <h3>Score Meaning</h3>
          <p>The <strong>Total Risk Score (0–100)</strong> indicates the overall privacy risk level. A higher score means more potential privacy issues detected.</p>
          <ul className="help-list">
            <li><strong>0–30 Low:</strong> Generally safe with minimal privacy risks.</li>
            <li><strong>31–60 Medium:</strong> Some privacy risks found; caution advised.</li>
            <li><strong>61–100 High:</strong> Significant privacy concerns detected.</li>
          </ul>
        </div>

        <div className="help-section">
          <h3>Score Breakdown</h3>
          <ul className="help-list">
            <li><strong>Policy Risk (0–50):</strong> Inferred from the privacy policy text (e.g., data sharing, ads profiling, unclear retention periods).</li>
            <li><strong>Evidence Risk (0–30):</strong> Based on technical signals like cookie security flags and third-party tracker domains.</li>
            <li><strong>Consent Risk (0–20):</strong> Evaluates if a consent banner is present and if it offers easy options to reject tracking.</li>
          </ul>
        </div>

        <div className="help-section">
          <h3>Preference Modes</h3>
          <ul className="help-list">
            <li><strong>Balanced:</strong> The baseline standard for privacy warnings (default).</li>
            <li><strong>Strict:</strong> Shows all potential warnings and adds stricter advice. May apply a small risk penalty if a consent banner lacks a clear "Reject" option.</li>
            <li><strong>Custom:</strong> Only shows warnings for the categories you've enabled in your settings.</li>
          </ul>
        </div>

        <div className="help-section">
          <h3>Cookie & Session Risks</h3>
          <ul className="help-list">
            <li><strong>Secure missing:</strong> The cookie can be sent over unencrypted connections, increasing interception risk.</li>
            <li><strong>HttpOnly missing:</strong> The cookie can be accessed by scripts, increasing XSS exposure.</li>
            <li><strong>SameSite missing:</strong> Increases risk of cross-site request forgery and cross-site tracking.</li>
          </ul>
        </div>

        <div className="help-section">
          <h3>Consent & Banners</h3>
          <p>If a banner is detected but "Reject" or "Manage" options are missing, it may indicate limited user choice over tracking.</p>
        </div>

        <div className="help-section">
          <h3>Reasons & Recommendations</h3>
          <ul className="help-list">
            <li><strong>Reasons:</strong> Specific findings that contributed to the risk score.</li>
            <li><strong>Recommendations:</strong> Suggested actions you can take to mitigate the identified risks.</li>
          </ul>
        </div>

        <div style={{ textAlign: 'right', marginTop: '1rem' }}>
          <button className="btn" onClick={onClose}>Got it</button>
        </div>
      </div>
    </div>
  );
};

export default HelpModal;
