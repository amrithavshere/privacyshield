import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import HelpModal from '../components/HelpModal';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';

export default function ScansList() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [showHelp, setShowHelp] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/scans`)
      .then(res => {
        if (!res.ok) throw new Error('Failed to fetch scans');
        return res.json();
      })
      .then(data => {
        setScans(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  if (loading) return <div className="loading">Loading scans...</div>;
  if (error) return <div className="error">Error: {error}</div>;

  const filteredScans = scans.filter(scan => {
    const matchesSearch = scan.domain.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === 'All' || 
      (scan.severity_label && scan.severity_label.toLowerCase() === severityFilter.toLowerCase());
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="surface">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 className="title" style={{ margin: 0 }}>Scan History</h2>
        <button className="btn btn-secondary" onClick={() => setShowHelp(true)}>
          How to read reports?
        </button>
      </div>
      
      <div className="controls-bar">
        <input 
          type="text" 
          placeholder="Search by domain..." 
          className="input-field"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        
        <select 
          className="input-field" 
          value={severityFilter} 
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="All">All Severities</option>
          <option value="Low">Low</option>
          <option value="Medium">Medium</option>
          <option value="High">High</option>
        </select>
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Domain</th>
              <th>Date</th>
              <th>Score</th>
              <th>Severity</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredScans.length === 0 ? (
              <tr>
                <td colSpan="6" style={{textAlign: 'center', padding: '2rem'}}>No scans found.</td>
              </tr>
            ) : (
              filteredScans.map(scan => (
                <tr key={scan.id}>
                  <td>{scan.id}</td>
                  <td style={{fontWeight: 500}}>{scan.domain}</td>
                  <td>{new Date(scan.created_at).toLocaleString()}</td>
                  <td>{scan.score_total !== null ? scan.score_total : '-'}</td>
                  <td>
                    {scan.severity_label ? (
                      <span className={`severity-tag severity-${scan.severity_label.toLowerCase()}`}>
                        {scan.severity_label}
                      </span>
                    ) : '-'}
                  </td>
                  <td>
                    <Link to={`/scans/${scan.id}`} className="btn">View</Link>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <HelpModal 
        open={showHelp} 
        onClose={() => setShowHelp(false)} 
        context="scanList"
      />
    </div>
  );
}
