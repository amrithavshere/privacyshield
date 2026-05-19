import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import ScansList from './pages/ScansList';
import ScanDetail from './pages/ScanDetail';

function App() {
  return (
    <Router>
      <div className="layout">
        <header className="header">
          <h1>PrivacyShield Dashboard</h1>
        </header>
        <main className="main-content">
          <Routes>
            <Route path="/" element={<ScansList />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
