import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import UrlAnalyzer from './pages/UrlAnalyzer'
import EmailAnalyzer from './pages/EmailAnalyzer'
import QrScanner from './pages/QrScanner'
import PhoneAnalyzer from './pages/PhoneAnalyzer'
import ImageAnalyzer from './pages/ImageAnalyzer'
import AudioAnalyzer from './pages/AudioAnalyzer'
import History from './pages/History'
import CyberChat from './pages/CyberChat'
import CyberTraining from './pages/CyberTraining'
import Landing from './pages/Landing'
import ThreatIntel from './pages/ThreatIntel'

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/dashboard" element={<Layout><Dashboard /></Layout>} />
        <Route path="/url" element={<Layout><UrlAnalyzer /></Layout>} />
        <Route path="/email" element={<Layout><EmailAnalyzer /></Layout>} />
        <Route path="/phone" element={<Layout><PhoneAnalyzer /></Layout>} />
        <Route path="/image" element={<Layout><ImageAnalyzer /></Layout>} />
        <Route path="/audio" element={<Layout><AudioAnalyzer /></Layout>} />
        <Route path="/qr" element={<Layout><QrScanner /></Layout>} />
        <Route path="/history" element={<Layout><History /></Layout>} />
        <Route path="/chat" element={<Layout><CyberChat /></Layout>} />
        <Route path="/training" element={<Layout><CyberTraining /></Layout>} />
        <Route path="/threat-intel" element={<Layout><ThreatIntel /></Layout>} />
      </Routes>
    </Router>
  )
}

export default App
