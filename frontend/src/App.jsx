import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import UrlAnalyzer from './pages/UrlAnalyzer'
import EmailAnalyzer from './pages/EmailAnalyzer'
import QrScanner from './pages/QrScanner'
import History from './pages/History'
import CyberChat from './pages/CyberChat'
import Landing from './pages/Landing'

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/dashboard" element={<Layout><Dashboard /></Layout>} />
        <Route path="/url" element={<Layout><UrlAnalyzer /></Layout>} />
        <Route path="/email" element={<Layout><EmailAnalyzer /></Layout>} />
        <Route path="/qr" element={<Layout><QrScanner /></Layout>} />
        <Route path="/history" element={<Layout><History /></Layout>} />
        <Route path="/chat" element={<Layout><CyberChat /></Layout>} />
      </Routes>
    </Router>
  )
}

export default App
