import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import UrlAnalyzer from './pages/UrlAnalyzer'
import EmailAnalyzer from './pages/EmailAnalyzer'
import QrScanner from './pages/QrScanner'
import History from './pages/History'

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/url" element={<UrlAnalyzer />} />
          <Route path="/email" element={<EmailAnalyzer />} />
          <Route path="/qr" element={<QrScanner />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App
