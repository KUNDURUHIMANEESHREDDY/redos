import React, { useEffect, useState } from 'react'
import { BrowserRouter as Router, Routes, Route, useNavigate } from 'react-router-dom'
import axios from 'axios'
import FindingPage from './components/FindingPage'
import { useAuth } from './hooks/useAuth'

const App: React.FC = () => {
  const { user, organizationId, isAuthenticated } = useAuth()
  const navigate = useNavigate()
  const [dashboards, setDashboards] = useState<'targets' | 'campaigns' | 'executions' | 'findings'>('targets')
  const [organizations, setOrganizations] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  // Set API base from auth context - points to Python FastAPI
  const apiBase = `http://localhost:8000/api/v1`

  useEffect(() => {
    const initApp = async () => {
      try {
        if (isAuthenticated && user) {
          // Fetch organizations for the user from the real API
          const resp = await axios.get(`${apiBase}/organizations`, {
            params: { orgId: organizationId },
            headers: { Authorization: `Bearer ${localStorage.getItem('redos_token')}` }
          })
          setOrganizations(resp.data)
        }
      } catch (err) {
        console.error('Failed to init app:', err)
        // Redirect to login if not authenticated
        if (!isAuthenticated) {
          navigate('/api/auth/login')
        }
      } finally {
        setLoading(false)
      }
    }

    initApp()
  }, [user, organizationId, isAuthenticated])

  if (!isAuthenticated) {
    return <div className="auth-screen">
      <h2>Login Required</h2>
      <p>Please authenticate to access the security console.</p>
      <button
        onClick={() => {
          window.location.href = `${apiBase}/api/auth/login`
        }}
      >Authenticate</button>
    </div>
  }

  if (loading) {
    return <div className="loading-screen">Loading...</div>
  }

  return (
    <Router>
      <div className="app">
        <header className="app-header">
          <h1>🛡️ RedOS Security Platform</h1>
          <div className="user-info">
            <span>User: {user?.email || 'Guest'}</span>
            <span>Org: {organizationId || 'None'}</span>
            <button onClick={() => {
              // Logout - call the Python API
              axios.post(`${apiBase}/auth/logout`, {}, {
                headers: { Authorization: `Bearer ${localStorage.getItem('redos_token')}` }
              })
              // Clear local state
              // navigate('/')
            }}>Logout</button>
          </div>
        </header>

        <nav className="app-nav">
          <button className={dashboards === 'targets' ? 'active' : ''} onClick={() => setDashboards('targets')}>
            Targets
          </button>
          <button className={dashboards === 'campaigns' ? 'active' : ''} onClick={() => setDashboards('campaigns')}>
            Attack Campaigns
          </button>
          <button className={dashboards === 'executions' ? 'active' : ''} onClick={() => setDashboards('executions')}>
            Executions
          </button>
          <button className={dashboards === 'findings' ? 'active' : ''} onClick={() => setDashboards('findings')}>
            Findings
          </button>
        </nav>

        <main className="app-main">
          <Routes>
            <Route path="/" element={<div>Dashboard content</div>} />
            <Route path="/findings/:id" element={<FindingPage />} />
            <Route path="/organizations/:id" element={<div>Organization Detail</div>} />
          </Routes>
        </main>
      </div>
    </Router>
  )
}

export default App