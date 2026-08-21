import { createContext, useContext, useState, useEffect } from 'react'
import axios from 'axios'

type User = {
  id: string
  email: string
  role: string
  organizationId: string
}

type AuthContextType = {
  user: User | null
  organizationId: string | null
  isAuthenticated: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  // API base URL - points to production Python API
  apiBase: string
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null)
  const [organizationId, setOrganizationId] = useState<string | null>(null)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [apiBase, setApiBase] = useState<string>('http://localhost:8000/api/v1')

  useEffect(() => {
    const loadAuthState = async () => {
      try {
        // Try to get authenticated user from the Python API
        const resp = await axios.get(`${apiBase}/auth/me`, {
          withCredentials: true
        })
        setUser(resp.data.user)
        setOrganizationId(resp.data.organizationId)
        setIsAuthenticated(true)
      } catch (err) {
        // Maybe no token yet - try auto-login with stored token
        const storedToken = localStorage.getItem('redos_token')
        if (storedToken) {
          try {
            axios.defaults.headers.common['Authorization'] = `Bearer ${storedToken}`
            const resp = await axios.get(`${apiBase}/auth/me`)
            setUser(resp.data.user)
            setOrganizationId(resp.data.organizationId)
            setIsAuthenticated(true)
          } catch (authErr) {
            // Token invalid, clear it
            localStorage.removeItem('redos_token')
            axios.defaults.headers.common['Authorization'] = ''
          }
        }
        setIsAuthenticated(false)
        setUser(null)
        setOrganizationId(null)
      }
    }

    loadAuthState()
  }, [apiBase])

  const login = async (email: string, password: string) => {
    try {
      const resp = await axios.post(`${apiBase}/auth/login`, { email, password }, {
        withCredentials: true
      })
      const { token } = resp.data
      
      // Store token for future requests
      localStorage.setItem('redos_token', token)
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
      
      setUser({
        id: resp.data.user.id,
        email,
        role: resp.data.user.role,
        organizationId: resp.data.organizationId,
      })
      setOrganizationId(resp.data.organizationId)
      setIsAuthenticated(true)
    } catch (err) {
      console.error('Login failed:', err)
      throw err
    }
  }

  const logout = async () => {
    try {
      await axios.post(`${apiBase}/auth/logout`, {}, { withCredentials: true })
    } catch (err) {
      console.error('Logout failed:', err)
    } finally {
      localStorage.removeItem('redos_token')
      axios.defaults.headers.common['Authorization'] = ''
      setUser(null)
      setOrganizationId(null)
      setIsAuthenticated(false)
    }
  }

  return (
    <AuthContext.Provider value={{ user, organizationId, isAuthenticated, login, logout, apiBase }}>
      {children}
    </AuthContext.Provider>
  )
}