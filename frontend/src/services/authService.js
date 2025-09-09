import { useState, useEffect, useCallback } from 'react'
import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'

/**
 * Unified authentication service that includes both service logic
 * and React hook for a completely modular solution
 */
class AuthService {
  constructor() {
    this.baseURL = API_BASE_URL
    this.tokenKey = 'auth_token'
    this.authRoutePrefix = import.meta.env.VITE_AUTH_ROUTE_PREFIX || 'auth'
  }

  // === TOKEN MANAGEMENT ===
  
  getToken() {
    return localStorage.getItem(this.tokenKey)
  }

  // getRefreshToken removed - refresh tokens are not used

  setTokens(token) {
    localStorage.setItem(this.tokenKey, token)
  }

  clearTokens() {
    localStorage.removeItem(this.tokenKey)
    sessionStorage.removeItem('logs_password')
  }

  // === AUTHENTICATION VERIFICATION ===
  
  isAuthenticated() {
    const token = this.getToken()
    if (!token) return false
    
    try {
      const payload = JSON.parse(atob(token.split('.')[1]))
      const currentTime = Date.now() / 1000
      return payload.authenticated === true && payload.exp > currentTime
    } catch (error) {
      console.error('Error parsing token:', error)
      return false
    }
  }

  // getUserInfo and hasPermissions functions removed - not consistent with simple JWT backend

  // === AUTHENTICATION ===
  
  async login(password) {
    try {
      const response = await axios.post(`${this.baseURL}/api/${this.authRoutePrefix}/login`, {
        password  // Only send password, backend doesn't require username
      })

      const { access_token } = response.data
      this.setTokens(access_token)
      
      return {
        success: true,
        token: access_token
      }
    } catch (error) {
      console.error('Login error:', error)
      return {
        success: false,
        error: error.response?.data?.message || 'Authentication failed'
      }
    }
  }

  async logout() {
    try {
      const token = this.getToken()
      if (token) {
        await axios.post(`${this.baseURL}/api/${this.authRoutePrefix}/logout`, {}, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        })
      }
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      this.clearTokens()
    }
  }

  // === TOKEN RENEWAL ===
  
  async refreshToken() {
    // Backend doesn't handle refresh tokens, re-authentication required
    throw new Error('Token refresh not supported - please login again')
  }

  // === MIGRATION FROM LEGACY SYSTEM ===
  
  migrateFromLegacy() {
    const legacyPassword = sessionStorage.getItem('logs_password')
    if (legacyPassword && !this.isAuthenticated()) {
      return this.login(legacyPassword)  // Only password required
    }
    return Promise.resolve({ success: false, error: 'No legacy credentials found' })
  }

  // === INTEGRATED REACT HOOK ===
  
  /**
   * Integrated React hook for authentication
   * Simplified to work only with basic JWT authentication
   */
  useAuth() {
    const [isAuthenticated, setIsAuthenticated] = useState(false)
    const [authError, setAuthError] = useState(null)
    const [isAuthenticating, setIsAuthenticating] = useState(false)
    const [isLoading, setIsLoading] = useState(true)

    // Check initial authentication
    const checkAuth = useCallback(async () => {
      try {
        if (this.isAuthenticated()) {
          setIsAuthenticated(true)
          setAuthError(null)
        } else {
          // Attempt legacy system migration if it exists
          await attemptLegacyMigration(setIsAuthenticated, setAuthError)
        }
      } catch (error) {
        console.error('Authentication check failed:', error)
        this.clearTokens()
        setIsAuthenticated(false)
        setAuthError('Authentication check failed')
      } finally {
        setIsLoading(false)
      }
    }, [])

    // Legacy system migration
    const attemptLegacyMigration = async (setAuth, setError) => {
      try {
        const migrationResult = await this.migrateFromLegacy()
        if (migrationResult.success) {
          setAuth(true)
          setError(null)
        } else {
          setAuth(false)
        }
      } catch (error) {
        console.error('Legacy migration failed:', error)
        setAuth(false)
      }
    }

    // Authentication function
    const authenticate = async (password) => {
      setIsAuthenticating(true)
      setAuthError(null)

      try {
        const result = await this.login(password)
        
        if (result.success) {
          setIsAuthenticated(true)
          setAuthError(null)
        }
        
        return result
      } catch (error) {
        const errorMsg = 'Authentication failed'
        setAuthError(errorMsg)
        return { success: false, error: errorMsg }
      } finally {
        setIsAuthenticating(false)
      }
    }

    // Logout function
    const logout = async () => {
      try {
        await this.logout()
      } catch (error) {
        console.error('Logout error:', error)
      } finally {
        setIsAuthenticated(false)
        setAuthError(null)
      }
    }

    // Clear errors
    const clearError = () => {
      setAuthError(null)
    }

    // Check authentication on mount
    useEffect(() => {
      checkAuth()
    }, [checkAuth])

    return {
      isAuthenticated,
      authError,
      isAuthenticating,
      isLoading,
      authenticate,
      logout,
      clearError,
      checkAuth
    }
  }
}

// Singleton service instance
const authService = new AuthService()

export default authService
export { AuthService }