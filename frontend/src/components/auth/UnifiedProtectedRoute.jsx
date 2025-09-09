import { useState } from 'react'
import { Shield, Lock, Eye, EyeOff, AlertTriangle, Database } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import authService from '../../services/authService'

/**
 * Unified protected route component that replaces ProtectedRoute and LogsProtectedRoute.
 * Handles authentication with specific permissions and different UI types.
 */
const UnifiedProtectedRoute = ({ 
  children, 
  requiredPermissions = [], 
  onAuthenticated, 
  redirectTo = null,
  variant = 'dashboard', // 'dashboard' | 'logs'
  title,
  description
}) => {
  const {
    isAuthenticated,
    authError,
    isAuthenticating,
    isLoading,
    authenticate,
    clearError
  } = authService.useAuth()

  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [localError, setLocalError] = useState('')
  const navigate = useNavigate()

  // Configuration by variant
  const variantConfig = {
    dashboard: {
      icon: Shield,
      title: title || 'HoneyGuard Dashboard',
      description: description || 'Secure access to your honeypot monitoring system',
      primaryColor: 'blue',
      helpText: 'Enter your credentials to access the dashboard'
    },
    logs: {
      icon: Database,
      title: title || 'Advanced Logs Access',
      description: description || 'Secure access to detailed log analysis',
      primaryColor: 'green',
      helpText: 'Enter your credentials to access advanced logs'
    }
  }

  const config = variantConfig[variant] || variantConfig.dashboard
  const IconComponent = config.icon

  // Show loading while verifying authentication
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-300">Verifying authentication...</p>
        </div>
      </div>
    )
  }

  // If authenticated, show protected content
  if (isAuthenticated) {
    if (onAuthenticated) {
      onAuthenticated(true)
    }
    return children
  }

  // Handle login
  const handleLogin = async (e) => {
    e.preventDefault()
    setLocalError('')
    clearError()

    const result = await authenticate(password)

    if (!result.success) {
      setLocalError(result.error || 'Authentication failed')
      setPassword('')
    } else {
      // If redirection is configured, navigate
      if (redirectTo) {
        navigate(redirectTo)
      }
    }
  }



  const displayError = localError || authError

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full space-y-8">
        {/* Header */}
        <div className="text-center">
          <div className={`mx-auto h-16 w-16 bg-${config.primaryColor}-600 rounded-full flex items-center justify-center mb-4`}>
            <IconComponent className="h-8 w-8 text-white" />
          </div>
          <h2 className="text-3xl font-bold text-white mb-2">
            {config.title}
          </h2>
          <p className="text-gray-400">
            {config.description}
          </p>
        </div>

        {/* Error Alert */}
        {displayError && (
          <div className="bg-red-900/50 border border-red-500 rounded-lg p-4 flex items-start space-x-3">
            <AlertTriangle className="h-5 w-5 text-red-400 mt-0.5 flex-shrink-0" />
            <div className="flex-1">
              <p className="text-red-200 text-sm">{displayError}</p>
              <button
              onClick={() => {
                setLocalError('')
                clearError()
              }}
              className="text-red-400 hover:text-red-300 text-xs mt-1 underline"
            >
              Dismiss
            </button>
            </div>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleLogin} className="space-y-6">
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl p-6 border border-gray-700">
            {/* Password Field */}
            <div className="mb-6">
              <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3 py-2 pr-10 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Enter password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-300"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isAuthenticating}
              className={`w-full bg-${config.primaryColor}-600 hover:bg-${config.primaryColor}-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center space-x-2`}
            >
              {isAuthenticating ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  <span>Authenticating...</span>
                </>
              ) : (
                <>
                  <Lock className="h-4 w-4" />
                  <span>Access {variant === 'logs' ? 'Logs' : 'Dashboard'}</span>
                </>
              )}
            </button>
          </div>
        </form>

        {/* Help Text */}
        <div className="text-center">
          <p className="text-gray-400 text-sm">
            {config.helpText}
          </p>
          {requiredPermissions.length > 0 && (
            <p className="text-gray-500 text-xs mt-2">
              Required permissions: {requiredPermissions.join(', ')}
            </p>
          )}
        </div>

        {/* Navigation Links */}
        <div className="text-center space-y-2">
          <button
            onClick={() => navigate('/')}
            className="text-gray-400 hover:text-gray-300 text-sm underline"
          >
            ← Back to Home
          </button>
        </div>
      </div>
    </div>
  )
}

export default UnifiedProtectedRoute