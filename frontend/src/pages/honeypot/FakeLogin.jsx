import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import LogGenerator from '../../components/honeypot/LogGenerator'

const FakeLogin = () => {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  })
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [attempts, setAttempts] = useState(0)
  const [shouldGenerateLog, setShouldGenerateLog] = useState(false)
  const [logData, setLogData] = useState(null)
  const navigate = useNavigate()

  // "Valid" credentials for the honeypot
  const validCredentials = [
    { username: 'admin', password: 'admin123' },
    { username: 'user', password: 'password' },
    { username: 'test', password: 'test123' }
  ]

  const handleSubmit = async (e) => {
    e.preventDefault()
    setIsLoading(true)
    setError('')

    // Simulate authentication delay
    await new Promise(resolve => setTimeout(resolve, 1500))

    // Check if credentials are "valid"
    const isValid = validCredentials.some(cred => 
      cred.username === formData.username && cred.password === formData.password
    )

    // Prepare data to generate real log
    setLogData({
      username: formData.username,
      password: formData.password
    })
    setShouldGenerateLog(true)

    if (isValid) {
      // "Successful login"
        setError('Login successful! Redirecting...')
      setTimeout(() => {
        navigate('/dashboard')
      }, 1000)
    } else {
      // Failed login
      setAttempts(prev => prev + 1)
      
      const errorMessages = [
        'Invalid username or password. Please try again.',
        'Access denied. Please check your credentials.',
        'Authentication failed. Too many attempts.',
        'User account is locked. Contact administrator.'
      ]
      
      setError(errorMessages[Math.min(attempts, errorMessages.length - 1)])
      
      // After 3 attempts, "unlock" with valid credentials
      if (attempts >= 2) {
        setTimeout(() => {
          setError('Hint: Try admin/admin123 or user/password')
        }, 2000)
      }
    }
    
    setIsLoading(false)
  }

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    })
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      {/* Generate real log when form is submitted */}
      {shouldGenerateLog && logData && (
        <LogGenerator 
          endpoint="/login" 
          method="POST" 
          data={logData}
          silent={true}
        />
      )}
      
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Sign in to your account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            SecureCorp Enterprise Portal
          </p>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <label htmlFor="username" className="sr-only">
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                placeholder="Username"
                value={formData.username}
                onChange={handleChange}
              />
            </div>
            <div>
              <label htmlFor="password" className="sr-only">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                placeholder="Password"
                value={formData.password}
                onChange={handleChange}
              />
            </div>
          </div>

          {error && (
            <div className={`px-4 py-3 rounded-md text-sm ${
              error.includes('successful') 
                ? 'bg-green-50 border border-green-200 text-green-700'
                : 'bg-red-50 border border-red-200 text-red-700'
            }`}>
              {error}
            </div>
          )}

          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <input
                id="remember-me"
                name="remember-me"
                type="checkbox"
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-900">
                Remember me
              </label>
            </div>

            <div className="text-sm">
              <a href="#" className="font-medium text-blue-600 hover:text-blue-500">
                Forgot your password?
              </a>
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={isLoading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
              ) : null}
              {isLoading ? 'Signing in...' : 'Sign in'}
            </button>
          </div>

          <div className="text-center">
            <p className="text-sm text-gray-600">
              Don't have an account?{' '}
              <a href="#" className="font-medium text-blue-600 hover:text-blue-500">
                Contact your administrator
              </a>
            </p>
          </div>
        </form>
      </div>
    </div>
  )
}

export default FakeLogin