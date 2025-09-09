import { useState } from 'react'
import HoneypotLayout from '../../components/layout/HoneypotLayout'
import LogGenerator from '../../components/honeypot/LogGenerator'

const FakeWordPress = () => {
  const [formData, setFormData] = useState({
    log: '',
    pwd: ''
  })
  const [isLoading, setIsLoading] = useState(false)
  const [message, setMessage] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setIsLoading(true)
    setMessage('')

    try {
      // Redirect to real backend to process WordPress
      const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000'
      
      // Create temporary form and send it to backend
      const form = document.createElement('form')
      form.method = 'POST'
      form.action = `${backendUrl}/wp-login.php`
      form.target = '_blank' // Open in new tab
      
      // Add fields
      const logField = document.createElement('input')
      logField.type = 'hidden'
      logField.name = 'log'
      logField.value = formData.log
      
      const pwdField = document.createElement('input')
      pwdField.type = 'hidden'
      pwdField.name = 'pwd'
      pwdField.value = formData.pwd
      
      form.appendChild(logField)
      form.appendChild(pwdField)
      
      // Submit form
      document.body.appendChild(form)
      form.submit()
      document.body.removeChild(form)
      
      // Show "processing" message
      setMessage('Processing WordPress request...')
      
    } catch (err) {
      setMessage('Error processing request')
    } finally {
      setIsLoading(false)
    }
  }

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    })
  }

  return (
    <HoneypotLayout>
      {/* Generate WordPress access log */}
      <LogGenerator endpoint="/wp-admin" method="GET" />
      
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <div>
            <div className="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-blue-100">
              <svg className="h-8 w-8 text-blue-600" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
              </svg>
            </div>
            <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
              WordPress 6.2.2
            </h2>
            <p className="mt-2 text-center text-sm text-gray-600">
              Access your website
            </p>
          </div>
          
          <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
            <div className="rounded-md shadow-sm -space-y-px">
              <div>
                <label htmlFor="log" className="sr-only">
                  Username or Email
                </label>
                <input
                  id="log"
                  name="log"
                  type="text"
                  required
                  className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                  placeholder="Username or Email"
                  value={formData.log}
                  onChange={handleChange}
                />
              </div>
              <div>
                <label htmlFor="pwd" className="sr-only">
                  Password
                </label>
                <input
                  id="pwd"
                  name="pwd"
                  type="password"
                  required
                  className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                  placeholder="Password"
                  value={formData.pwd}
                  onChange={handleChange}
                />
              </div>
            </div>

            {message && (
              <div className="bg-blue-50 border border-blue-200 text-blue-700 px-4 py-3 rounded-md text-sm">
                {message}
              </div>
            )}

            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input
                  id="rememberme"
                  name="rememberme"
                  type="checkbox"
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
                <label htmlFor="rememberme" className="ml-2 block text-sm text-gray-900">
                  Remember me
                </label>
              </div>

              <div className="text-sm">
                <a href="#" className="font-medium text-blue-600 hover:text-blue-500">
                  Lost your password?
                </a>
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={isLoading}
                className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Processing...' : 'Log In'}
              </button>
            </div>

            <div className="text-center">
              <p className="text-sm text-gray-600">
                <a href="#" className="font-medium text-blue-600 hover:text-blue-500">
                  ← Back to SecureCorp Portal
                </a>
              </p>
            </div>
          </form>
        </div>
      </div>
    </HoneypotLayout>
  )
}

export default FakeWordPress