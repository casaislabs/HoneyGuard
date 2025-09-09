import { useState } from 'react'
import HoneypotLayout from '../../components/layout/HoneypotLayout'
import LogGenerator from '../../components/honeypot/LogGenerator'

const FakeAdmin = () => {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  })
  const [isLoading, setIsLoading] = useState(false)
  const [message, setMessage] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setIsLoading(true)
    setMessage('')

    try {
      // Redirect to real backend to process admin request
      const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000'
      
      // Create temporary form and send to backend
      const form = document.createElement('form')
      form.method = 'POST'
      form.action = `${backendUrl}/admin`
      form.target = '_blank' // Open in new tab
      
      // Add fields
      const usernameField = document.createElement('input')
      usernameField.type = 'hidden'
      usernameField.name = 'username'
      usernameField.value = formData.username
      
      const passwordField = document.createElement('input')
      passwordField.type = 'hidden'
      passwordField.name = 'password'
      passwordField.value = formData.password
      
      form.appendChild(usernameField)
      form.appendChild(passwordField)
      
      // Submit form
      document.body.appendChild(form)
      form.submit()
      document.body.removeChild(form)
      
      // Show "processing" message
      setMessage('Processing administration request...')
      
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
      {/* Generate admin access log */}
      <LogGenerator endpoint="/admin" method="GET" />
      
      <div className="bg-white rounded-lg shadow-sm p-8">
        <div className="text-center">
          <div className="mx-auto h-16 w-16 flex items-center justify-center rounded-full bg-red-100 mb-4">
            <svg className="h-8 w-8 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          
          <h1 className="text-3xl font-bold text-gray-900 mb-4">
            Administration Panel - v2.3.1
          </h1>
          <p className="text-gray-600 mb-8">
            Enterprise Management System
          </p>
          
          <form className="max-w-md mx-auto space-y-4" onSubmit={handleSubmit}>
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                Username:
              </label>
              <input
                type="text"
                id="username"
                name="username"
                required
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                value={formData.username}
                onChange={handleChange}
              />
            </div>
            
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                Password:
              </label>
              <input
                type="password"
                id="password"
                name="password"
                required
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                value={formData.password}
                onChange={handleChange}
              />
            </div>
            
            {message && (
              <div className="bg-blue-50 border border-blue-200 text-blue-700 px-4 py-3 rounded-md text-sm">
                {message}
              </div>
            )}
            
            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded-md font-medium disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Processing...' : 'Sign In'}
            </button>
          </form>
          
          <div className="mt-8 text-sm text-gray-500">
            <p>Status: Available</p>
            <p>Last update: {new Date().toLocaleString()}</p>
          </div>
        </div>
      </div>
    </HoneypotLayout>
  )
}

export default FakeAdmin