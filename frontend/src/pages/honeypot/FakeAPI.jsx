import { useState } from 'react'
import HoneypotLayout from '../../components/layout/HoneypotLayout'
import LogGenerator from '../../components/honeypot/LogGenerator'

const FakeAPI = () => {
  const [activeTab, setActiveTab] = useState('users')
  const [response, setResponse] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [testData, setTestData] = useState({
    users: { id: '1', name: 'John Doe', email: 'john@example.com' },
    settings: { theme: 'dark', language: 'en', notifications: true },
    payments: { amount: '100.00', currency: 'USD', description: 'Test payment' }
  })

  const endpoints = {
    users: {
      url: '/api/v1/users',
      method: 'GET',
      description: 'Get user information',
      parameters: ['id', 'name', 'email'],
      example: '/api/v1/users?id=1'
    },
    settings: {
      url: '/api/v1/settings',
      method: 'GET',
      description: 'Get application settings',
      parameters: ['theme', 'language', 'notifications'],
      example: '/api/v1/settings?theme=dark'
    },
    payments: {
      url: '/api/v1/payments',
      method: 'POST',
      description: 'Process payment transactions',
      parameters: ['amount', 'currency', 'description'],
      example: 'POST /api/v1/payments'
    },
    auth: {
      url: '/api/v1/auth/refresh',
      method: 'POST',
      description: 'Refresh authentication token',
      parameters: ['token', 'expires'],
      example: 'POST /api/v1/auth/refresh'
    },
    session: {
      url: '/api/v1/session',
      method: 'GET',
      description: 'Get current session information',
      parameters: ['user_id', 'session_id', 'expires'],
      example: '/api/v1/session'
    },
    keys: {
      url: '/api/v1/keys',
      method: 'GET',
      description: 'Get API keys and credentials',
      parameters: ['key_id', 'permissions', 'expires'],
      example: '/api/v1/keys'
    }
  }

  const handleTestEndpoint = async (endpointKey) => {
    setIsLoading(true)
    setResponse(null)

    const endpoint = endpoints[endpointKey]
    const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000'
    
    try {
      let url = `${backendUrl}${endpoint.url}`
      
      if (endpoint.method === 'GET') {
        // For GET, add example parameters
        const params = new URLSearchParams()
        Object.entries(testData[endpointKey] || {}).forEach(([key, value]) => {
          params.append(key, value)
        })
        if (params.toString()) {
          url += `?${params.toString()}`
        }
      }

      const response = await fetch(url, {
        method: endpoint.method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer fake-token-12345',
          'X-API-Key': 'sk_test_1234567890abcdef'
        },
        body: endpoint.method === 'POST' ? JSON.stringify(testData[endpointKey] || {}) : undefined
      })

      const data = await response.text()
      
      setResponse({
        status: response.status,
        statusText: response.statusText,
        data: data,
        url: url,
        method: endpoint.method
      })

    } catch (error) {
      setResponse({
        status: 'ERROR',
        statusText: 'Network Error',
        data: error.message,
        url: `${backendUrl}${endpoint.url}`,
        method: endpoint.method
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleInputChange = (endpointKey, field, value) => {
    setTestData(prev => ({
      ...prev,
      [endpointKey]: {
        ...prev[endpointKey],
        [field]: value
      }
    }))
  }

  return (
    <HoneypotLayout>
      {/* Generate API access log */}
      <LogGenerator endpoint="/api/v1/users" method="GET" />
      
      <div className="max-w-6xl mx-auto p-6">
        <div className="bg-white rounded-lg shadow-lg">
          {/* Header */}
          <div className="border-b border-gray-200 px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-bold text-gray-900">API Documentation</h1>
                <p className="text-gray-600">SecureCorp REST API v1.0</p>
              </div>
              <div className="flex items-center space-x-2">
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  Production
                </span>
                <span className="text-sm text-gray-500">Base URL: /api/v1</span>
              </div>
            </div>
          </div>

          <div className="flex">
            {/* Sidebar */}
            <div className="w-64 border-r border-gray-200">
              <nav className="p-4">
                <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-3">
                  Endpoints
                </h3>
                <ul className="space-y-1">
                  {Object.entries(endpoints).map(([key, endpoint]) => (
                    <li key={key}>
                      <button
                        onClick={() => setActiveTab(key)}
                        className={`w-full text-left px-3 py-2 text-sm rounded-md transition-colors ${
                          activeTab === key
                            ? 'bg-blue-100 text-blue-700'
                            : 'text-gray-700 hover:bg-gray-100'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span>{endpoint.url.split('/').pop()}</span>
                          <span className={`text-xs px-2 py-1 rounded ${
                            endpoint.method === 'GET' ? 'bg-green-100 text-green-700' :
                            endpoint.method === 'POST' ? 'bg-blue-100 text-blue-700' :
                            'bg-gray-100 text-gray-700'
                          }`}>
                            {endpoint.method}
                          </span>
                        </div>
                      </button>
                    </li>
                  ))}
                </ul>
              </nav>
            </div>

            {/* Main content */}
            <div className="flex-1 p-6">
              {activeTab && endpoints[activeTab] && (
                <div>
                  <div className="mb-6">
                    <h2 className="text-xl font-semibold text-gray-900 mb-2">
                      {endpoints[activeTab].url}
                    </h2>
                    <p className="text-gray-600 mb-4">
                      {endpoints[activeTab].description}
                    </p>
                    
                    <div className="bg-gray-50 rounded-lg p-4 mb-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-medium text-gray-700">Example Request</span>
                        <span className={`text-xs px-2 py-1 rounded ${
                          endpoints[activeTab].method === 'GET' ? 'bg-green-100 text-green-700' :
                          'bg-blue-100 text-blue-700'
                        }`}>
                          {endpoints[activeTab].method}
                        </span>
                      </div>
                      <code className="text-sm text-gray-800 font-mono">
                        {endpoints[activeTab].example}
                      </code>
                    </div>

                    {/* Parameters */}
                    <div className="mb-6">
                      <h3 className="text-sm font-medium text-gray-700 mb-3">Parameters</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {endpoints[activeTab].parameters.map(param => (
                          <div key={param} className="flex items-center space-x-3">
                            <input
                              type="text"
                              placeholder={param}
                              value={testData[activeTab]?.[param] || ''}
                              onChange={(e) => handleInputChange(activeTab, param, e.target.value)}
                              className="flex-1 px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                            <span className="text-xs text-gray-500 w-16">{param}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Test button */}
                    <button
                      onClick={() => handleTestEndpoint(activeTab)}
                      disabled={isLoading}
                      className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {isLoading ? 'Testing...' : 'Test Endpoint'}
                    </button>
                  </div>

                  {/* Response */}
                  {response && (
                    <div className="border-t border-gray-200 pt-6">
                      <h3 className="text-sm font-medium text-gray-700 mb-3">Response</h3>
                      <div className="bg-gray-50 rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-medium text-gray-700">Status</span>
                          <span className={`text-xs px-2 py-1 rounded ${
                            response.status === 200 ? 'bg-green-100 text-green-700' :
                            response.status >= 400 ? 'bg-red-100 text-red-700' :
                            'bg-yellow-100 text-yellow-700'
                          }`}>
                            {response.status} {response.statusText}
                          </span>
                        </div>
                        <div className="mb-2">
                          <span className="text-sm font-medium text-gray-700">URL: </span>
                          <span className="text-sm text-gray-600 font-mono">{response.url}</span>
                        </div>
                        <div className="mb-2">
                          <span className="text-sm font-medium text-gray-700">Method: </span>
                          <span className="text-sm text-gray-600">{response.method}</span>
                        </div>
                        <div>
                          <span className="text-sm font-medium text-gray-700">Response: </span>
                          <pre className="mt-2 text-sm text-gray-800 bg-white p-3 rounded border overflow-x-auto">
                            {response.data}
                          </pre>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Security Notice */}
        <div className="mt-6 bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-yellow-800">
                Security Notice
              </h3>
              <div className="mt-2 text-sm text-yellow-700">
                <p>
                  This API is for testing purposes only. All requests are logged and monitored for security analysis.
                  Do not use real credentials or sensitive data.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </HoneypotLayout>
  )
}

export default FakeAPI