import { useDashboard } from '../../hooks/useDashboard'
import { formatTimeAgo } from '../../utils/formatters'
import { useNavigate } from 'react-router-dom'

// Generate fake data for the fake dashboard
const FAKE_STATS = {
  users: Math.floor(Math.random() * 10) + 5,
  sessions: Math.floor(Math.random() * 30) + 10,
  uptime: `${(Math.random() * 10 + 90).toFixed(2)}%`,
  alerts: Math.floor(Math.random() * 5) + 1
};

const FAKE_ACTIVITY = [
  { message: 'Blocked suspicious IP 185.23.44.12', user: 'system', time: '2 min ago', status: 'success' },
  { message: 'Malware sample uploaded', user: 'analyst', time: '5 min ago', status: 'warning' },
  { message: 'Brute force attempt detected', user: 'system', time: '10 min ago', status: 'danger' },
  { message: 'New admin login from 91.200.12.1', user: 'admin', time: '15 min ago', status: 'success' },
  { message: 'XSS attack blocked', user: 'system', time: '20 min ago', status: 'success' },
];

const FakeDashboard = () => {
  const navigate = useNavigate();
  const { 
    systemStatus, 
    files,
    settings,
    loading, 
    error, 
    lastUpdate, 
    backendStatus,
    currentPage,
    refreshData
  } = useDashboard()

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading honeypot dashboard...</p>
        </div>
      </div>
    )
  }

  // Render files page
  if (currentPage === 'files') {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="px-4 py-6 sm:px-0">
          {/* Header */}
          <div className="mb-8">
            <div className="flex justify-between items-center">
              <div>
                <button
                  onClick={() => navigate('/dashboard')}
                  className="text-blue-600 hover:text-blue-800 mb-2"
                >
                  ← Back to Dashboard
                </button>
                <h1 className="text-3xl font-bold text-gray-900">📁 File Management</h1>
                <p className="text-gray-600">Available system files</p>
              </div>
              <div className="flex items-center space-x-4">
                <div className={`px-3 py-1 rounded-full text-sm font-medium ${
                  backendStatus === 'online' ? 'bg-green-100 text-green-800' : 
                  backendStatus === 'offline' ? 'bg-red-100 text-red-800' : 
                  'bg-yellow-100 text-yellow-800'
                }`}>
                  Backend: {backendStatus}
                </div>
              </div>
            </div>
          </div>

          {/* Files table */}
          <div className="bg-white shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        File Name
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Size
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Date
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Type
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {files?.map((file, index) => (
                      <tr key={index}>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <a href={`/${file.name}`} className="text-blue-600 hover:text-blue-900 font-mono">
                            {file.name}
                          </a>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{file.size}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{file.date}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{file.type}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  // Render configuration page
  if (currentPage === 'settings') {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="px-4 py-6 sm:px-0">
          {/* Header */}
          <div className="mb-8">
            <div className="flex justify-between items-center">
              <div>
                <button
                  onClick={() => navigate('/dashboard')}
                  className="text-blue-600 hover:text-blue-800 mb-2"
                >
                  ← Back to Dashboard
                </button>
                <h1 className="text-3xl font-bold text-gray-900">⚙️ System Settings</h1>
                <p className="text-gray-600">System parameters</p>
              </div>
              <div className="flex items-center space-x-4">
                <div className={`px-3 py-1 rounded-full text-sm font-medium ${
                  backendStatus === 'online' ? 'bg-green-100 text-green-800' : 
                  backendStatus === 'offline' ? 'bg-red-100 text-red-800' : 
                  'bg-yellow-100 text-yellow-800'
                }`}>
                  Backend: {backendStatus}
                </div>
              </div>
            </div>
          </div>

          {/* Warning */}
          <div className="mb-6 bg-yellow-50 border border-yellow-200 rounded-md p-4">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-yellow-800">Sensitive Information</h3>
                <p className="text-sm text-yellow-700 mt-1">
                  These parameters are sensitive. Do not share this information.
                </p>
              </div>
            </div>
          </div>

          {/* Configuration table */}
          <div className="bg-white shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Parameter
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Value
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {settings && Object.entries(settings).map(([key, value]) => (
                      <tr key={key}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {key.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {key.includes('mode') ? (
                            <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">
                              {value}
                            </span>
                          ) : key.includes('key') || key.includes('url') ? (
                            <code className="text-sm bg-gray-100 px-2 py-1 rounded">
                              {value}
                            </code>
                          ) : (
                            <span className="text-sm text-gray-900">{value}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  // Main dashboard page
  if (currentPage === 'upload') {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center">
        <h1 className="text-3xl font-bold text-gray-900 mb-4">File Upload</h1>
        <p className="text-gray-600 mb-8">Upload new files to the honeypot (simulated).</p>
        <button onClick={() => navigate('/dashboard')} className="text-blue-600 hover:text-blue-800 mb-2">← Back to Dashboard</button>
        {/* You can add a real upload form here if needed */}
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="px-4 py-6 sm:px-0">
        {/* Header with backend status */}
        <div className="mb-8">
          <div className="flex justify-between items-center">
            <h1 className="text-3xl font-bold text-gray-900">🛡️ Admin Dashboard</h1>
            <div className="flex items-center space-x-4">
              <div className={`px-3 py-1 rounded-full text-sm font-medium ${
                backendStatus === 'online' ? 'bg-green-100 text-green-800' : 
                backendStatus === 'offline' ? 'bg-red-100 text-red-800' : 
                'bg-yellow-100 text-yellow-800'
              }`}>
                Backend: {backendStatus}
              </div>
              <button
                onClick={refreshData}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
              >
                Refresh
              </button>
            </div>
          </div>
          {lastUpdate && (
            <p className="text-sm text-gray-500 mt-2">
              Last update: {formatTimeAgo(lastUpdate)}
            </p>
          )}
        </div>

        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 rounded-md p-4">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-800">Connection Error</h3>
                <p className="text-sm text-red-700 mt-1">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Honeypot Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <svg className="h-6 w-6 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                  </svg>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Active Users</dt>
                    <dd className="text-lg font-medium text-gray-900">{FAKE_STATS.users}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <svg className="h-6 w-6 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Sessions</dt>
                    <dd className="text-lg font-medium text-gray-900">{FAKE_STATS.sessions}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <svg className="h-6 w-6 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Uptime</dt>
                    <dd className="text-lg font-medium text-gray-900">{FAKE_STATS.uptime}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <svg className="h-6 w-6 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Alerts</dt>
                    <dd className="text-lg font-medium text-gray-900">{FAKE_STATS.alerts}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* System Navigation */}
        <div className="bg-white shadow rounded-lg mb-8">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">🔧 System Navigation</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <button
                onClick={() => navigate('/admin')}
                className="flex items-center p-4 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors"
              >
                <span className="text-2xl mr-3">🛡️</span>
                <div className="text-left">
                  <h4 className="font-medium text-gray-900">Admin Panel</h4>
                  <p className="text-sm text-gray-600">Manage honeypot settings</p>
                </div>
              </button>
              <button
                onClick={() => navigate('/sandbox')}
                className="flex items-center p-4 bg-orange-50 hover:bg-orange-100 rounded-lg transition-colors"
              >
                <span className="text-2xl mr-3">🧪</span>
                <div className="text-left">
                  <h4 className="font-medium text-gray-900">Malware Sandbox</h4>
                  <p className="text-sm text-gray-600">Analyze suspicious files</p>
                </div>
              </button>
              <button
                onClick={() => navigate('/wp-admin')}
                className="flex items-center p-4 bg-purple-50 hover:bg-purple-100 rounded-lg transition-colors"
              >
                <span className="text-2xl mr-3">📝</span>
                <div className="text-left">
                  <h4 className="font-medium text-gray-900">WordPress Admin</h4>
                  <p className="text-sm text-gray-600">Simulate WP attacks</p>
                </div>
              </button>
              <button
                onClick={() => navigate('/api-docs')}
                className="flex items-center p-4 bg-green-50 hover:bg-green-100 rounded-lg transition-colors"
              >
                <span className="text-2xl mr-3">📖</span>
                <div className="text-left">
                  <h4 className="font-medium text-gray-900">API Docs</h4>
                  <p className="text-sm text-gray-600">Explore fake API</p>
                </div>
              </button>
            </div>
          </div>
        </div>

        {/* System Status */}
        <div className="bg-white shadow rounded-lg mb-8">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">System Status</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {systemStatus && Object.entries(systemStatus).map(([service, status]) => (
                <div key={service} className="flex items-center">
                  <div className={`w-3 h-3 rounded-full mr-3 ${
                    status === 'online' ? 'bg-green-400' : 'bg-red-400'
                  }`}></div>
                  <span className="text-sm font-medium text-gray-900 capitalize">
                    {service.replace('_', ' ')}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-white shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">Recent Activity</h3>
            <div className="space-y-4">
              {FAKE_ACTIVITY.map((activity, index) => (
                <div key={index} className="flex items-start space-x-3">
                  <div className={`flex-shrink-0 w-2 h-2 rounded-full mt-2 ${
                    activity.status === 'success' ? 'bg-green-400' : 
                    activity.status === 'warning' ? 'bg-yellow-400' : 'bg-red-400'
                  }`}></div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900">{activity.message}</p>
                    <p className="text-sm text-gray-500">
                      {activity.user} • {activity.time}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default FakeDashboard