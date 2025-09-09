import { useState } from 'react'
import { useHoneyGuard } from '../../hooks/useHoneyGuard'

const HoneypotExplorer = () => {
  const { 
    admin, api, vulnerabilities, cves, network, cms, files, panels, utilities, webhooks,
    error
  } = useHoneyGuard()
  
  const [activeCategory, setActiveCategory] = useState('admin')
  const [testResults, setTestResults] = useState({})
  const [selectedEndpoint, setSelectedEndpoint] = useState(null)
  const [loadingStates, setLoadingStates] = useState({})

  // No auto-refresh needed - manual refresh button available

  const categories = {
    admin: {
      name: 'Administration',
      icon: '🔐',
      endpoints: [
        { name: 'Administration Panel', endpoint: '/admin/panel', method: 'GET', service: admin.getPanel },
        { name: 'Settings', endpoint: '/admin/settings', method: 'GET', service: admin.getSettings },
        { name: 'Backup', endpoint: '/admin/backup', method: 'GET', service: admin.getBackup },
        { name: 'User Management', endpoint: '/admin/users', method: 'GET', service: admin.getUsers }
      ]
    },
    api: {
      name: 'Fake APIs',
      icon: '🔌',
      endpoints: [
        { name: 'Users API', endpoint: '/api/v1/users', method: 'GET', service: api.getUsers },
        { name: 'Settings API', endpoint: '/api/v1/settings', method: 'GET', service: api.getSettings },
        { name: 'GraphQL', endpoint: '/api/v2/graphql', method: 'POST', service: api.queryGraphQL },
        { name: 'Refresh Auth', endpoint: '/api/v1/auth/refresh', method: 'POST', service: api.refreshAuth },
        { name: 'Payments API', endpoint: '/api/v1/payments', method: 'POST', service: api.processPayment },
        { name: 'API Keys', endpoint: '/api/v1/keys', method: 'GET', service: api.getKeys },
        { name: 'Session Information', endpoint: '/api/v1/session', method: 'GET', service: api.getSession }
      ]
    },
    vulnerabilities: {
      name: 'Vulnerabilities',
      icon: '🕳️',
      endpoints: [
        { name: 'LFI (Local File Inclusion)', endpoint: '/lfi', method: 'GET', service: vulnerabilities.testLFI },
        { name: 'XSS (Cross-Site Scripting)', endpoint: '/xss', method: 'POST', service: vulnerabilities.testXSS },
        { name: 'SQL Injection', endpoint: '/sql', method: 'POST', service: vulnerabilities.testSQLInjection },
        { name: 'SSRF (Server-Side Request Forgery)', endpoint: '/ssrf', method: 'GET', service: vulnerabilities.testSSRF },
        { name: 'XXE (XML External Entity)', endpoint: '/xxe', method: 'POST', service: vulnerabilities.testXXE },
        { name: 'Deserialization', endpoint: '/deserialize', method: 'POST', service: vulnerabilities.testDeserialization },
        { name: 'Path Traversal', endpoint: '/traversal', method: 'GET', service: vulnerabilities.testPathTraversal },
        { name: 'RCE (Remote Code Execution)', endpoint: '/rce', method: 'POST', service: vulnerabilities.testRCE }
      ]
    },
    cves: {
      name: 'CVEs',
      icon: '🚨',
      endpoints: [
        { name: 'CVE-2017-5638 (Struts2 RCE)', endpoint: '/struts2', method: 'POST', service: cves.testStruts2 },
        { name: 'CVE-2022-22965 (Spring4Shell)', endpoint: '/spring', method: 'POST', service: cves.testSpring4Shell },
        { name: 'CVE-2018-7600 (Drupalgeddon2)', endpoint: '/drupal', method: 'POST', service: cves.testDrupalgeddon2 },
        { name: 'CVE-2014-6271 (Shellshock)', endpoint: '/cgi-bin/bash', method: 'POST', service: cves.testShellshock },
        { name: 'CVE-2017-10271 (WebLogic)', endpoint: '/wls-wsat/CoordinatorPortType', method: 'POST', service: cves.testWebLogic },
        { name: 'Apache Path Traversal', endpoint: '/cgi-bin/{filename}', method: 'GET', service: cves.testApachePathTraversal },
        { name: 'CVEs Index', endpoint: '/cves', method: 'GET', service: cves.getIndex },
        { name: 'PHPMyAdmin CVE', endpoint: '/phpmyadmin', method: 'POST', service: cms.testWordPress }
      ]
    },
    network: {
      name: 'Network Services',
      icon: '🌐',
      endpoints: [
        { name: 'Database', endpoint: '/database', method: 'POST', service: network.testDatabase },
        { name: 'FTP', endpoint: '/ftp', method: 'POST', service: network.testFTP },
        { name: 'SSH', endpoint: '/ssh', method: 'POST', service: network.testSSH },
        { name: 'Telnet', endpoint: '/telnet', method: 'POST', service: network.testTelnet },
        { name: 'POP3', endpoint: '/pop3', method: 'POST', service: network.testPOP3 },
        { name: 'IMAP', endpoint: '/imap', method: 'POST', service: network.testIMAP },
        { name: 'SMTP', endpoint: '/smtp/login', method: 'POST', service: network.testSMTP }
      ]
    },
    cms: {
      name: 'CMS & Platforms',
      icon: '📝',
      endpoints: [
        { name: 'WordPress Login', endpoint: '/wp-login.php', method: 'POST', service: cms.testWordPress },
        { name: 'WordPress Admin', endpoint: '/wp-admin', method: 'GET', service: cms.testWordPress },
        { name: 'Joomla', endpoint: '/joomla/administrator', method: 'POST', service: cms.testJoomla },
        { name: 'Drupal', endpoint: '/drupal/user/login', method: 'POST', service: cms.testDrupal },
        { name: 'Magento', endpoint: '/magento/admin', method: 'POST', service: cms.testMagento }
      ]
    },
    files: {
      name: 'Files & Resources',
      icon: '📁',
      endpoints: [
        { name: 'Backup ZIP', endpoint: '/backup.zip', method: 'GET', service: files.getBackupZip },
        { name: 'Config PHP', endpoint: '/config.php', method: 'GET', service: files.getConfigPHP },
        { name: 'Debug Log', endpoint: '/debug.log', method: 'GET', service: files.getDebugLog },
        { name: 'Access Log', endpoint: '/logs/access.log', method: 'GET', service: files.getAccessLog },
        { name: 'Error Log', endpoint: '/logs/error.log', method: 'GET', service: files.getErrorLog },
        { name: 'Leak Files', endpoint: '/leak-{name}.sql', method: 'GET', service: files.getLeakFile },
        { name: 'Secret Files', endpoint: '/secret-{token}.zip', method: 'GET', service: files.getSecretFile }
      ]
    },
    panels: {
      name: 'Panels & Dashboards',
      icon: '📊',
      endpoints: [
        { name: 'Main Dashboard', endpoint: '/dashboard', method: 'GET', service: panels.getDashboard },
        { name: 'Dashboard Files', endpoint: '/dashboard/files', method: 'GET', service: panels.getDashboardFiles },
        { name: 'Dashboard Settings', endpoint: '/dashboard/settings', method: 'GET', service: panels.getDashboardSettings },
        { name: 'Internal Panel', endpoint: '/internal-panel', method: 'GET', service: panels.getInternalPanel },
        { name: 'Webmail', endpoint: '/webmail', method: 'GET', service: panels.getWebmail },
        { name: 'Router Login', endpoint: '/router/login', method: 'GET', service: panels.getRouterLogin },
        { name: 'IoT Status', endpoint: '/iot/status', method: 'GET', service: panels.getIoTStatus }
      ]
    },
    utilities: {
      name: 'Utilities',
      icon: '🛠️',
      endpoints: [
        { name: 'Generate Secret Token', endpoint: '/generate-secret', method: 'GET', service: utilities.generateSecret },
        { name: 'Redirection', endpoint: '/redirect', method: 'GET', service: utilities.testRedirect },
        { name: 'Generic Login', endpoint: '/login', method: 'POST', service: utilities.testLogin },
        { name: 'Home Page', endpoint: '/home', method: 'GET', service: utilities.getHome },
        { name: 'Flag Access', endpoint: '/flag-access', method: 'GET', service: utilities.getFlagAccess },
        { name: 'Stolen Cookie', endpoint: '/stolen-cookie', method: 'GET', service: utilities.getStolenCookie },
        { name: 'Unstable Service', endpoint: '/unstable', method: 'GET', service: utilities.getUnstable },
        { name: 'File Upload', endpoint: '/upload', method: 'POST', service: utilities.uploadFile }
      ]
    },
    webhooks: {
      name: 'Webhooks & WAF',
      icon: '🔗',
      endpoints: [
        { name: 'GitHub Webhook', endpoint: '/webhook/github', method: 'POST', service: webhooks.testGitHubWebhook },
        { name: 'Stripe Webhook', endpoint: '/webhook/stripe', method: 'POST', service: webhooks.testStripeWebhook },
        { name: 'WAF (Web Application Firewall)', endpoint: '/waf', method: 'POST', service: webhooks.testWAF }
      ]
    },
    auth: {
      name: 'Authentication',
      icon: '🔑',
      endpoints: [
        { name: 'Login', endpoint: '/login', method: 'POST', service: utilities.testLogin },
        { name: 'Session Token', endpoint: '/api/v1/session', method: 'GET', service: api.getSession },
        { name: 'Auth Refresh', endpoint: '/api/v1/auth/refresh', method: 'POST', service: api.refreshAuth }
      ]
    }
  }

  const handleTestEndpoint = async (endpoint) => {
    const endpointKey = endpoint.endpoint
    
    try {
      // Set loading state for this specific endpoint
      setLoadingStates(prev => ({ ...prev, [endpointKey]: true }))
      setSelectedEndpoint(endpoint)
      
      const result = await endpoint.service()
      
      setTestResults(prev => ({
        ...prev,
        [endpointKey]: {
          success: true,
          data: result,
          timestamp: new Date().toISOString()
        }
      }))
    } catch (err) {
      setTestResults(prev => ({
        ...prev,
        [endpointKey]: {
          success: false,
          error: err.message,
          timestamp: new Date().toISOString()
        }
      }))
    } finally {
      // Clear loading state for this specific endpoint
      setLoadingStates(prev => ({ ...prev, [endpointKey]: false }))
    }
  }

  const getMethodColor = (method) => {
    switch (method) {
      case 'GET': return 'bg-green-100 text-green-800'
      case 'POST': return 'bg-blue-100 text-blue-800'
      case 'PUT': return 'bg-yellow-100 text-yellow-800'
      case 'DELETE': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const getStatusColor = (success) => {
    return success ? 'text-green-600' : 'text-red-600'
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Honeypot Explorer
          </h1>
          <p className="text-gray-600">
            Explore and test all available honeypot endpoints
          </p>
        </div>
      </div>

      {/* Category Navigation */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Categories</h2>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
            {Object.entries(categories).map(([key, category]) => (
              <button
                key={key}
                onClick={() => setActiveCategory(key)}
                className={`p-4 rounded-lg border-2 transition-colors ${
                  activeCategory === key
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="text-center">
                  <div className="text-2xl mb-2">{category.icon}</div>
                  <div className="text-sm font-medium text-gray-900">{category.name}</div>
                  <div className="text-xs text-gray-500 mt-1">
                    {category.endpoints.length} endpoints
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Endpoints List */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">
            {categories[activeCategory].name} - Endpoints
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            Click "Test" to execute the endpoint
          </p>
        </div>
        <div className="p-6">
          <div className="space-y-4">
            {categories[activeCategory].endpoints.map((endpoint, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-4">
                {/* Header with endpoint info and button */}
                <div className="flex items-center justify-between mb-3">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <h3 className="text-lg font-medium text-gray-900">{endpoint.name}</h3>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getMethodColor(endpoint.method)}`}>
                        {endpoint.method}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mt-1 font-mono">{endpoint.endpoint}</p>
                  </div>
                  
                  <div className="ml-4">
                    <button
                      onClick={() => handleTestEndpoint(endpoint)}
                      disabled={loadingStates[endpoint.endpoint]}
                      className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white px-4 py-2 rounded-md text-sm font-medium transition-colors"
                    >
                      {loadingStates[endpoint.endpoint] ? (
                        <div className="flex items-center space-x-2">
                          <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                          </svg>
                          <span>Loading...</span>
                        </div>
                      ) : (
                        'Test'
                      )}
                    </button>
                  </div>
                </div>
                
                {/* Test Results - Now displayed below */}
                {testResults[endpoint.endpoint] && (
                  <div className="border-t border-gray-100 pt-3">
                    <div className={`flex items-center space-x-2 ${getStatusColor(testResults[endpoint.endpoint].success)}`}>
                      <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                        {testResults[endpoint.endpoint].success ? (
                          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                        ) : (
                          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                        )}
                      </svg>
                      <span className="text-sm font-medium">
                         {testResults[endpoint.endpoint].success ? 'Success' : 'Failed'}
                       </span>
                      <span className="text-xs text-gray-500">
                        {new Date(testResults[endpoint.endpoint].timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    
                    {testResults[endpoint.endpoint].success && (
                      <div className="mt-2 p-3 bg-green-50 border border-green-200 rounded">
                        <p className="text-sm text-green-800">
                           Response received correctly
                         </p>
                        {testResults[endpoint.endpoint].data && (
                          <details className="mt-2">
                            <summary className="text-xs text-green-600 cursor-pointer hover:text-green-700">
                               View response details
                             </summary>
                            <pre className="mt-2 text-xs text-green-700 bg-green-100 p-2 rounded overflow-auto max-h-64">
                              {JSON.stringify(testResults[endpoint.endpoint].data, null, 2)}
                            </pre>
                          </details>
                        )}
                      </div>
                    )}
                    
                    {!testResults[endpoint.endpoint].success && (
                      <div className="mt-2 p-3 bg-red-50 border border-red-200 rounded">
                        <p className="text-sm text-red-800">
                          Error: {testResults[endpoint.endpoint].error}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <div className="mt-2 text-sm text-red-700">
                <p>{error}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default HoneypotExplorer