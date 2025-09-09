import axios from 'axios'

// Base axios configuration
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Interceptor to add authentication token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Interceptor to handle errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error)
    return Promise.reject(error)
  }
)

// ============================================================================
// LOGS AND ANALYSIS SERVICES
// ============================================================================

export const logsService = {
  // Get all logs
  getAllLogs: async () => {
    const response = await api.get('/logs')
    return response.data
  },

  // Get logs analysis
  getAnalysis: async () => {
    const response = await api.get('/logs/analysis')
    return response.data
  },

  // Get logs by fingerprint
  getLogsByFingerprint: async (fingerprint, ip = null) => {
    const params = { fingerprint }
    if (ip) params.ip = ip
    const response = await api.get('/logs/by_fingerprint', { params })
    return response.data
  },

  // Get fingerprint information
  getFingerprintInfo: async (fingerprint) => {
    const response = await api.get(`/logs/fingerprint_info/${fingerprint}`)
    return response.data
  },

  // Get unique fingerprints
  getUniqueFingerprints: async () => {
    const response = await api.get('/logs/fingerprints_unicos')
    return response.data
  },
}

// ============================================================================
// SANDBOX AND MALWARE ANALYSIS SERVICES
// ============================================================================

export const sandboxService = {
  // Unified upload endpoint with complete analysis
  upload: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await fetch(`${API_BASE_URL}/upload`, {
      method: 'POST',
      body: formData,
    });
    
    if (!response.ok) {
      throw new Error(`Upload error: ${response.status}`);
    }
    
    return response.json();
  },

  // Get analysis status
  getStatus: async (fileHash) => {
    const response = await fetch(`${API_BASE_URL}/sandbox/status/${fileHash}`);
    
    if (!response.ok) {
      throw new Error(`Error getting status: ${response.status}`);
    }
    
    return response.json();
  },

  // Get complete analysis report
  getReport: async (fileHash) => {
    const response = await fetch(`${API_BASE_URL}/sandbox/report/${fileHash}`);
    
    if (!response.ok) {
      throw new Error(`Error getting report: ${response.status}`);
    }
    
    return response.json();
  },

  // Scan content (separate endpoint for text scanning)
  scan: async (content) => {
    const response = await fetch(`${API_BASE_URL}/sandbox/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
      },
      body: content,
    });
    
    if (!response.ok) {
      throw new Error(`Scan error: ${response.status}`);
    }
    
    return response.json();
  },

  // Get analysis history
  getAnalysisHistory: async () => {
    const response = await api.get('/sandbox/history')
    return response.data
  },

  // Get analysis statistics
  getAnalysisStats: async () => {
    const response = await api.get('/sandbox/stats')
    return response.data
  },
}

// ============================================================================
// STATISTICS AND DASHBOARD SERVICES
// ============================================================================

export const statsService = {
  // Get general statistics
  getGeneralStats: async () => {
    const response = await api.get('/logs/analysis')
    return response.data.general_stats || {}
  },

  // Get attack distribution
  getAttackDistribution: async () => {
    const response = await api.get('/logs/analysis')
    return response.data.attack_distribution || {}
  },

  // Get top attackers
  getTopAttackers: async () => {
    const response = await api.get('/logs/analysis')
    return response.data.top_attackers || {}
  },



  // Get uploaded files statistics
  getUploadedFilesStats: async () => {
    const response = await api.get('/uploads')
    return response.data.summary || {}
  },
}

// ============================================================================
// REAL-TIME LOGS SERVICES
// ============================================================================

export const realtimeService = {
  // Get recent logs (last 10)
  getRecentLogs: async (limit = 10) => {
    const response = await api.get('/logs')
    const logs = response.data
    return logs.slice(0, limit)
  },

  // Get today's logs
  getTodayLogs: async () => {
    const response = await api.get('/logs')
    const logs = response.data
    const today = new Date().toISOString().split('T')[0]
    return logs.filter(log => log.timestamp && log.timestamp.startsWith(today))
  },
}

// ============================================================================
// HONEYPOT SERVICES - ADMINISTRATION
// ============================================================================

export const adminHoneypotService = {
  // Main administration panel
  getAdminPanel: async () => {
    const response = await api.get('/admin/panel')
    return response.data
  },

  // Administration settings
  getAdminSettings: async () => {
    const response = await api.get('/admin/settings')
    return response.data
  },

  // Administration backup
  getAdminBackup: async () => {
    const response = await api.get('/admin/backup')
    return response.data
  },

  // User management
  getAdminUsers: async () => {
    const response = await api.get('/admin/users')
    return response.data
  },
}

// ============================================================================
// HONEYPOT SERVICES - FAKE APIs
// ============================================================================

export const apiHoneypotService = {
  // Users API
  getApiUsers: async () => {
    const response = await api.get('/api/v1/users')
    return response.data
  },

  // Configurations API
  getApiSettings: async () => {
    const response = await api.get('/api/v1/settings')
    return response.data
  },

  // API GraphQL
  queryGraphQL: async (query) => {
    const response = await api.post('/api/v2/graphql', { query })
    return response.data
  },

  // Authentication refresh
  refreshAuth: async (refreshToken) => {
    const response = await api.post('/api/v1/auth/refresh', { refresh_token: refreshToken })
    return response.data
  },

  // Payments API
  processPayment: async (paymentData) => {
    const response = await api.post('/api/v1/payments', paymentData)
    return response.data
  },

  // API keys
  getApiKeys: async () => {
    const response = await api.get('/api/v1/keys')
    return response.data
  },

  // Session API
  getSessionInfo: async () => {
    const response = await api.get('/api/v1/session')
    return response.data
  },
}

// ============================================================================
// HONEYPOT SERVICES - VULNERABILITIES
// ============================================================================

export const vulnerabilityHoneypotService = {
  // LFI (Local File Inclusion)
  testLFI: async (path) => {
    const response = await api.get('/lfi', { params: { file: path } })
    return response.data
  },

  // XSS (Cross-Site Scripting)
  testXSS: async (payload) => {
    const response = await api.post('/xss', { input: payload })
    return response.data
  },

  // SQL Injection
  testSQLInjection: async (query) => {
    const response = await api.post('/sql', { query })
    return response.data
  },

  // SSRF (Server-Side Request Forgery)
  testSSRF: async (url) => {
    const response = await api.get('/ssrf', { params: { url } })
    return response.data
  },

  // XXE (XML External Entity)
  testXXE: async (xmlData) => {
    const response = await api.post('/xxe', { xml: xmlData })
    return response.data
  },

  // Deserialization
  testDeserialization: async (data) => {
    const response = await api.post('/deserialize', { data })
    return response.data
  },

  // Path Traversal
  testPathTraversal: async (path) => {
    const response = await api.get('/traversal', { params: { file: path } })
    return response.data
  },

  // RCE (Remote Code Execution)
  testRCE: async (command) => {
    const response = await api.post('/rce', { command })
    return response.data
  },
}

// ============================================================================
// HONEYPOT SERVICES - CVEs
// ============================================================================

export const cveHoneypotService = {
  // CVE-2017-5638: Apache Struts2 RCE
  testStruts2: async (payload) => {
    const response = await api.post('/struts2', payload, {
      headers: { 'Content-Type': payload.contentType || 'application/x-www-form-urlencoded' }
    })
    return response.data
  },

  // CVE-2022-22965: Spring4Shell
  testSpring4Shell: async (payload) => {
    const response = await api.post('/spring', payload)
    return response.data
  },

  // CVE-2018-7600: Drupalgeddon2
  testDrupalgeddon2: async (payload) => {
    const response = await api.post('/drupal', payload)
    return response.data
  },

  // CVE-2014-6271: Shellshock
  testShellshock: async (payload) => {
    const response = await api.post('/cgi-bin/bash', payload, {
      headers: { 'User-Agent': payload.userAgent || '() { :; }; echo "Shellshock Test"' }
    })
    return response.data
  },

  // CVE-2017-10271: WebLogic
  testWebLogic: async (payload) => {
    const response = await api.post('/wls-wsat/CoordinatorPortType', payload, {
      headers: { 'Content-Type': 'text/xml' }
    })
    return response.data
  },

  // Apache path traversal
  testApachePathTraversal: async (filename) => {
    const response = await api.get(`/cgi-bin/${filename}`)
    return response.data
  },

  // CVE index
  getCvesIndex: async () => {
    const response = await api.get('/cves')
    return response.data
  },
}

// ============================================================================
// HONEYPOT SERVICES - NETWORK SERVICES
// ============================================================================

export const networkHoneypotService = {
  // Database
  testDatabase: async (query) => {
    const response = await api.post('/database', { query })
    return response.data
  },

  // FTP
  testFTP: async (credentials) => {
    const response = await api.post('/ftp', credentials)
    return response.data
  },

  // SSH
  testSSH: async (credentials) => {
    const response = await api.post('/ssh', credentials)
    return response.data
  },

  // Telnet
  testTelnet: async (credentials) => {
    const response = await api.post('/telnet', credentials)
    return response.data
  },

  // POP3
  testPOP3: async (credentials) => {
    const response = await api.post('/pop3', credentials)
    return response.data
  },

  // IMAP
  testIMAP: async (credentials) => {
    const response = await api.post('/imap', credentials)
    return response.data
  },

  // SMTP
  testSMTP: async (credentials) => {
    const response = await api.post('/smtp/login', credentials)
    return response.data
  },
}

// ============================================================================
// HONEYPOT SERVICES - CMS AND PLATFORMS
// ============================================================================

export const cmsHoneypotService = {
  // WordPress
  testWordPress: async (credentials) => {
    const response = await api.post('/wp-login.php', credentials)
    return response.data
  },

  // Joomla
  testJoomla: async (credentials) => {
    const response = await api.post('/joomla/administrator', credentials)
    return response.data
  },

  // Drupal
  testDrupal: async (credentials) => {
    const response = await api.post('/drupal/user/login', credentials)
    return response.data
  },

  // Magento
  testMagento: async (credentials) => {
    const response = await api.post('/magento/admin', credentials)
    return response.data
  },
}

// ============================================================================
// HONEYPOT SERVICES - FILES AND RESOURCES
// ============================================================================

export const fileHoneypotService = {
  // Backup ZIP
  getBackupZip: async () => {
    const response = await api.get('/backup.zip')
    return response.data
  },

  // Config PHP
  getConfigPHP: async () => {
    const response = await api.get('/config.php')
    return response.data
  },

  // Debug log
  getDebugLog: async () => {
    const response = await api.get('/debug.log')
    return response.data
  },

  // Access log
  getAccessLog: async () => {
    const response = await api.get('/logs/access.log')
    return response.data
  },

  // Error log
  getErrorLog: async () => {
    const response = await api.get('/logs/error.log')
    return response.data
  },

  // Leak files
  getLeakFile: async (name) => {
    const response = await api.get(`/leak-${name}.sql`)
    return response.data
  },

  // Secret file
  getSecretFile: async (token) => {
    const response = await api.get(`/secret-${token}.zip`)
    return response.data
  },
}

// ============================================================================
// HONEYPOT SERVICES - PANELS AND DASHBOARDS
// ============================================================================

export const panelHoneypotService = {
  // Main dashboard
  getDashboard: async () => {
    const response = await api.get('/dashboard')
    return response.data
  },

  // Dashboard files
  getDashboardFiles: async () => {
    const response = await api.get('/dashboard/files')
    return response.data
  },

  // Dashboard configurations
  getDashboardSettings: async () => {
    const response = await api.get('/dashboard/settings')
    return response.data
  },

  // Internal panel
  getInternalPanel: async () => {
    const response = await api.get('/internal-panel')
    return response.data
  },

  // Webmail
  getWebmail: async () => {
    const response = await api.get('/webmail')
    return response.data
  },

  // Router login
  getRouterLogin: async () => {
    const response = await api.get('/router/login')
    return response.data
  },

  // IoT status
  getIoTStatus: async () => {
    const response = await api.get('/iot/status')
    return response.data
  },
}

// ============================================================================
// HONEYPOT SERVICES - UTILITIES AND MISCELLANEOUS
// ============================================================================

export const utilityHoneypotService = {
  // Generate secret token
  generateSecret: async () => {
    const response = await api.get('/generate-secret')
    return response.data
  },

  // Redirection
  testRedirect: async (url) => {
    const response = await api.get('/redirect', { params: { url } })
    return response.data
  },

  // Generic login
  testLogin: async (credentials) => {
    const response = await api.post('/login', credentials)
    return response.data
  },

  // Home page
  getHome: async () => {
    const response = await api.get('/home')
    return response.data
  },

  // Flag access
  getFlagAccess: async () => {
    const response = await api.get('/flag-access')
    return response.data
  },

  // Stolen cookie
  getStolenCookie: async () => {
    const response = await api.get('/stolen-cookie')
    return response.data
  },

  // Unstable service
  getUnstable: async () => {
    const response = await api.get('/unstable')
    return response.data
  },
}

// ============================================================================
// HONEYPOT SERVICES - WEBHOOKS AND WAF
// ============================================================================

export const webhookHoneypotService = {
  // GitHub webhook
  testGitHubWebhook: async (payload) => {
    const response = await api.post('/webhook/github', payload)
    return response.data
  },

  // Stripe webhook
  testStripeWebhook: async (payload) => {
    const response = await api.post('/webhook/stripe', payload)
    return response.data
  },

  // WAF (Web Application Firewall)
  testWAF: async (payload) => {
    const response = await api.post('/waf', payload)
    return response.data
  },
}

// ============================================================================
// UNIFIED MAIN SERVICE
// ============================================================================

export const honeyGuardService = {
  // Logs and analysis
  logs: logsService,
  
  // Sandbox and malware (consolidated)
  sandbox: sandboxService,
  
  // Statistics (corrected name to avoid collision)
  statsServices: statsService,
  
  // Real time
  realtime: realtimeService,
  
  // Honeypots by category
  admin: adminHoneypotService,
  api: apiHoneypotService,
  vulnerabilities: vulnerabilityHoneypotService,
  cves: cveHoneypotService,
  network: networkHoneypotService,
  cms: cmsHoneypotService,
  files: fileHoneypotService,
  panels: panelHoneypotService,
  utilities: utilityHoneypotService,
  webhooks: webhookHoneypotService,
}

export default api