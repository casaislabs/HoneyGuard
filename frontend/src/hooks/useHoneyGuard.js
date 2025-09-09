import { useState, useCallback, useEffect, useRef } from 'react'
import { honeyGuardService, logsService, realtimeService } from '../services/api'

export const useHoneyGuard = () => {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [stats, setStats] = useState({
    totalAttacks: 0,
    uniqueIPs: 0,
    todayAttacks: 0,
    uploadedFiles: 0
  })
  const [recentLogs, setRecentLogs] = useState([])
  const [analysisData, setAnalysisData] = useState(null)

  // Ref to avoid multiple executions
  const hasLoaded = useRef(false)

  // Debug: Log initial state
  console.log('🏁 Hook initialized with stats:', stats)

  // Monitor state changes
  useEffect(() => {
    console.log('📊 Stats state changed to:', stats)
  }, [stats])

  useEffect(() => {
    console.log('📝 RecentLogs state changed to:', recentLogs.length, 'elements')
  }, [recentLogs])

  // Load initial data and set up auto-refresh
  useEffect(() => {
    if (hasLoaded.current) {
      console.log('⏭️  Data already loaded, skipping...')
      return
    }
    
    console.log('🔄 Starting data loading...')
    hasLoaded.current = true
    
    const loadData = () => {
      setLoading(true)
      
      // Load data using configured services
      Promise.all([
        logsService.getAnalysis(),
        realtimeService.getRecentLogs(10),
        honeyGuardService.statsServices.getUploadedFilesStats()
      ])
      .then(([analysisDataResponse, logsData, uploadsStats]) => {
        console.log('📈 Analysis data:', analysisDataResponse)
        console.log('📝 Logs loaded:', logsData.length)
        console.log('📁 Uploads stats:', uploadsStats)
        
        const generalStats = analysisDataResponse.general_stats || {}
        const newStats = {
          totalAttacks: generalStats.total_logs || 0,
          uniqueIPs: generalStats.unique_ips || 0,
          todayAttacks: generalStats.today_logs || 0,
          uploadedFiles: uploadsStats.total_files || 0
        }
        
        console.log('📊 Final statistics:', newStats)
        setStats(newStats)
        setRecentLogs(logsData || [])
        setAnalysisData(analysisDataResponse)
        setLoading(false)
        console.log('✅ Data loaded successfully')
      })
      .catch(err => {
        console.error('❌ Error loading data:', err)
        setError(err.message || 'Unknown error')
        setLoading(false)
      })
    }
    
    // Load initial data
    loadData()
    
    return () => {
      console.log('🧹 Cleaning up HoneyGuard hook')
    }
  }, [])

  // Function to refresh data
  const refresh = useCallback(async () => {
    try {
      setLoading(true)
      const [analysisData, logsData, uploadsStats] = await Promise.all([
        honeyGuardService.logs.getAnalysis(),
        honeyGuardService.logs.getAllLogs(),
        honeyGuardService.statsServices.getUploadedFilesStats()
      ])
      
      const generalStats = analysisData.general_stats || {}
      setStats({
        totalAttacks: generalStats.total_logs || 0,
        uniqueIPs: generalStats.unique_ips || 0,
        todayAttacks: generalStats.today_logs || 0,
        uploadedFiles: uploadsStats.total_files || 0
      })
      setRecentLogs(logsData.slice(0, 10) || [])
      setAnalysisData(analysisData)
    } catch (err) {
      console.error('Error refreshing data:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  // Generic function to handle requests
  const handleRequest = useCallback(async (requestFn) => {
      setLoading(true)
      setError(null)

    try {
      const result = await requestFn()
      return result
    } catch (err) {
      const errorMessage = err.response?.data?.error || err.message || 'An error occurred'
      setError(errorMessage)
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  // ============================================================================
  // LOGS AND ANALYSIS
  // ============================================================================

  const logs = {
    getAll: useCallback(() => handleRequest(() => honeyGuardService.logs.getAllLogs()), [handleRequest]),
    getAnalysis: useCallback(() => handleRequest(() => honeyGuardService.logs.getAnalysis()), [handleRequest]),
    getByFingerprint: useCallback((fingerprint, ip) => 
      handleRequest(() => honeyGuardService.logs.getLogsByFingerprint(fingerprint, ip)), [handleRequest]),
    getFingerprintInfo: useCallback((fingerprint) => 
      handleRequest(() => honeyGuardService.logs.getFingerprintInfo(fingerprint)), [handleRequest]),
    getUniqueFingerprints: useCallback(() => 
      handleRequest(() => honeyGuardService.logs.getUniqueFingerprints()), [handleRequest]),
  }









  // Scan text content
  const scanContent = async (content) => {
    setLoading(true);
    setError(null);
    
    try {
      const result = await honeyGuardService.sandbox.scan(content);
      return result;
    } catch (err) {
      const errorMsg = `Error scanning content: ${err.message}`;
      setError(errorMsg);
      console.error(errorMsg, err);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  // ============================================================================
  // STATISTICS
  // ============================================================================

  const statsServices = {
    getGeneral: useCallback(() => 
      handleRequest(() => honeyGuardService.stats.getGeneralStats()), [handleRequest]),
    getAttackDistribution: useCallback(() => 
      handleRequest(() => honeyGuardService.stats.getAttackDistribution()), [handleRequest]),
    getTopAttackers: useCallback(() => 
      handleRequest(() => honeyGuardService.stats.getTopAttackers()), [handleRequest]),
    getGeographicDistribution: useCallback(() => 
      handleRequest(() => honeyGuardService.stats.getGeographicDistribution()), [handleRequest]),
  }

  // ============================================================================
  // REAL TIME
  // ============================================================================

  const realtime = {
    getRecent: useCallback((limit) => 
      handleRequest(() => honeyGuardService.realtime.getRecentLogs(limit)), [handleRequest]),
    getToday: useCallback(() => 
      handleRequest(() => honeyGuardService.realtime.getTodayLogs()), [handleRequest]),
  }

  // ============================================================================
  // HONEYPOT - ADMINISTRATION
  // ============================================================================

  const admin = {
    getPanel: useCallback(() => 
      handleRequest(() => honeyGuardService.admin.getAdminPanel()), [handleRequest]),
    getSettings: useCallback(() => 
      handleRequest(() => honeyGuardService.admin.getAdminSettings()), [handleRequest]),
    getBackup: useCallback(() => 
      handleRequest(() => honeyGuardService.admin.getAdminBackup()), [handleRequest]),
    getUsers: useCallback(() => 
      handleRequest(() => honeyGuardService.admin.getAdminUsers()), [handleRequest]),
  }

  // ============================================================================
  // HONEYPOT - FAKE APIs
  // ============================================================================

  const api = {
    getUsers: useCallback(() => 
      handleRequest(() => honeyGuardService.api.getApiUsers()), [handleRequest]),
    getSettings: useCallback(() => 
      handleRequest(() => honeyGuardService.api.getApiSettings()), [handleRequest]),
    queryGraphQL: useCallback((query) => 
      handleRequest(() => honeyGuardService.api.queryGraphQL(query)), [handleRequest]),
    refreshAuth: useCallback((refreshToken) => 
      handleRequest(() => honeyGuardService.api.refreshAuth(refreshToken)), [handleRequest]),
    processPayment: useCallback((paymentData) => 
      handleRequest(() => honeyGuardService.api.processPayment(paymentData)), [handleRequest]),
    getKeys: useCallback(() => 
      handleRequest(() => honeyGuardService.api.getApiKeys()), [handleRequest]),
    getSession: useCallback(() => 
      handleRequest(() => honeyGuardService.api.getSessionInfo()), [handleRequest]),
  }

  // ============================================================================
  // HONEYPOT - VULNERABILITIES
  // ============================================================================

  const vulnerabilities = {
    testLFI: useCallback((path) => 
      handleRequest(() => honeyGuardService.vulnerabilities.testLFI(path)), [handleRequest]),
    testXSS: useCallback((payload) => 
      handleRequest(() => honeyGuardService.vulnerabilities.testXSS(payload)), [handleRequest]),
    testSQLInjection: useCallback((query) => 
      handleRequest(() => honeyGuardService.vulnerabilities.testSQLInjection(query)), [handleRequest]),
    testSSRF: useCallback((url) => 
      handleRequest(() => honeyGuardService.vulnerabilities.testSSRF(url)), [handleRequest]),
    testXXE: useCallback((xmlData) => 
      handleRequest(() => honeyGuardService.vulnerabilities.testXXE(xmlData)), [handleRequest]),
    testDeserialization: useCallback((data) => 
      handleRequest(() => honeyGuardService.vulnerabilities.testDeserialization(data)), [handleRequest]),
    testPathTraversal: useCallback((path) => 
      handleRequest(() => honeyGuardService.vulnerabilities.testPathTraversal(path)), [handleRequest]),
    testRCE: useCallback((command) => 
      handleRequest(() => honeyGuardService.vulnerabilities.testRCE(command)), [handleRequest]),
  }

  // ============================================================================
  // HONEYPOT - CVEs
  // ============================================================================

  const cves = {
    testStruts2: useCallback((payload) => 
      handleRequest(() => honeyGuardService.cves.testStruts2(payload)), [handleRequest]),
    testSpring4Shell: useCallback((payload) => 
      handleRequest(() => honeyGuardService.cves.testSpring4Shell(payload)), [handleRequest]),
    testDrupalgeddon2: useCallback((payload) => 
      handleRequest(() => honeyGuardService.cves.testDrupalgeddon2(payload)), [handleRequest]),
    testShellshock: useCallback((payload) => 
      handleRequest(() => honeyGuardService.cves.testShellshock(payload)), [handleRequest]),
    testWebLogic: useCallback((payload) => 
      handleRequest(() => honeyGuardService.cves.testWebLogic(payload)), [handleRequest]),
    testApachePathTraversal: useCallback((filename) => 
      handleRequest(() => honeyGuardService.cves.testApachePathTraversal(filename)), [handleRequest]),
    getIndex: useCallback(() => 
      handleRequest(() => honeyGuardService.cves.getCvesIndex()), [handleRequest]),
  }

  // ============================================================================
  // HONEYPOT - NETWORK SERVICES
  // ============================================================================

  const network = {
    testDatabase: useCallback((query) => 
      handleRequest(() => honeyGuardService.network.testDatabase(query)), [handleRequest]),
    testFTP: useCallback((credentials) => 
      handleRequest(() => honeyGuardService.network.testFTP(credentials)), [handleRequest]),
    testSSH: useCallback((credentials) => 
      handleRequest(() => honeyGuardService.network.testSSH(credentials)), [handleRequest]),
    testTelnet: useCallback((credentials) => 
      handleRequest(() => honeyGuardService.network.testTelnet(credentials)), [handleRequest]),
    testPOP3: useCallback((credentials) => 
      handleRequest(() => honeyGuardService.network.testPOP3(credentials)), [handleRequest]),
    testIMAP: useCallback((credentials) => 
      handleRequest(() => honeyGuardService.network.testIMAP(credentials)), [handleRequest]),
    testSMTP: useCallback((credentials) => 
      handleRequest(() => honeyGuardService.network.testSMTP(credentials)), [handleRequest]),
  }

  // ============================================================================
  // HONEYPOT - CMS AND PLATFORMS
  // ============================================================================

  const cms = {
    testWordPress: useCallback((credentials) => 
      handleRequest(() => honeyGuardService.cms.testWordPress(credentials)), [handleRequest]),
    testJoomla: useCallback((credentials) => 
      handleRequest(() => honeyGuardService.cms.testJoomla(credentials)), [handleRequest]),
    testDrupal: useCallback((credentials) => 
      handleRequest(() => honeyGuardService.cms.testDrupal(credentials)), [handleRequest]),
    testMagento: useCallback((credentials) => 
      handleRequest(() => honeyGuardService.cms.testMagento(credentials)), [handleRequest]),
  }

  // ============================================================================
  // HONEYPOT - FILES AND RESOURCES
  // ============================================================================

  const files = {
    getBackupZip: useCallback(() => 
      handleRequest(() => honeyGuardService.files.getBackupZip()), [handleRequest]),
    getConfigPHP: useCallback(() => 
      handleRequest(() => honeyGuardService.files.getConfigPHP()), [handleRequest]),
    getDebugLog: useCallback(() => 
      handleRequest(() => honeyGuardService.files.getDebugLog()), [handleRequest]),
    getAccessLog: useCallback(() => 
      handleRequest(() => honeyGuardService.files.getAccessLog()), [handleRequest]),
    getErrorLog: useCallback(() => 
      handleRequest(() => honeyGuardService.files.getErrorLog()), [handleRequest]),
    getLeakFile: useCallback((name) => 
      handleRequest(() => honeyGuardService.files.getLeakFile(name)), [handleRequest]),
    getSecretFile: useCallback((token) => 
      handleRequest(() => honeyGuardService.files.getSecretFile(token)), [handleRequest]),
  }

  // ============================================================================
  // HONEYPOT - PANELS AND DASHBOARDS
  // ============================================================================

  const panels = {
    getDashboard: useCallback(() => 
      handleRequest(() => honeyGuardService.panels.getDashboard()), [handleRequest]),
    getDashboardFiles: useCallback(() => 
      handleRequest(() => honeyGuardService.panels.getDashboardFiles()), [handleRequest]),
    getDashboardSettings: useCallback(() => 
      handleRequest(() => honeyGuardService.panels.getDashboardSettings()), [handleRequest]),
    getInternalPanel: useCallback(() => 
      handleRequest(() => honeyGuardService.panels.getInternalPanel()), [handleRequest]),
    getWebmail: useCallback(() => 
      handleRequest(() => honeyGuardService.panels.getWebmail()), [handleRequest]),
    getRouterLogin: useCallback(() => 
      handleRequest(() => honeyGuardService.panels.getRouterLogin()), [handleRequest]),
    getIoTStatus: useCallback(() => 
      handleRequest(() => honeyGuardService.panels.getIoTStatus()), [handleRequest]),
  }

  // ============================================================================
  // HONEYPOT - UTILITIES AND MISCELLANEOUS
  // ============================================================================

  const utilities = {
    generateSecret: useCallback(() => 
      handleRequest(() => honeyGuardService.utilities.generateSecret()), [handleRequest]),
    testRedirect: useCallback((url) => 
      handleRequest(() => honeyGuardService.utilities.testRedirect(url)), [handleRequest]),
    testLogin: useCallback((credentials) => 
      handleRequest(() => honeyGuardService.utilities.testLogin(credentials)), [handleRequest]),
    getHome: useCallback(() => 
      handleRequest(() => honeyGuardService.utilities.getHome()), [handleRequest]),
    getFlagAccess: useCallback(() => 
      handleRequest(() => honeyGuardService.utilities.getFlagAccess()), [handleRequest]),
    getStolenCookie: useCallback(() => 
      handleRequest(() => honeyGuardService.utilities.getStolenCookie()), [handleRequest]),
    getUnstable: useCallback(() => 
      handleRequest(() => honeyGuardService.utilities.getUnstable()), [handleRequest]),
    uploadFile: useCallback((file) => 
      handleRequest(() => honeyGuardService.utilities.uploadFile(file)), [handleRequest]),
  }

  // ============================================================================
  // HONEYPOT - WEBHOOKS & WAF
  // ============================================================================

  const webhooks = {
    testGitHubWebhook: useCallback((payload) => 
      handleRequest(() => honeyGuardService.webhooks.testGitHubWebhook(payload)), [handleRequest]),
    testStripeWebhook: useCallback((payload) => 
      handleRequest(() => honeyGuardService.webhooks.testStripeWebhook(payload)), [handleRequest]),
    testWAF: useCallback((payload) => 
      handleRequest(() => honeyGuardService.webhooks.testWAF(payload)), [handleRequest]),
  }

  // ============================================================================
  // UTILITY FUNCTIONS
  // ============================================================================

  const clearError = useCallback(() => {
    setError(null)
  }, [])

  const reset = useCallback(() => {
    setLoading(false)
    setError(null)
  }, [])

  // Export honeyGuardService services directly
  return {
    loading,
    error,
    stats,
    recentLogs,
    analysisData,
    refresh,
    logs,
    realtime,
    admin,
    api,
    vulnerabilities,
    cves,
    network,
    cms,
    files,
    panels,
    utilities,
    webhooks,
    statsServices,
    clearError,
    reset,
    scanContent
  }
}