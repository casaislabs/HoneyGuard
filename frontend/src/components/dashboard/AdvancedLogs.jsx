import { useState, useEffect } from 'react'
import { useHoneyGuard } from '../../hooks/useHoneyGuard'
import { logsService } from '../../services/api'
import UnifiedProtectedRoute from '../auth/UnifiedProtectedRoute'
import StatCard from '../common/StatCard'
import { BarChart3, Users, Activity } from 'lucide-react'

const AdvancedLogsContent = () => {
  const { logs, loading, error } = useHoneyGuard()
  const [fingerprints, setFingerprints] = useState([])
  const [selectedFingerprint, setSelectedFingerprint] = useState(null)
  const [fingerprintInfo, setFingerprintInfo] = useState(null)
  const [logsByFingerprint, setLogsByFingerprint] = useState([])
  const [analysis, setAnalysis] = useState(null)
  const [loadingDetails, setLoadingDetails] = useState(false)
  const [dataLoading, setDataLoading] = useState(true)

  // Load initial data (fingerprints and analysis)
  const loadData = async () => {
    try {
      setDataLoading(true)
      const [fingerprintsData, analysisData] = await Promise.all([
        logs.getUniqueFingerprints(),
        logsService.getAnalysis()
      ])
      setFingerprints(fingerprintsData)
      setAnalysis(analysisData)
    } catch (err) {
      console.error('Error loading data:', err)
    } finally {
      setDataLoading(false)
    }
  }

  useEffect(() => {
    loadData()
    // Data is automatically refreshed via useHoneyGuard hook
  }, [])

  // Handle fingerprint selection and load detailed data
  const handleFingerprintSelect = async (fingerprint) => {
    setSelectedFingerprint(fingerprint)
    setLoadingDetails(true)
    
    try {
      const logsData = await logs.getByFingerprint(fingerprint)
      setLogsByFingerprint(logsData)
      
      // Find the fingerprint information in the list
      const fpInfo = fingerprints.find(fp => fp.fingerprint === fingerprint)
      setFingerprintInfo(fpInfo)
    } catch (error) {
      console.error('Error loading fingerprint details:', error)
    } finally {
      setLoadingDetails(false)
    }
  }

  // Utility functions for formatting
  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString('en-US')
  }

  const formatDate = (dateString) => {
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'long', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }).format(new Date(dateString))
  }

  // Get appropriate color class based on HTTP status code
  const getStatusColor = (status) => {
    if (status >= 200 && status < 300) return 'bg-green-100 text-green-800'
    if (status >= 300 && status < 400) return 'bg-blue-100 text-blue-800'
    if (status >= 400 && status < 500) return 'bg-yellow-100 text-yellow-800'
    if (status >= 500) return 'bg-red-100 text-red-800'
    return 'bg-gray-100 text-gray-800'
  }

  // Component to copy text to clipboard
  const CopyToClipboard = ({ text }) => {
    const [copied, setCopied] = useState(false);

    const handleCopy = () => {
      navigator.clipboard.writeText(text).then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000) // Reset copied state after 2 seconds
      })
    }

    return (
      <button
        onClick={handleCopy}
        className="p-1 text-gray-400 rounded-md hover:bg-gray-700 hover:text-white focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-800 focus:ring-white transition-colors"
        title="Copy to clipboard"
      >
        <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
        {copied && <span className="text-xs absolute -top-5 right-0 bg-green-600 text-white rounded px-1">Copied!</span>}
      </button>
    )
  }



  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (error) {
    return (
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
    )
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Advanced Logs</h1>
          <p className="text-sm text-gray-600">Detailed system log analysis</p>
        </div>
      </div>
      
      {/* General Statistics Overview */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">General Analysis</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatCard
            icon={BarChart3}
            title="Total Logs"
            value={analysis?.general_stats?.total_logs}
            loading={dataLoading}
            bgColor="bg-blue-50"
            iconColor="text-blue-600"
            textColor="text-blue-900"
            titleColor="text-blue-800"
          />
          <StatCard
            icon={Users}
            title="Unique Fingerprints"
            value={fingerprints.length}
            loading={dataLoading}
            bgColor="bg-green-50"
            iconColor="text-green-600"
            textColor="text-green-900"
            titleColor="text-green-800"
          />
          <StatCard
            icon={Activity}
            title="Unique IPs"
            value={analysis?.general_stats?.unique_ips}
            loading={dataLoading}
            bgColor="bg-purple-50"
            iconColor="text-purple-600"
            textColor="text-purple-900"
            titleColor="text-purple-800"
          />
        </div>
      </div>

      {/* Fingerprint Analysis Section */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-xl font-bold text-gray-900">Fingerprint Explorer</h2>
          <p className="text-sm text-gray-600 mt-1">Analyze the activity of unique attackers</p>
        </div>
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-0">
          {/* Fingerprint List Column */}
          <div className="lg:col-span-1 lg:border-r lg:border-gray-200">
            <div className="p-4 space-y-2 max-h-[600px] overflow-y-auto">
              {fingerprints.map((fp) => (
                <div
                  key={fp.fingerprint}
                  onClick={() => handleFingerprintSelect(fp.fingerprint)}
                  className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ease-in-out ${
                    selectedFingerprint === fp.fingerprint
                      ? 'bg-blue-50 border-blue-500 shadow-md'
                      : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                  }`}
                >
                  <div className="flex items-start space-x-3">
                    <div className="flex-shrink-0 pt-1">
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.79-2.93 9.563l-1.05-1.543A9.96 9.96 0 014 12C4 6.477 7.582 2 12 2s8 4.477 8 10a9.96 9.96 0 01-4.02 7.92l-1.05 1.543C13.009 17.79 12 14.517 12 11z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 21a9.04 9.04 0 004.594-1.406l-1.05-1.543A7.036 7.036 0 0112 18c-1.605 0-3.084-.54-4.242-1.457l-1.05 1.543A9.04 9.04 0 0012 21z" />
                      </svg>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-mono text-sm text-gray-800 font-medium truncate" title={fp.fingerprint}>
                        {fp.fingerprint}
                      </p>
                      <div className="flex justify-between items-center mt-2 text-xs text-gray-500">
                        <span>{fp.count} attempts</span>
                        <span>{fp.unique_ips} IPs</span>
                        <span>Last: {new Date(fp.last_seen).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Fingerprint Details Column */}
          <div className="lg:col-span-2 p-6">
            {loadingDetails ? (
              <div className="flex justify-center items-center h-full min-h-[400px]">
                <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600"></div>
              </div>
            ) : fingerprintInfo ? (
              <div className="space-y-6">
                {/* Fingerprint Information Card */}
                <div className="bg-gray-800 shadow-lg rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-white mb-3">Fingerprint Details</h3>
                  <div className="space-y-3 text-sm">
                    <div className="flex items-start justify-between">
                      <span className="text-gray-400 font-medium pt-1">Hash:</span>
                      <div className="relative flex items-center gap-2 bg-gray-900 rounded-md px-2 py-1 min-w-0 max-w-xs">
                        <span 
                          className="text-yellow-400 font-mono truncate"
                          title={selectedFingerprint}
                        >
                          {selectedFingerprint}
                        </span>
                        <CopyToClipboard text={selectedFingerprint} />
                      </div>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400 font-medium">Event Count:</span>
                      <span className="text-green-400 font-semibold">{fingerprintInfo?.count || 0}</span>
                    </div>
                    <div className="flex justify-between items-start">
                      <span className="text-gray-400 font-medium">Associated IPs ({fingerprintInfo?.unique_ips || 0}):</span>
                      <ul className="text-right">
                        {fingerprintInfo?.ips?.map((ip, index) => (
                          <li key={index} className="text-blue-400 font-mono">{ip}</li>
                        )) || []}
                      </ul>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400 font-medium">First Seen:</span>
                      <span className="text-gray-300">{fingerprintInfo?.first_seen ? formatDate(fingerprintInfo.first_seen) : 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400 font-medium">Last Seen:</span>
                      <span className="text-gray-300">{fingerprintInfo?.last_seen ? formatDate(fingerprintInfo.last_seen) : 'N/A'}</span>
                    </div>
                  </div>
                </div>
                
                {/* Additional Details Card */}
                {/* Reserved for future enhancements like User Agents and Paths */}

                {/* Recent Activity Logs */}
                <div>
                  <h4 className="font-semibold text-gray-800 mb-3">Recent Activity ({logsByFingerprint.length} logs)</h4>
                  <div className="space-y-2 max-h-80 overflow-y-auto pr-2">
                    {logsByFingerprint.slice(0, 15).map((log) => (
                      <div key={log.id} className="bg-white border border-gray-200 rounded-md p-3 hover:bg-gray-50 transition-colors">
                        <div className="flex justify-between items-center">
                          <p className="font-mono text-xs text-gray-700 truncate flex-1">
                            {log.method} {log.path}
                          </p>
                          <span className={`text-xs font-bold ml-4 px-2 py-0.5 rounded-full ${getStatusColor(log.http_status)}`}>
                            {log.http_status}
                          </span>
                        </div>
                        <p className="text-xs text-gray-500 mt-1">
                          {log.ip} &bull; {formatTimestamp(log.timestamp)}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex flex-col justify-center items-center h-full min-h-[400px] text-center text-gray-500">
                <svg className="mx-auto h-16 w-16 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                </svg>
                <p className="mt-4 font-semibold">Select a Fingerprint</p>
                <p className="text-sm">Choose an attacker from the list to view their detailed activities</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

const AdvancedLogs = () => {
  return (
    <UnifiedProtectedRoute variant="logs">
      <AdvancedLogsContent />
    </UnifiedProtectedRoute>
  )
}

export default AdvancedLogs