import  { useState, useEffect } from 'react'
import { useHoneyGuard } from '../../hooks/useHoneyGuard'
import { BarChart3, Users, Shield, AlertTriangle, MapPin, Clock, Activity } from 'lucide-react'
import StatCard from '../common/StatCard'

const AdvancedStats = () => {
  const { stats, logs, realtime, loading, error } = useHoneyGuard()
  const [analysis, setAnalysis] = useState(null)
  const [fingerprints, setFingerprints] = useState([])
  const [recentLogs, setRecentLogs] = useState([])
  const [todayLogs, setTodayLogs] = useState([])
  const [dataLoading, setDataLoading] = useState(true)

  useEffect(() => {
    loadAdvancedStats()
    // Data is automatically refreshed via useHoneyGuard hook
  }, [])

  const loadAdvancedStats = async () => {
    try {
      setDataLoading(true)
      const [analysisData, fingerprintsData, recentData, todayData] = await Promise.all([
        logs.getAnalysis(),
        logs.getUniqueFingerprints(),
        realtime.getRecent(20),
        realtime.getToday()
      ])
      
      setAnalysis(analysisData)
      setFingerprints(fingerprintsData)
      setRecentLogs(recentData)
      setTodayLogs(todayData)
    } catch (err) {
      console.error('Error loading advanced stats:', err)
    } finally {
      setDataLoading(false)
    }
  }

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString()
  }

  const getAttackTypeColor = (type) => {
    const colors = {
      'admin_panel': 'bg-red-100 text-red-800',
      'wordpress': 'bg-blue-100 text-blue-800',
      'ftp': 'bg-green-100 text-green-800',
      'ssh': 'bg-purple-100 text-purple-800',
      'sql_injection': 'bg-yellow-100 text-yellow-800',
      'xss': 'bg-orange-100 text-orange-800',
      'lfi': 'bg-pink-100 text-pink-800',
      'rce': 'bg-red-100 text-red-800',
      'malware_upload': 'bg-red-100 text-red-800',
      'default': 'bg-gray-100 text-gray-800'
    }
    return colors[type] || colors.default
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 200: return 'text-green-600'
      case 403: return 'text-red-600'
      case 404: return 'text-yellow-600'
      case 500: return 'text-red-800'
      default: return 'text-gray-600'
    }
  }

  const getTopAttackTypes = () => {
    const attackTypes = {}
    recentLogs.forEach(log => {
      const type = log.attack_type || log.attack_category || 'unknown'
      attackTypes[type] = (attackTypes[type] || 0) + 1
    })
    return Object.entries(attackTypes)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
  }

  const getTopIPs = () => {
    const ipCounts = {}
    recentLogs.forEach(log => {
      if (log.ip) {
        ipCounts[log.ip] = (ipCounts[log.ip] || 0) + 1
      }
    })
    return Object.entries(ipCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
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
      {/* Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          icon={AlertTriangle}
          title="Total Attacks"
          value={analysis?.total_logs || recentLogs.length}
          loading={dataLoading}
          iconColor="text-red-500"
        />

        <StatCard
          icon={Users}
          title="Unique IPs"
          value={analysis?.unique_ips || new Set(recentLogs.map(log => log.ip)).size}
          loading={dataLoading}
          iconColor="text-blue-500"
        />

        <StatCard
          icon={Activity}
          title="Attacks Today"
          value={todayLogs.length}
          loading={dataLoading}
          iconColor="text-yellow-500"
        />

        <StatCard
          icon={Shield}
          title="Unique Fingerprints"
          value={fingerprints.length}
          loading={dataLoading}
          iconColor="text-green-500"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Attack Types */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center">
              <BarChart3 className="h-5 w-5 mr-2" />
              Most Common Attack Types
            </h2>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {getTopAttackTypes().map(([type, count], index) => (
                <div key={type} className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className="text-sm font-medium text-gray-900">#{index + 1}</span>
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getAttackTypeColor(type)}`}>
                      {type}
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-32 bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-blue-600 h-2 rounded-full"
                        style={{ width: `${(count / Math.max(...getTopAttackTypes().map(([,c]) => c))) * 100}%` }}
                      ></div>
                    </div>
                    <span className="text-sm font-medium text-gray-900">{count}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Top Attacker IPs */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center">
              <MapPin className="h-5 w-5 mr-2" />
              Most Active IPs
            </h2>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {getTopIPs().map(([ip, count], index) => (
                <div key={ip} className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className="text-sm font-medium text-gray-900">#{index + 1}</span>
                    <span className="text-sm font-mono text-gray-700">{ip}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-32 bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-red-600 h-2 rounded-full"
                        style={{ width: `${(count / Math.max(...getTopIPs().map(([,c]) => c))) * 100}%` }}
                      ></div>
                    </div>
                    <span className="text-sm font-medium text-gray-900">{count}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity Timeline */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900 flex items-center">
            <Clock className="h-5 w-5 mr-2" />
            Recent Activity
          </h2>
        </div>
        <div className="p-6">
          <div className="space-y-4">
            {recentLogs.slice(0, 15).map((log, index) => (
              <div key={index} className="flex items-center space-x-4 p-4 bg-gray-50 rounded-lg">
                <div className="flex-shrink-0">
                  <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {log.ip} - {log.attack_type || log.attack_category || 'Unknown'}
                      </p>
                      <p className="text-sm text-gray-500 font-mono">
                        {log.method} {log.path}
                      </p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`text-sm font-medium ${getStatusColor(log.http_status)}`}>
                        {log.http_status}
                      </span>
                      <span className="text-sm text-gray-500">
                        {formatTimestamp(log.timestamp)}
                      </span>
                    </div>
                  </div>
                  {log.fingerprint && (
                    <p className="text-xs text-gray-400 mt-1 font-mono">
                      Fingerprint: {log.fingerprint}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Fingerprint Statistics */}
      {fingerprints.length > 0 && (
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center">
              <Shield className="h-5 w-5 mr-2" />
              Fingerprint Statistics
            </h2>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-900">{fingerprints.length}</p>
                <p className="text-sm text-gray-600">Unique Fingerprints</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-900">
                  {fingerprints.reduce((sum, fp) => sum + (fp.count || 0), 0)}
                </p>
                <p className="text-sm text-gray-600">Total Attempts</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-900">
                  {fingerprints.reduce((sum, fp) => sum + (fp.unique_ips || 0), 0)}
                </p>
                <p className="text-sm text-gray-600">Total Unique IPs</p>
              </div>
            </div>
            
            <div className="mt-6">
              <h3 className="text-md font-medium text-gray-900 mb-3">Most Active Fingerprints</h3>
              <div className="space-y-2">
                {fingerprints.slice(0, 5).map((fp, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                    <div>
                      <p className="text-sm font-mono text-gray-900 truncate">
                        {fp.fingerprint}
                      </p>
                      <p className="text-xs text-gray-500">
                        {fp.count} attempts • {fp.unique_ips} IPs
                      </p>
                    </div>
                    <span className="text-sm text-gray-500">
                      {formatTimestamp(fp.last_seen)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default AdvancedStats