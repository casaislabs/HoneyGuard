import { Shield, AlertTriangle, Users, Activity, Eye, Clock, RefreshCw, FileText, BarChart3, Search, Bug, TrendingUp, LogOut } from 'lucide-react'
import { useHoneyGuard } from '../../hooks/useHoneyGuard'
import { useState, useEffect } from 'react'
import authService from '../../services/authService'
import AdvancedLogs from '../../components/dashboard/AdvancedLogs'
import UploadedFiles from '../../components/dashboard/UploadedFiles'
import HoneypotExplorer from '../../components/dashboard/HoneypotExplorer'
import AdvancedStats from '../../components/dashboard/AdvancedStats'

const RealDashboard = () => {
  const {
    stats,
    recentLogs,
    analysisData,
    loading,
    error,
    refresh
  } = useHoneyGuard()

  const [activeSection, setActiveSection] = useState('overview')
  // Authentication is now handled by UnifiedProtectedRoute wrapper
  // No need for local authentication state

  // Debug: Monitor changes in statistics
  useEffect(() => {
    console.log('🎯 RealDashboard received stats:', stats)
  }, [stats])

  // Handle logout
  const handleLogout = async () => {
    try {
      await authService.logout()
      // Redirect to login page
      window.location.href = '/'
    } catch (error) {
      console.error('Error during logout:', error)
      // Force redirect even if logout fails
      window.location.href = '/'
    }
  }

  // Debug: Monitor changes in recent logs
  useEffect(() => {
    console.log('🎯 RealDashboard received recentLogs:', recentLogs?.length || 0, 'elements')
  }, [recentLogs])

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A'
    try {
      return new Date(timestamp).toLocaleString('en-US')
    } catch {
      return timestamp
    }
  }

  const getAttackType = (log) => {
    // Prioritize attack_type and attack_category from backend
    if (log.attack_type) return log.attack_type.replace(/_/g, ' ').toUpperCase()
    if (log.attack_category) return log.attack_category.replace(/_/g, ' ').toUpperCase()
    
    // Fallback based on path
    if (log.path) {
      if (log.path.includes('admin')) return 'ADMIN PANEL'
      if (log.path.includes('wp-login')) return 'WORDPRESS'
      if (log.path.includes('ftp')) return 'FTP'
      if (log.path.includes('ssh')) return 'SSH'
      if (log.path.includes('upload')) return 'FILE UPLOAD'
      if (log.path.includes('database')) return 'DATABASE'
    }
    return 'UNKNOWN'
  }

  const getStatusColor = (log) => {
    // Use the suspicious field from backend
    if (log.suspicious === true || log.suspicious === 1) return 'bg-red-100 text-red-800'
    if (log.http_status >= 400) return 'bg-yellow-100 text-yellow-800'
    return 'bg-green-100 text-green-800'
  }

  const getStatusText = (log) => {
    // Use the suspicious field from backend
    if (log.suspicious === true || log.suspicious === 1) return 'Suspicious'
    if (log.http_status >= 400) return 'Error'
    return 'OK'
  }



  const navigationItems = [
    { id: 'overview', name: 'Overview', icon: Eye, protected: false },
    { id: 'advanced-stats', name: 'Advanced Statistics', icon: TrendingUp, protected: true },
    { id: 'advanced-logs', name: 'Advanced Logs', icon: BarChart3, protected: true },
    { id: 'sandbox', name: 'Uploaded Files', icon: FileText, protected: true },
    { id: 'honeypots', name: 'Honeypot Explorer', icon: Bug, protected: true },
  ]

  const handleSectionChange = (sectionId) => {
    setActiveSection(sectionId)
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="relative">
            <div className="animate-spin rounded-full h-16 w-16 border-4 border-blue-500/20 border-t-blue-500 mx-auto mb-6"></div>
            <div className="absolute inset-0 rounded-full h-16 w-16 border-4 border-blue-400/10 animate-pulse mx-auto"></div>
          </div>
          <p className="text-gray-300 text-lg font-medium">Loading HoneyGuard Dashboard...</p>
          <p className="text-gray-500 text-sm mt-2">Initializing security monitoring systems</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center">
        <div className="text-center max-w-md mx-auto p-8">
          <div className="bg-red-500/10 rounded-full p-4 w-20 h-20 mx-auto mb-6 flex items-center justify-center">
            <AlertTriangle className="h-10 w-10 text-red-400" />
          </div>
          <h2 className="text-xl font-semibold text-red-300 mb-3">Connection Error</h2>
          <p className="text-gray-400 mb-6 leading-relaxed">{error}</p>
          <button
            onClick={refresh}
            className="bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white px-6 py-3 rounded-lg font-medium transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-0.5"
          >
            <RefreshCw className="h-4 w-4 mr-2 inline" />
            Try Again
          </button>
        </div>
      </div>
    )
  }

  const renderSection = () => {
    switch (activeSection) {
      case 'advanced-stats':
        return <AdvancedStats />
      case 'advanced-logs':
        return <AdvancedLogs />
      case 'sandbox':
        return <UploadedFiles />
      case 'honeypots':
        return <HoneypotExplorer />
      default:
        return (
          <div className="space-y-8">
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="group bg-gradient-to-br from-red-50 via-red-50 to-red-100 rounded-2xl p-6 shadow-lg border border-red-200/50 hover:shadow-2xl hover:border-red-300/50 transition-all duration-300 transform hover:-translate-y-1">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-3">
                      <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
                      <p className="text-sm font-semibold text-red-700 uppercase tracking-wide">Total Attacks</p>
                    </div>
                    <p className="text-4xl font-bold text-red-900 mb-2 group-hover:scale-105 transition-transform duration-200">
                      {stats?.totalAttacks ? stats.totalAttacks.toLocaleString() : '0'}
                    </p>
                    <p className="text-xs text-red-600 font-medium">Detected so far</p>
                  </div>
                  <div className="bg-gradient-to-br from-red-200 to-red-300 p-4 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300">
                    <AlertTriangle className="h-8 w-8 text-red-700 group-hover:scale-110 transition-transform duration-200" />
                  </div>
                </div>
              </div>

              <div className="group bg-gradient-to-br from-blue-50 via-blue-50 to-blue-100 rounded-2xl p-6 shadow-lg border border-blue-200/50 hover:shadow-2xl hover:border-blue-300/50 transition-all duration-300 transform hover:-translate-y-1">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-3">
                      <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
                      <p className="text-sm font-semibold text-blue-700 uppercase tracking-wide">Unique IPs</p>
                    </div>
                    <p className="text-4xl font-bold text-blue-900 mb-2 group-hover:scale-105 transition-transform duration-200">
                      {stats?.uniqueIPs || '0'}
                    </p>
                    <p className="text-xs text-blue-600 font-medium">Different addresses</p>
                  </div>
                  <div className="bg-gradient-to-br from-blue-200 to-blue-300 p-4 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300">
                    <Users className="h-8 w-8 text-blue-700 group-hover:scale-110 transition-transform duration-200" />
                  </div>
                </div>
              </div>

              <div className="group bg-gradient-to-br from-amber-50 via-amber-50 to-amber-100 rounded-2xl p-6 shadow-lg border border-amber-200/50 hover:shadow-2xl hover:border-amber-300/50 transition-all duration-300 transform hover:-translate-y-1">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-3">
                      <div className="w-2 h-2 bg-amber-500 rounded-full animate-pulse"></div>
                      <p className="text-sm font-semibold text-amber-700 uppercase tracking-wide">Today's Attacks</p>
                    </div>
                    <p className="text-4xl font-bold text-amber-900 mb-2 group-hover:scale-105 transition-transform duration-200">
                      {stats?.todayAttacks || '0'}
                    </p>
                    <p className="text-xs text-amber-600 font-medium">In the last 24h</p>
                  </div>
                  <div className="bg-gradient-to-br from-amber-200 to-amber-300 p-4 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300">
                    <Activity className="h-8 w-8 text-amber-700 group-hover:scale-110 transition-transform duration-200" />
                  </div>
                </div>
              </div>

              <div className="group bg-gradient-to-br from-emerald-50 via-emerald-50 to-emerald-100 rounded-2xl p-6 shadow-lg border border-emerald-200/50 hover:shadow-2xl hover:border-emerald-300/50 transition-all duration-300 transform hover:-translate-y-1">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-3">
                      <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div>
                      <p className="text-sm font-semibold text-emerald-700 uppercase tracking-wide">Stored Files</p>
                    </div>
                    <p className="text-4xl font-bold text-emerald-900 mb-2 group-hover:scale-105 transition-transform duration-200">
                      {stats?.uploadedFiles || '0'}
                    </p>
                    <p className="text-xs text-emerald-600 font-medium">Uploaded & stored</p>
                  </div>
                  <div className="bg-gradient-to-br from-emerald-200 to-emerald-300 p-4 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300">
                    <FileText className="h-8 w-8 text-emerald-700 group-hover:scale-110 transition-transform duration-200" />
                  </div>
                </div>
              </div>
            </div>

            {/* Analysis Data */}
            {analysisData && (
              <div className="space-y-8">
                {/* Stats cards and other content would go here */}
              </div>
            )}

            {/* Top Attackers */}
            {analysisData?.top_attackers && (
              <div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-xl border border-gray-200/50 overflow-hidden">
                <div className="px-8 py-6 border-b border-gray-200/50 bg-gradient-to-r from-red-50 via-orange-50 to-red-50">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-3 mb-2">
                        <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse"></div>
                        <h3 className="text-xl font-bold text-gray-900">Top Attackers</h3>
                      </div>
                      <p className="text-sm text-gray-600 font-medium">Most active attacking IP addresses</p>
                    </div>
                    <div className="flex items-center space-x-3">
                      <div className="bg-red-100 p-2 rounded-xl">
                        <AlertTriangle className="h-5 w-5 text-red-600" />
                      </div>
                      <div className="text-right">
                        <div className="text-lg font-bold text-red-600">{analysisData.top_attackers.length}</div>
                        <div className="text-xs text-gray-500 font-medium">attackers</div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="p-8">
                  <div className="space-y-4">
                    {analysisData.top_attackers.slice(0, 8).map((attacker, index) => {
                      const maxCount = analysisData.top_attackers[0]?.count || 1
                      const percentage = (attacker.count / maxCount) * 100
                      const isTopThree = index < 3
                      return (
                        <div key={attacker.ip} className={`group bg-gradient-to-r ${isTopThree ? 'from-red-50 via-orange-50 to-red-50 border-red-200/70' : 'from-gray-50 to-gray-100 border-gray-200/50'} rounded-xl p-5 border hover:shadow-lg transition-all duration-300 transform hover:-translate-y-0.5`}>
                          <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center space-x-4">
                              <div className="flex-shrink-0">
                                <div className={`h-10 w-10 ${isTopThree ? 'bg-gradient-to-br from-red-200 to-orange-200' : 'bg-gradient-to-br from-gray-200 to-gray-300'} rounded-xl flex items-center justify-center shadow-md group-hover:shadow-lg transition-all duration-200`}>
                                  <span className={`text-sm font-bold ${isTopThree ? 'text-red-700' : 'text-gray-600'}`}>#{index + 1}</span>
                                </div>
                              </div>
                              <div>
                                <div className="font-mono text-base font-semibold text-gray-900 group-hover:text-gray-700 transition-colors">{attacker.ip}</div>
                                <div className="text-xs text-gray-500 font-medium mt-1">IP Address</div>
                              </div>
                            </div>
                            <div className="text-right">
                              <div className={`text-2xl font-bold ${isTopThree ? 'text-red-600' : 'text-gray-700'} group-hover:scale-105 transition-transform duration-200`}>{attacker.count}</div>
                              <div className="text-xs text-gray-500 font-medium">attacks</div>
                            </div>
                          </div>
                          <div className="w-full bg-gray-200 rounded-full h-3 shadow-inner">
                            <div 
                              className={`${isTopThree ? 'bg-gradient-to-r from-red-500 via-orange-500 to-red-500' : 'bg-gradient-to-r from-gray-400 to-gray-500'} h-3 rounded-full transition-all duration-700 shadow-sm`}
                              style={{ width: `${percentage}%` }}
                            ></div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              </div>
            )}

            {/* Recent Activity */}
            <div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-xl border border-gray-200/50 overflow-hidden">
              <div className="px-8 py-6 border-b border-gray-200/50 bg-gradient-to-r from-blue-50 via-indigo-50 to-blue-50">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="flex items-center space-x-3 mb-2">
                      <div className="w-3 h-3 bg-blue-500 rounded-full animate-pulse"></div>
                      <h3 className="text-xl font-bold text-gray-900">Recent Activity</h3>
                    </div>
                    <p className="text-sm text-gray-600 font-medium">Latest attack attempts detected in real time</p>
                  </div>
                  <div className="flex items-center space-x-3">
                    <div className="bg-blue-100 p-2 rounded-xl">
                      <Activity className="h-5 w-5 text-blue-600" />
                    </div>
                    <div className="text-right">
                      <div className="text-lg font-bold text-blue-600">{(recentLogs || []).length}</div>
                      <div className="text-xs text-gray-500 font-medium">events</div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200/50">
                  <thead className="bg-gradient-to-r from-gray-50 via-gray-100 to-gray-50">
                    <tr>
                      <th className="px-8 py-5 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                        <div className="flex items-center space-x-3">
                          <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                          <Activity className="h-4 w-4 text-blue-600" />
                          <span>IP Address</span>
                        </div>
                      </th>
                      <th className="px-8 py-5 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                        <div className="flex items-center space-x-3">
                          <div className="w-2 h-2 bg-orange-500 rounded-full"></div>
                          <Bug className="h-4 w-4 text-orange-600" />
                          <span>Attack Type</span>
                        </div>
                      </th>
                      <th className="px-8 py-5 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                        <div className="flex items-center space-x-3">
                          <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                          <Shield className="h-4 w-4 text-green-600" />
                          <span>Status</span>
                        </div>
                      </th>
                      <th className="px-8 py-5 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                        <div className="flex items-center space-x-3">
                          <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
                          <Clock className="h-4 w-4 text-purple-600" />
                          <span>Time</span>
                        </div>
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white/50 divide-y divide-gray-100/50">
                    {(recentLogs || []).slice(0, 10).map((log, index) => (
                      <tr key={index} className="hover:bg-gradient-to-r hover:from-blue-50/50 hover:to-indigo-50/50 transition-all duration-300 group">
                        <td className="px-8 py-6 whitespace-nowrap text-sm text-gray-900">
                          <div className="flex items-center space-x-4">
                            <div className="flex-shrink-0">
                              <div className="h-10 w-10 bg-gradient-to-br from-blue-100 to-blue-200 rounded-xl flex items-center justify-center group-hover:from-blue-200 group-hover:to-blue-300 transition-all duration-200 shadow-md">
                                <Activity className="h-5 w-5 text-blue-600" />
                              </div>
                            </div>
                            <div>
                              <div className="font-mono text-base font-semibold text-gray-900 group-hover:text-blue-700 transition-colors">{log.ip}</div>
                              <div className="text-xs text-gray-500 font-medium mt-1">Source IP</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-8 py-6 whitespace-nowrap text-sm text-gray-900">
                          <span className="inline-flex items-center px-4 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-orange-100 to-red-100 text-orange-800 border border-orange-200/50 shadow-sm">
                            <Bug className="h-3 w-3 mr-2" />
                            {getAttackType(log)}
                          </span>
                        </td>
                        <td className="px-8 py-6 whitespace-nowrap">
                          <span className={`inline-flex items-center px-4 py-2 text-xs font-bold rounded-xl border shadow-sm ${getStatusColor(log)}`}>
                            <span className={`w-2 h-2 rounded-full mr-2 ${
                              getStatusText(log) === 'Suspicious' ? 'bg-red-500 animate-pulse' : 
                              getStatusText(log) === 'Error' ? 'bg-yellow-500' : 'bg-green-500'
                            }`}></span>
                            {getStatusText(log)}
                          </span>
                        </td>
                        <td className="px-8 py-6 whitespace-nowrap text-sm text-gray-900">
                          <div className="flex items-center space-x-3">
                            <div className="bg-purple-100 p-2 rounded-lg">
                              <Clock className="h-4 w-4 text-purple-600" />
                            </div>
                            <div>
                              <div className="font-semibold text-gray-900">{formatTimestamp(log.timestamp)}</div>
                              <div className="text-xs text-gray-500 font-medium mt-1">Detected</div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {(recentLogs || []).length === 0 && (
                <div className="text-center py-16">
                  <div className="bg-gray-100 rounded-full p-6 w-24 h-24 mx-auto mb-6 flex items-center justify-center">
                    <Activity className="h-12 w-12 text-gray-400" />
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">No Recent Activity</h3>
                  <p className="text-sm text-gray-500 max-w-md mx-auto leading-relaxed">Your honeypot is monitoring for threats. Attack events will appear here when detected by the security system.</p>
                  <div className="mt-6">
                    <div className="inline-flex items-center px-4 py-2 bg-green-100 text-green-800 rounded-lg text-sm font-medium">
                      <Shield className="h-4 w-4 mr-2" />
                      System Active
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Advanced Analysis */}
            {analysisData && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Attack Patterns */}
                {analysisData.attack_patterns && (
                  <div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-xl border border-gray-200/50 overflow-hidden">
                    <div className="px-6 py-5 border-b border-gray-200/50 bg-gradient-to-r from-indigo-50 via-purple-50 to-indigo-50">
                      <div className="flex items-center space-x-3 mb-2">
                        <div className="w-3 h-3 bg-indigo-500 rounded-full animate-pulse"></div>
                        <h3 className="text-lg font-bold text-gray-900">Attack Patterns</h3>
                      </div>
                      <p className="text-sm text-gray-600 font-medium">Common attack signatures detected</p>
                    </div>
                    <div className="p-6">
                      <div className="space-y-4">
                        {Object.entries(analysisData.attack_patterns)
                          .sort(([,a], [,b]) => b - a)
                          .slice(0, 5)
                          .map(([pattern, count], index) => {
                            const maxCount = Math.max(...Object.values(analysisData.attack_patterns))
                            const percentage = (count / maxCount) * 100
                            return (
                              <div key={pattern} className="group bg-gradient-to-r from-indigo-50 to-purple-50 rounded-xl p-4 border border-indigo-200/50 hover:shadow-lg transition-all duration-300 transform hover:-translate-y-0.5">
                                <div className="flex items-center justify-between mb-3">
                                  <div className="flex items-center space-x-3">
                                    <div className="bg-gradient-to-br from-indigo-200 to-purple-200 rounded-lg p-2">
                                      <span className="text-xs font-bold text-indigo-700">#{index + 1}</span>
                                    </div>
                                    <span className="text-sm font-semibold text-gray-900 truncate group-hover:text-indigo-700 transition-colors">{pattern}</span>
                                  </div>
                                  <div className="text-right">
                                    <div className="text-lg font-bold text-indigo-600">{count}</div>
                                    <div className="text-xs text-gray-500 font-medium">occurrences</div>
                                  </div>
                                </div>
                                <div className="w-full bg-gray-200 rounded-full h-2 shadow-inner">
                                  <div 
                                    className="bg-gradient-to-r from-indigo-500 to-purple-500 h-2 rounded-full transition-all duration-700 shadow-sm"
                                    style={{ width: `${percentage}%` }}
                                  ></div>
                                </div>
                              </div>
                            )
                          })
                        }
                      </div>
                    </div>
                  </div>
                )}


              </div>
            )}

          </div>
        )
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      {/* Header */}
      <div className="bg-gradient-to-r from-gray-800 via-gray-900 to-gray-800 border-b border-gray-700/50 shadow-2xl">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-2 rounded-xl shadow-lg mr-4">
                <Shield className="h-8 w-8 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">HoneyGuard Dashboard</h1>
                <p className="text-sm text-gray-400 font-medium">Advanced Threat Detection System</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={refresh}
                className="bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white px-5 py-2.5 rounded-xl flex items-center font-medium shadow-lg hover:shadow-xl transition-all duration-200 transform hover:-translate-y-0.5"
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </button>
              <button
                onClick={handleLogout}
                className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white px-5 py-2.5 rounded-xl flex items-center font-medium shadow-lg hover:shadow-xl transition-all duration-200 transform hover:-translate-y-0.5"
              >
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </button>
              <div className="flex items-center bg-green-500/10 px-4 py-2.5 rounded-xl border border-green-500/20">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse mr-3"></div>
                <Shield className="h-4 w-4 mr-2 text-green-400" />
                <span className="text-sm font-medium text-green-400">System Active</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <div className="bg-gradient-to-r from-gray-800 via-gray-900 to-gray-800 border-b border-gray-700/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <nav className="flex space-x-2">
            {navigationItems.map((item) => {
              const Icon = item.icon
              const isActive = activeSection === item.id
              return (
                <button
                  key={item.id}
                  onClick={() => handleSectionChange(item.id)}
                  className={`group flex items-center px-4 py-4 text-sm font-semibold rounded-t-xl transition-all duration-200 transform hover:-translate-y-0.5 ${
                    isActive
                      ? 'bg-gradient-to-b from-blue-500/20 to-blue-600/10 text-blue-400 border-b-2 border-blue-500 shadow-lg'
                      : 'text-gray-300 hover:text-white hover:bg-gray-700/50'
                  }`}
                >
                  <Icon className={`h-5 w-5 mr-3 transition-all duration-200 ${
                    isActive ? 'text-blue-400' : 'text-gray-400 group-hover:text-white'
                  }`} />
                  <span className="transition-all duration-200">{item.name}</span>
                  {isActive && (
                    <div className="ml-2 w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                  )}
                </button>
              )
            })}
          </nav>
        </div>
      </div>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-8 sm:px-6 lg:px-8">
        <div className="px-4 py-8 sm:px-0">
          <div className="backdrop-blur-sm bg-gray-800/30 rounded-2xl border border-gray-700/50 shadow-2xl p-6">
            {renderSection()}
          </div>
        </div>
      </main>
    </div>
  )
}

export default RealDashboard