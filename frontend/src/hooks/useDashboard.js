import { useState, useEffect } from 'react'
import { realtimeService, logsService } from '../services/api'
import { getBackendInfo } from '../utils/backendCheck'

export const useDashboard = () => {
  // State for backend data
  const [dashboardData, setDashboardData] = useState({
    stats: {
      totalAttacks: 0,
      uniqueIPs: 0,
      todayAttacks: 0
    },
    recentActivity: [],
    systemStatus: {},
    files: [],
    settings: {}
  })
  const [backendLogs, setBackendLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastUpdate, setLastUpdate] = useState(null)
  const [backendStatus, setBackendStatus] = useState('unknown')
  // const [currentPage, setCurrentPage] = useState('dashboard')

  // Function to load real backend data
  const loadBackendData = async (page = 'dashboard') => {
    try {
      console.log(`🔄 Loading real backend data for ${page}...`)
      
      if (page === 'dashboard') {
        // Load real statistics and logs
        const [analysisData, recentLogs] = await Promise.all([
          logsService.getAnalysis(),
          realtimeService.getRecentLogs(10)
        ])
        
        const generalStats = analysisData.general_stats || {}
        
        setDashboardData(prev => ({
          ...prev,
          stats: {
            totalAttacks: generalStats.total_logs || 0,
            uniqueIPs: generalStats.unique_ips || 0,
            todayAttacks: generalStats.today_logs || 0
          },
          recentActivity: recentLogs || [],
          systemStatus: {
            status: 'online',
            uptime: '99.9%',
            lastCheck: new Date().toISOString()
          }
        }))
        
        setBackendLogs(recentLogs || [])
        console.log('✅ Real dashboard data loaded:', {
          totalAttacks: generalStats.total_logs,
          uniqueIPs: generalStats.unique_ips,
          todayAttacks: generalStats.today_logs,
          recentLogsCount: recentLogs?.length
        })
        
        return true
      } else if (page === 'files') {
        // Load file data (sandbox)
        const sandboxHistory = await realtimeService.getRecentLogs(20)
        setDashboardData(prev => ({
          ...prev,
          files: sandboxHistory || []
        }))
        return true
      } else if (page === 'settings') {
        // Default settings
        setDashboardData(prev => ({
          ...prev,
          settings: {
            honeypotMode: 'active',
            alertLevel: 'medium', // Network attack detection level
            autoBlock: true,
            fileAnalysis: false // Disable file analysis
          }
        }))
        return true
      } else if (page === 'upload') {
        // Default settings for the upload page
        setDashboardData(prev => ({
          ...prev,
          settings: {
            honeypotMode: 'active',
            alertLevel: 'medium', // Network attack detection level
            autoBlock: true,
            fileAnalysis: false // Disable file analysis
          }
        }))
        return true
      }
      
      return false
    } catch (error) {
      console.log(`❌ Error loading real backend data for ${page}:`, error.message)
      return false
    }
  }

  // Function to simulate real navigation on the dashboard
  // const navigateToPage = async (page) => {
  //   console.log(`🎭 Navigating to honeypot page: ${page}`)
  //   setCurrentPage(page)
  //   
  //   try {
  //     // Load JSON data from the backend for the specific page
  //     const success = await loadBackendData(page)
  //     
  //     if (success) {
  //       console.log(`✅ Navigation and JSON data loading successful for ${page}`)
  //     } else {
  //       console.log(`⚠️ Navigation successful but JSON data loading failed for ${page}`)
  //     }
  //     
  //     // Simulate page loading
  //     await new Promise(resolve => setTimeout(resolve, 500))
  //     
  //   } catch (error) {
  //     console.log(`⚠️ Error navigating to ${page}:`, error.message)
  //   }
  // }

  const loadDashboardData = async () => {
    console.log('🔄 Loading honeypot dashboard data...')
    console.log('🔧 Backend info:', getBackendInfo())
    
    try {
      setLoading(true)
      setError(null)

      // Load JSON data for the main dashboard
      const success = await loadBackendData('dashboard')
      
      if (success) {
        console.log('✅ Dashboard JSON data loaded successfully')
        setBackendStatus('online')
        
        // Attempt to load real backend logs (for internal monitoring only)
        try {
          const logs = await realtimeService.getRecentLogs(5)
          console.log('✅ Real logs loaded for monitoring')
          setBackendLogs(logs)
        } catch (logError) {
          console.log('⚠️ Could not load real logs:', logError)
        }
      } else {
        console.log('⚠️ Dashboard not accessible')
        setBackendStatus('offline')
        setError('Dashboard not accessible')
      }

      setLastUpdate(new Date())

    } catch (err) {
      console.error('❌ Error in honeypot dashboard:', err)
      setError('Error loading honeypot data')
      setBackendStatus('error')
    } finally {
      console.log('🏁 Honeypot dashboard loaded')
      setLoading(false)
    }
  }

  const refreshData = () => {
    console.log('🔄 Manual refresh triggered')
    loadDashboardData()
  }

  // Load initial data and set up auto-refresh
  useEffect(() => {
    console.log('🚀 Honeypot dashboard initialized')
    
    const timer = setTimeout(() => {
      loadDashboardData()
    }, 100)
    
    return () => {
      console.log('🧹 Cleaning up honeypot timer')
      clearTimeout(timer)
    }
  }, [])

  console.log('📊 Honeypot state:', { 
    loading, 
    error, 
    backendStatus,
    stats: dashboardData.stats,
  })

  return {
    // State
    stats: dashboardData.stats,
    recentActivity: dashboardData.recentActivity,
    systemStatus: dashboardData.systemStatus,
    files: dashboardData.files,
    settings: dashboardData.settings,
    loading,
    error,
    lastUpdate,
    backendStatus,
    refreshData,
  }
}

export default useDashboard