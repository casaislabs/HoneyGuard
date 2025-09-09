// Format timestamp
export const formatTimestamp = (timestamp) => {
  if (!timestamp) return 'N/A'
  try {
    return new Date(timestamp).toLocaleString('en-US')
  } catch {
    return timestamp
  }
}

// Format relative time (time ago)
export const formatTimeAgo = (date) => {
  if (!date) return 'N/A'
  try {
    const now = new Date()
    const targetDate = new Date(date)
    const diffInSeconds = Math.floor((now - targetDate) / 1000)

    if (diffInSeconds < 60) return 'Just now'
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`
    if (diffInSeconds < 2592000) return `${Math.floor(diffInSeconds / 86400)} days ago`
    return `${Math.floor(diffInSeconds / 2592000)} months ago`
  } catch {
    return 'N/A'
  }
}

// Format relative date
export const formatRelativeTime = (timestamp) => {
  if (!timestamp) return 'N/A'
  try {
    const now = new Date()
    const date = new Date(timestamp)
    const diffInSeconds = Math.floor((now - date) / 1000)

    if (diffInSeconds < 60) return 'Just now'
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`
    return `${Math.floor(diffInSeconds / 86400)}d ago`
  } catch {
    return timestamp
  }
}

// Get attack type
export const getAttackType = (log) => {
  if (log.attack_type) return log.attack_type
  if (log.attack_category) return log.attack_category
  if (log.path) {
    if (log.path.includes('admin')) return 'Admin Panel'
    if (log.path.includes('wp-login')) return 'WordPress'
    if (log.path.includes('ftp')) return 'FTP'
    if (log.path.includes('ssh')) return 'SSH'
    if (log.path.includes('cgi-bin')) return 'CGI'
    if (log.path.includes('api')) return 'API'
    if (log.path.includes('upload')) return 'File Upload'
  }
  return 'Unknown'
}

// Get status color
export const getStatusColor = (log) => {
  if (log.suspicious) return 'bg-red-100 text-red-800'
  if (log.http_status >= 400) return 'bg-yellow-100 text-yellow-800'
  return 'bg-green-100 text-green-800'
}

// Get status text
export const getStatusText = (log) => {
  if (log.suspicious) return 'Suspicious'
  if (log.http_status >= 400) return 'Error'
  return 'OK'
}

// Format IP
export const formatIP = (ip) => {
  if (!ip) return 'Unknown'
  return ip
}

// Format User Agent
export const formatUserAgent = (userAgent) => {
  if (!userAgent) return 'N/A'
  if (userAgent.length > 50) {
    return userAgent.substring(0, 50) + '...'
  }
  return userAgent
}

// Format file size
export const formatFileSize = (bytes) => {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

// Format percentage
export const formatPercentage = (value, total) => {
  if (!total || total === 0) return '0%'
  return Math.round((value / total) * 100) + '%'
}

// Format number with separators
export const formatNumber = (number) => {
  if (number === null || number === undefined) return '0'
  return number.toLocaleString()
}

// Get country from IP
export const getCountryFromIP = (log) => {
  if (log.location) return log.location
  if (log.abuse_country_code) return log.abuse_country_code
  return 'Unknown'
}

// Get ISP from IP
export const getISPFromIP = (log) => {
  if (log.isp) return log.isp
  if (log.abuse_usage_type) return log.abuse_usage_type
  return 'Unknown'
}

// Format analysis data
export const formatAnalysisData = (analysis) => {
  if (!analysis) return {}
  
  return {
    generalStats: analysis.general_stats || {},
    attackDistribution: analysis.attack_distribution || {},
    topAttackers: analysis.top_attackers || {},
    temporalAnalysis: analysis.temporal_analysis || {},
    topTools: analysis.top_tools || [],
    topPatterns: analysis.top_patterns || [],
    alerts: analysis.alerts || []
  }
}

// Get icon by attack type
export const getAttackIcon = (attackType) => {
  const icons = {
    'admin': '👤',
    'wordpress': '📝',
    'ftp': '📁',
    'ssh': '🔐',
    'sql_injection': '💉',
    'xss': '🎯',
    'file_upload': '📤',
    'api': '🔌',
    'cgi': '⚙️',
    'default': '⚠️'
  }
  
  const type = attackType?.toLowerCase()
  for (const [key, icon] of Object.entries(icons)) {
    if (type?.includes(key)) return icon
  }
  return icons.default
}

// Get color by attack type
export const getAttackColor = (attackType) => {
  const colors = {
    'admin': 'text-blue-500',
    'wordpress': 'text-green-500',
    'ftp': 'text-yellow-500',
    'ssh': 'text-purple-500',
    'sql_injection': 'text-red-500',
    'xss': 'text-orange-500',
    'file_upload': 'text-pink-500',
    'api': 'text-indigo-500',
    'cgi': 'text-gray-500',
    'default': 'text-gray-400'
  }
  
  const type = attackType?.toLowerCase()
  for (const [key, color] of Object.entries(colors)) {
    if (type?.includes(key)) return color
  }
  return colors.default
}