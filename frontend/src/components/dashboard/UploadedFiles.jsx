import { useState, useEffect } from 'react'
import { Upload, FileText, AlertTriangle, Clock, MapPin, HardDrive, Eye, Download, RefreshCw, Database, Shield } from 'lucide-react'
import authService from '../../services/authService'

const UploadedFiles = () => {
  const [uploadsData, setUploadsData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selectedIP, setSelectedIP] = useState(null)
  const [refreshing, setRefreshing] = useState(false)

  useEffect(() => {
    fetchUploadsData()
  }, [])

  const fetchUploadsData = async (isRefresh = false) => {
    try {
      if (isRefresh) {
        setRefreshing(true)
      } else {
        setLoading(true)
      }
      setError(null)
      
      const token = authService.getToken()
      if (!token) {
        throw new Error('Authentication token not found. Please log in again.')
      }

      const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000'
      const response = await fetch(`${backendUrl}/uploads`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Authentication failed. Please log in again.')
        }
        throw new Error(`Failed to fetch data (Status: ${response.status})`)
      }

      const data = await response.json()
      setUploadsData(data)
    } catch (err) {
      console.error('Error fetching uploads data:', err)
      setError(err.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  const handleRefresh = () => {
    fetchUploadsData(true)
  }

  const formatFileSize = (bytes) => {
    if (!bytes || bytes === 0) return '0 B'
    const units = ['B', 'KB', 'MB', 'GB', 'TB']
    const base = 1024
    const index = Math.floor(Math.log(bytes) / Math.log(base))
    const size = (bytes / Math.pow(base, index)).toFixed(2)
    return `${parseFloat(size)} ${units[index]}`
  }

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A'
    try {
      const date = new Date(timestamp)
      return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      })
    } catch {
      return timestamp
    }
  }

  const getFileTypeIcon = (fileType) => {
    if (!fileType) return FileText
    const type = fileType.toLowerCase()
    if (type.includes('image')) return Eye
    if (type.includes('zip') || type.includes('archive') || type.includes('compressed')) return Download
    if (type.includes('text') || type.includes('document')) return FileText
    return FileText
  }

  const getFileTypeColor = (fileType) => {
    if (!fileType) return 'bg-gray-100 text-gray-800 border-gray-300'
    
    const type = fileType.toLowerCase()
    if (type.includes('image')) return 'bg-blue-100 text-blue-800 border-blue-300'
    if (type.includes('video')) return 'bg-red-100 text-red-800 border-red-300'
    if (type.includes('audio')) return 'bg-purple-100 text-purple-800 border-purple-300'
    if (type.includes('pdf')) return 'bg-orange-100 text-orange-800 border-orange-300'
    if (type.includes('zip') || type.includes('archive')) return 'bg-yellow-100 text-yellow-800 border-yellow-300'
    if (type.includes('text') || type.includes('code')) return 'bg-green-100 text-green-800 border-green-300'
    return 'bg-gray-100 text-gray-800 border-gray-300'
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-4 border-blue-200 border-t-blue-600 mx-auto mb-6"></div>
          <h3 className="text-lg font-semibold text-gray-700 mb-2">Loading Upload Data</h3>
          <p className="text-gray-500">Fetching uploaded files from attackers...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-white rounded-xl shadow-lg border border-red-200 p-8">
        <div className="text-center">
          <div className="bg-red-100 rounded-full p-4 w-20 h-20 mx-auto mb-6 flex items-center justify-center">
            <AlertTriangle className="h-10 w-10 text-red-600" />
          </div>
          <h3 className="text-xl font-semibold text-gray-900 mb-2">Failed to Load Upload Data</h3>
          <p className="text-gray-600 mb-4">We encountered an issue while fetching the uploaded files.</p>
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
            <p className="text-sm text-red-700 font-mono">{error}</p>
          </div>
          <div className="flex justify-center space-x-4">
            <button
              onClick={() => fetchUploadsData()}
              className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-medium transition-colors duration-200 flex items-center space-x-2"
            >
              <RefreshCw className="h-4 w-4" />
              <span>Try Again</span>
            </button>
          </div>
        </div>
      </div>
    )
  }

  if (!uploadsData || !uploadsData.uploads_by_ip || uploadsData.uploads_by_ip.length === 0) {
    return (
      <div className="bg-white rounded-xl shadow-lg border border-gray-200 p-12">
        <div className="text-center">
          <div className="bg-gray-100 rounded-full p-6 w-24 h-24 mx-auto mb-6 flex items-center justify-center">
            <Upload className="h-12 w-12 text-gray-400" />
          </div>
          <h3 className="text-xl font-semibold text-gray-900 mb-2">No Upload Activity Detected</h3>
          <p className="text-gray-600 mb-4">No files have been uploaded by attackers yet.</p>
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 max-w-md mx-auto">
            <div className="flex items-center space-x-2 text-blue-700">
              <Shield className="h-4 w-4" />
              <span className="text-sm font-medium">Honeypot is actively monitoring for file uploads</span>
            </div>
          </div>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="mt-6 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white px-6 py-3 rounded-lg font-medium transition-colors duration-200 flex items-center space-x-2 mx-auto"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
            <span>{refreshing ? 'Refreshing...' : 'Refresh Data'}</span>
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="bg-white rounded-xl shadow-lg border border-gray-100 p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Upload Monitor</h1>
            <p className="text-gray-600">Track and analyze files uploaded by attackers to your honeypot</p>
          </div>
          <div className="flex items-center space-x-4">
            <div className="bg-green-50 border border-green-200 rounded-lg px-4 py-2">
              <div className="flex items-center space-x-2 text-green-700">
                <Database className="h-4 w-4" />
                <span className="text-sm font-medium">Live Monitoring Active</span>
              </div>
            </div>
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white px-4 py-2 rounded-lg font-medium transition-colors duration-200 flex items-center space-x-2"
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
              <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Summary Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl p-6 shadow-lg border border-blue-200 hover:shadow-xl transition-all duration-300 group">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-blue-700 mb-1 uppercase tracking-wide">Total Files</p>
              <p className="text-3xl font-bold text-blue-900">{uploadsData.summary?.total_files || 0}</p>
              <p className="text-xs text-blue-600 mt-2 font-medium">Files uploaded by attackers</p>
            </div>
            <div className="bg-blue-200 p-3 rounded-full group-hover:bg-blue-300 transition-colors duration-300">
              <FileText className="h-8 w-8 text-blue-600" />
            </div>
          </div>
        </div>

        <div className="bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl p-6 shadow-lg border border-purple-200 hover:shadow-xl transition-all duration-300 group">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-purple-700 mb-1 uppercase tracking-wide">Active Sources</p>
              <p className="text-3xl font-bold text-purple-900">{uploadsData.uploads_by_ip?.length || 0}</p>
              <p className="text-xs text-purple-600 mt-2 font-medium">IP addresses with uploads</p>
            </div>
            <div className="bg-purple-200 p-3 rounded-full group-hover:bg-purple-300 transition-colors duration-300">
              <Clock className="h-8 w-8 text-purple-600" />
            </div>
          </div>
        </div>

        <div className="bg-gradient-to-br from-green-50 to-green-100 rounded-xl p-6 shadow-lg border border-green-200 hover:shadow-xl transition-all duration-300 group">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-green-700 mb-1 uppercase tracking-wide">Unique IPs</p>
              <p className="text-3xl font-bold text-green-900">{uploadsData.summary?.unique_ips || 0}</p>
              <p className="text-xs text-green-600 mt-2 font-medium">Different attack sources</p>
            </div>
            <div className="bg-green-200 p-3 rounded-full group-hover:bg-green-300 transition-colors duration-300">
              <MapPin className="h-8 w-8 text-green-600" />
            </div>
          </div>
        </div>

        <div className="bg-gradient-to-br from-orange-50 to-orange-100 rounded-xl p-6 shadow-lg border border-orange-200 hover:shadow-xl transition-all duration-300 group">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-orange-700 mb-1 uppercase tracking-wide">Total Size</p>
              <p className="text-3xl font-bold text-orange-900">{formatFileSize(uploadsData.summary?.total_size)}</p>
              <p className="text-xs text-orange-600 mt-2 font-medium">Storage consumed</p>
            </div>
            <div className="bg-orange-200 p-3 rounded-full group-hover:bg-orange-300 transition-colors duration-300">
              <HardDrive className="h-8 w-8 text-orange-600" />
            </div>
          </div>
        </div>
      </div>

      {/* Upload Activity by IP Address */}
      <div className="bg-white rounded-xl shadow-lg border border-gray-100 overflow-hidden">
        <div className="px-6 py-5 border-b border-gray-200 bg-gradient-to-r from-blue-50 to-indigo-50">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xl font-bold text-gray-900 flex items-center space-x-2">
                <MapPin className="h-5 w-5 text-blue-600" />
                <span>Upload Activity by IP Address</span>
              </h3>
              <p className="text-sm text-gray-600 mt-1">Detailed breakdown of file uploads organized by source IP address</p>
            </div>
            <div className="bg-blue-100 border border-blue-200 rounded-lg px-3 py-2">
              <span className="text-sm font-semibold text-blue-800">
                {uploadsData.uploads_by_ip?.length || 0} Active IPs
              </span>
            </div>
          </div>
        </div>
        
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gradient-to-r from-gray-50 to-gray-100">
              <tr>
                <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                  <div className="flex items-center space-x-2">
                    <MapPin className="h-4 w-4" />
                    <span>IP Address</span>
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                  <div className="flex items-center space-x-2">
                    <FileText className="h-4 w-4" />
                    <span>Files Count</span>
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                  <div className="flex items-center space-x-2">
                    <Eye className="h-4 w-4" />
                    <span>File Types</span>
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                  <div className="flex items-center space-x-2">
                    <HardDrive className="h-4 w-4" />
                    <span>Total Size</span>
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                  <div className="flex items-center space-x-2">
                    <Clock className="h-4 w-4" />
                    <span>First Upload</span>
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                  <div className="flex items-center space-x-2">
                    <Clock className="h-4 w-4" />
                    <span>Latest Upload</span>
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-100">
              {uploadsData.uploads_by_ip.map((ipData, index) => (
                <tr key={index} className="hover:bg-gradient-to-r hover:from-blue-50 hover:to-indigo-50 transition-all duration-300 group">
                  <td className="px-6 py-5 whitespace-nowrap">
                    <div className="flex items-center space-x-3">
                      <div className="bg-blue-100 p-2 rounded-lg group-hover:bg-blue-200 transition-colors duration-300">
                        <MapPin className="h-4 w-4 text-blue-600" />
                      </div>
                      <div>
                        <span className="text-sm font-bold text-gray-900 font-mono">{ipData.ip}</span>
                        <p className="text-xs text-gray-500 mt-1">Source IP Address</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-5 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      <span className="text-lg font-bold text-gray-900">{ipData.total_files}</span>
                      <span className="text-xs text-gray-500 font-medium">files</span>
                    </div>
                  </td>
                  <td className="px-6 py-5 whitespace-nowrap">
                    <div className="flex flex-wrap gap-1">
                      <span className="inline-flex items-center px-3 py-1 text-xs font-bold rounded-full bg-gradient-to-r from-blue-100 to-blue-200 text-blue-800 border border-blue-300">
                        {new Set(ipData.files.map(f => f.file_type?.split('/')[0] || 'unknown')).size} types
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-5 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      <HardDrive className="h-4 w-4 text-gray-400" />
                      <span className="text-sm font-bold text-gray-900">{formatFileSize(ipData.total_size)}</span>
                    </div>
                  </td>
                  <td className="px-6 py-5 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      <Clock className="h-4 w-4 text-green-500" />
                      <div>
                        <span className="text-sm font-medium text-gray-900">{formatTimestamp(ipData.first_upload)}</span>
                        <p className="text-xs text-gray-500">Initial activity</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-5 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      <Clock className="h-4 w-4 text-orange-500" />
                      <div>
                        <span className="text-sm font-medium text-gray-900">{formatTimestamp(ipData.last_upload)}</span>
                        <p className="text-xs text-gray-500">Most recent</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-5 whitespace-nowrap">
                    <button
                      onClick={() => setSelectedIP(selectedIP === ipData.ip ? null : ipData.ip)}
                      className={`inline-flex items-center px-4 py-2 text-sm font-medium rounded-lg transition-all duration-200 ${
                        selectedIP === ipData.ip
                          ? 'bg-red-100 text-red-700 hover:bg-red-200 border border-red-300'
                          : 'bg-blue-100 text-blue-700 hover:bg-blue-200 border border-blue-300'
                      }`}
                    >
                      <Eye className="h-4 w-4 mr-2" />
                      {selectedIP === ipData.ip ? 'Hide Files' : 'View Files'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detailed File Analysis for Selected IP */}
      {selectedIP && (
        <div className="bg-white rounded-xl shadow-lg border border-gray-100 overflow-hidden">
          <div className="px-6 py-5 border-b border-gray-200 bg-gradient-to-r from-green-50 to-emerald-50">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xl font-bold text-gray-900 flex items-center space-x-2">
                  <FileText className="h-5 w-5 text-green-600" />
                  <span>File Analysis for {selectedIP}</span>
                </h3>
                <p className="text-sm text-gray-600 mt-1">Detailed breakdown of all files uploaded from this IP address</p>
              </div>
              <div className="bg-green-100 border border-green-200 rounded-lg px-3 py-2">
                <span className="text-sm font-semibold text-green-800">
                  {uploadsData.uploads_by_ip.find(ip => ip.ip === selectedIP)?.files?.length || 0} Files
                </span>
              </div>
            </div>
          </div>
          
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gradient-to-r from-gray-50 to-gray-100">
                <tr>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                    <div className="flex items-center space-x-2">
                      <FileText className="h-4 w-4" />
                      <span>File Name</span>
                    </div>
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                    <div className="flex items-center space-x-2">
                      <Eye className="h-4 w-4" />
                      <span>MIME Type</span>
                    </div>
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                    <div className="flex items-center space-x-2">
                      <HardDrive className="h-4 w-4" />
                      <span>File Size</span>
                    </div>
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                    <div className="flex items-center space-x-2">
                      <Download className="h-4 w-4" />
                      <span>Extension</span>
                    </div>
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                    <div className="flex items-center space-x-2">
                      <Clock className="h-4 w-4" />
                      <span>Upload Time</span>
                    </div>
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider">
                    <div className="flex items-center space-x-2">
                      <Shield className="h-4 w-4" />
                      <span>File Hash</span>
                    </div>
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-100">
                {uploadsData.uploads_by_ip
                  .find(ip => ip.ip === selectedIP)?.files
                  .map((file, index) => {
                    const FileIcon = getFileTypeIcon(file.file_type)
                    const extension = file.filename?.split('.').pop()?.toUpperCase() || 'N/A'
                    return (
                      <tr key={index} className="hover:bg-gradient-to-r hover:from-green-50 hover:to-emerald-50 transition-all duration-300 group">
                        <td className="px-6 py-5 whitespace-nowrap">
                          <div className="flex items-center space-x-3">
                            <div className="bg-green-100 p-2 rounded-lg group-hover:bg-green-200 transition-colors duration-300">
                              <FileIcon className="h-4 w-4 text-green-600" />
                            </div>
                            <div className="max-w-xs">
                              <span className="text-sm font-bold text-gray-900 font-mono truncate block">{file.filename}</span>
                              <p className="text-xs text-gray-500 mt-1">Uploaded file</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-5 whitespace-nowrap">
                          <span className={`inline-flex items-center px-3 py-1 text-xs font-bold rounded-full border ${getFileTypeColor(file.file_type)}`}>
                            {file.file_type || 'Unknown'}
                          </span>
                        </td>
                        <td className="px-6 py-5 whitespace-nowrap">
                          <div className="flex items-center space-x-2">
                            <HardDrive className="h-4 w-4 text-gray-400" />
                            <span className="text-sm font-bold text-gray-900">{formatFileSize(file.file_size)}</span>
                          </div>
                        </td>
                        <td className="px-6 py-5 whitespace-nowrap">
                          <span className="inline-flex items-center px-3 py-1 text-xs font-bold rounded-full bg-gradient-to-r from-purple-100 to-purple-200 text-purple-800 border border-purple-300">
                            .{extension}
                          </span>
                        </td>
                        <td className="px-6 py-5 whitespace-nowrap">
                          <div className="flex items-center space-x-2">
                            <Clock className="h-4 w-4 text-blue-500" />
                            <div>
                              <span className="text-sm font-medium text-gray-900">{formatTimestamp(file.timestamp)}</span>
                              <p className="text-xs text-gray-500">Upload time</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-5 whitespace-nowrap">
                          <div className="flex items-center space-x-2">
                            <Shield className="h-4 w-4 text-gray-400" />
                            <div className="max-w-xs">
                              <span className="text-xs font-mono text-gray-700 bg-gray-100 px-2 py-1 rounded border">
                                {file.file_hash ? file.file_hash.substring(0, 12) + '...' : 'N/A'}
                              </span>
                              <p className="text-xs text-gray-500 mt-1">File hash</p>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

export default UploadedFiles