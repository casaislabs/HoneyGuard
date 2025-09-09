import { useState } from 'react'
import HoneypotLayout from '../../components/layout/HoneypotLayout'
import LogGenerator from '../../components/honeypot/LogGenerator'

const FakeSandbox = () => {
  const [selectedFile, setSelectedFile] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [uploadSuccess, setUploadSuccess] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [error, setError] = useState(null)
  const [analysisId, setAnalysisId] = useState(null)

  const handleFileSelect = (e) => {
    const file = e.target.files[0]
    setSelectedFile(file)
    setUploadSuccess(false)
    setError(null)
    setAnalysisId(null)
  }

  const handleUpload = async (e) => {
    e.preventDefault()
    if (!selectedFile) return

    setIsAnalyzing(true)
    setUploadProgress(0)
    setError(null)

    // Simulate upload progress
    const progressInterval = setInterval(() => {
      setUploadProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval)
          return 90
        }
        return prev + 10
      })
    }, 200)

    try {
      const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000'
      const formData = new FormData()
      formData.append('file', selectedFile)

      const response = await fetch(`${backendUrl}/upload`, {
        method: 'POST',
        body: formData
      })

      const data = await response.json()
      
      if (response.ok) {
        setUploadProgress(100)
        setUploadSuccess(true)
        // Generate a fake analysis ID for the user
        setAnalysisId(`AN-${Date.now().toString(36).toUpperCase()}`)
      } else {
        setError(data.message || 'Error uploading file')
      }

    } catch (error) {
      console.error('Error uploading file:', error)
      setError('Network error: Could not connect to analysis service')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const generateFileHash = (filename, size) => {
    // Generate a fake hash based on name and size
    const str = filename + size.toString()
    let hash = 0
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i)
      hash = ((hash << 5) - hash) + char
      hash = hash & hash // Convert to 32bit integer
    }
    return hash.toString(16).padStart(8, '0').repeat(8)
  }

  return (
    <HoneypotLayout>
      {/* Generate sandbox access log */}
      <LogGenerator endpoint="/dashboard" method="GET" />
      
      <div className="max-w-4xl mx-auto p-6">
        <div className="bg-white rounded-lg shadow-lg p-8">
          <div className="text-center mb-8">
            <div className="mx-auto h-16 w-16 flex items-center justify-center rounded-full bg-orange-100 mb-4">
              <svg className="h-8 w-8 text-orange-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              Malware Analysis Service
            </h1>
            <p className="text-gray-600">
              Upload suspicious files for professional malware analysis
            </p>
          </div>

          {!uploadSuccess ? (
            <form onSubmit={handleUpload} className="space-y-6">
              <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
                <div className="mx-auto h-12 w-12 text-gray-400 mb-4">
                  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                  </svg>
                </div>
                <div className="text-sm text-gray-600">
                  <label htmlFor="file-upload" className="relative cursor-pointer bg-white rounded-md font-medium text-orange-600 hover:text-orange-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-orange-500">
                    <span>Upload a file</span>
                    <input
                      id="file-upload"
                      name="file-upload"
                      type="file"
                      className="sr-only"
                      onChange={handleFileSelect}
                      accept=".exe,.dll,.bat,.cmd,.ps1,.vbs,.js,.jar,.apk,.php,.asp,.jsp,.pdf,.doc,.docx,.xls,.xlsx,.zip,.rar"
                    />
                  </label>
                  <p className="pl-1">or drag and drop</p>
                </div>
                <p className="text-xs text-gray-500 mt-2">
                  EXE, DLL, BAT, CMD, PS1, VBS, JS, JAR, APK, PHP, ASP, JSP, PDF, Office, ZIP, RAR up to 50MB
                </p>
              </div>

              {selectedFile && (
                <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <svg className="h-5 w-5 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                      </svg>
                    </div>
                    <div className="ml-3">
                      <h3 className="text-sm font-medium text-blue-800">
                        File selected: {selectedFile.name}
                      </h3>
                      <div className="mt-2 text-sm text-blue-700">
                        <p>Size: {formatFileSize(selectedFile.size)}</p>
                        <p>Type: {selectedFile.type || 'Unknown'}</p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {error && (
                <div className="bg-red-50 border border-red-200 rounded-md p-4">
                  <div className="flex">
                    <div className="flex-shrink-0">
                      <svg className="h-5 w-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                      </svg>
                    </div>
                    <div className="ml-3">
                      <h3 className="text-sm font-medium text-red-800">Upload Error</h3>
                      <div className="mt-2 text-sm text-red-700">
                        <p>{error}</p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {isAnalyzing && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <svg className="animate-spin h-5 w-5 text-yellow-400" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                    </div>
                    <div className="ml-3">
                      <h3 className="text-sm font-medium text-yellow-800">
                        Uploading and preparing analysis...
                      </h3>
                      <div className="mt-2">
                        <div className="bg-yellow-200 rounded-full h-2">
                          <div 
                            className="bg-yellow-600 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${uploadProgress}%` }}
                          ></div>
                        </div>
                        <p className="text-xs text-yellow-700 mt-1">{uploadProgress}% complete</p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              <button
                type="submit"
                disabled={!selectedFile || isAnalyzing}
                className="w-full bg-orange-600 hover:bg-orange-700 text-white py-3 px-4 rounded-md font-medium disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isAnalyzing ? 'Uploading...' : 'Submit for Analysis'}
              </button>
            </form>
          ) : (
            <div className="text-center space-y-6">
              <div className="mx-auto h-16 w-16 flex items-center justify-center rounded-full bg-green-100">
                <svg className="h-8 w-8 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              
              <div>
                <h2 className="text-2xl font-bold text-gray-900 mb-2">
                  File Successfully Submitted
                </h2>
                <p className="text-gray-600 mb-6">
                  Your file has been uploaded and queued for analysis.
                </p>
              </div>

              <div className="bg-gray-50 rounded-lg p-6 max-w-md mx-auto">
                <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-4">
                  Analysis Details
                </h3>
                <dl className="space-y-3">
                  <div className="flex justify-between">
                    <dt className="text-sm font-medium text-gray-700">Analysis ID:</dt>
                    <dd className="text-sm text-gray-900 font-mono">{analysisId}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-sm font-medium text-gray-700">Filename:</dt>
                    <dd className="text-sm text-gray-900">{selectedFile.name}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-sm font-medium text-gray-700">File Size:</dt>
                    <dd className="text-sm text-gray-900">{formatFileSize(selectedFile.size)}</dd>
                  </div>
                  <div className="flex justify-between items-start">
                    <dt className="text-sm font-medium text-gray-700 flex-shrink-0 mr-4">File Hash:</dt>
                    <dd className="text-sm text-gray-900 font-mono text-right break-all">{generateFileHash(selectedFile.name, selectedFile.size)}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-sm font-medium text-gray-700">Status:</dt>
                    <dd className="text-sm text-gray-900">
                      <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-yellow-100 text-yellow-800">
                        QUEUED FOR ANALYSIS
                      </span>
                    </dd>
                  </div>
                </dl>
              </div>

              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 max-w-md mx-auto">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <svg className="h-5 w-5 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-blue-800">
                      What happens next?
                    </h3>
                    <div className="mt-2 text-sm text-blue-700">
                      <p>• Your file will be analyzed in our secure sandbox environment</p>
                      <p>• Analysis typically takes 15-30 minutes</p>
                      <p>• You will receive results via email</p>
                      <p>• Keep your Analysis ID for reference</p>
                    </div>
                  </div>
                </div>
              </div>

              <button
                onClick={() => {
                  setSelectedFile(null)
                  setUploadSuccess(false)
                  setAnalysisId(null)
                }}
                className="bg-gray-600 hover:bg-gray-700 text-white py-2 px-4 rounded-md font-medium"
              >
                Submit Another File
              </button>
            </div>
          )}

          {/* Security Notice */}
          <div className="mt-8 bg-yellow-50 border border-yellow-200 rounded-lg p-4">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-yellow-800">
                  Security Notice
                </h3>
                <div className="mt-2 text-sm text-yellow-700">
                  <p>
                    This service is for legitimate security analysis only. All uploads are logged and monitored. 
                    Do not upload files that you do not own or have permission to analyze.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </HoneypotLayout>
  )
}

export default FakeSandbox