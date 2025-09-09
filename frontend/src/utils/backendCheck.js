// Utility to verify backend connectivity
export const getBackendInfo = () => {
  const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000'
  return {
    url: backendUrl,
    dashboardEndpoint: `${backendUrl}/dashboard`,
    logsEndpoint: `${backendUrl}/logs`,
    isConfigured: !!import.meta.env.VITE_API_URL
  }
}

// Function to test basic connectivity
export const testBasicConnectivity = async () => {
  const backendInfo = getBackendInfo()
  console.log('🔍 Testing basic connectivity to:', backendInfo.url)
  
  try {
    const response = await fetch(backendInfo.url, {
      method: 'GET',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    if (response.ok) {
      console.log('✅ Basic connectivity test result:', response.status, response.statusText)
      return { status: 'success', statusCode: response.status }
    } else {
      console.log('⚠️ Basic connectivity test result:', response.status, response.statusText)
      return { status: 'failed', error: `HTTP ${response.status}` }
    }
  } catch (error) {
    console.log('❌ Basic connectivity test failed:', error.message)
    return { status: 'failed', error: error.message }
  }
}

// Function to test specific endpoint
export const testEndpoint = async (endpoint) => {
  const backendInfo = getBackendInfo()
  const url = `${backendInfo.url}${endpoint}`
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    if (response.ok) {
      console.log(`✅ ${endpoint}: ${response.status}`)
      return { status: 'success', statusCode: response.status }
    } else {
      console.log(`❌ ${endpoint}: ${response.status}`)
      return { status: 'failed', error: `HTTP ${response.status}` }
    }
  } catch (error) {
    console.log(`❌ ${endpoint}: ${error.message}`)
    return { status: 'failed', error: error.message }
  }
}

// Function to test honeypot endpoints
export const testHoneypotEndpoints = async () => {
  console.log('🔍 Testing honeypot endpoints...')
  
  const results = {
    dashboard: await testEndpoint('/dashboard'),
    logs: await testEndpoint('/logs')
  }
  
  console.log('📊 Honeypot endpoints test results:', results)
  return results
}