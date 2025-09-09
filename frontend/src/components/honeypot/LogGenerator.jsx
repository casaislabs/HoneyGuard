import { useEffect, useRef } from 'react'

const LogGenerator = ({ endpoint, method = 'GET', data = null, silent = true, delay = 0 }) => {
  const hasLogged = useRef(false)

  useEffect(() => {
    // Avoid multiple requests
    if (hasLogged.current) return
    
    const generateLog = async () => {
      try {
        hasLogged.current = true
        
        // Apply delay if specified
        if (delay > 0) {
          await new Promise(resolve => setTimeout(resolve, delay))
        }
        
        const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000'
        
        if (method === 'GET') {
          // For simple GET requests
          await fetch(`${backendUrl}${endpoint}`, {
            method: 'GET',
            headers: {
              'Content-Type': 'application/json',
            }
          })
        } else if (method === 'POST' && data) {
          // For POST requests with data
          const form = document.createElement('form')
          form.method = 'POST'
          form.action = `${backendUrl}${endpoint}`
          form.target = '_blank'
          form.style.display = 'none'
          
          // Add data fields
          Object.entries(data).forEach(([key, value]) => {
            const field = document.createElement('input')
            field.type = 'hidden'
            field.name = key
            field.value = value
            form.appendChild(field)
          })
          
          document.body.appendChild(form)
          form.submit()
          document.body.removeChild(form)
        } else if (method === 'POST') {
          // For POST requests without data (simulate access)
          await fetch(`${backendUrl}${endpoint}`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({})
          })
        }
        
        if (!silent) {
          console.log(`Log generated for ${endpoint}`)
        }
      } catch (error) {
        if (!silent) {
          console.log(`Error generating log for ${endpoint}:`, error)
        }
      }
    }
    
    generateLog()
  }, [endpoint, method, data, silent, delay])

  // This component doesn't render anything visible
  return null
}

export default LogGenerator