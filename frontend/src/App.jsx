import React, { useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import FakeLogin from './pages/honeypot/FakeLogin'
import FakeDashboard from './pages/honeypot/FakeDashboard'
import FakeHome from './pages/honeypot/FakeHome'
import FakeWordPress from './pages/honeypot/FakeWordPress'
import FakeAdmin from './pages/honeypot/FakeAdmin'
import FakeSandbox from './pages/honeypot/FakeSandbox'
import FakeAPI from './pages/honeypot/FakeAPI'
import RealDashboard from './pages/real/RealDashboard'
import UnifiedProtectedRoute from './components/auth/UnifiedProtectedRoute'
import LogGenerator from './components/honeypot/LogGenerator'
import FakeDrupalLogin from './pages/honeypot/FakeDrupalLogin';
import FakeDrupalRegister from './pages/honeypot/FakeDrupalRegister';
import FakeJoomlaLogin from './pages/honeypot/FakeJoomlaLogin';
import FakeMagentoLogin from './pages/honeypot/FakeMagentoLogin';
import FakePhpMyAdminLogin from './pages/honeypot/FakePhpMyAdminLogin';

// Component to redirect to backend
const BackendRedirect = ({ endpoint, description = "backend service" }) => {
  useEffect(() => {
    const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000'
    window.location.href = `${backendUrl}${endpoint}`
  }, [endpoint])
  
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
        <h2 className="text-xl font-semibold text-gray-900 mb-2">Redirecting...</h2>
        <p className="text-gray-600">Taking you to the {description}</p>
      </div>
    </div>
  )
}

// Component for pages that generate logs but maintain frontend experience
const HybridPage = ({ children, endpoint, method = "GET", data = null }) => {
  return (
    <>
      <LogGenerator endpoint={endpoint} method={method} data={data} />
      {children}
    </>
  )
}

function App() {
  return (
    <Router>
      <Routes>
        {/* ===== MAIN HONEYPOT ROUTES (Frontend) ===== */}
        
        {/* Home page - Generates access log */}
        <Route path="/" element={
          <HybridPage endpoint="/home" method="GET">
            <FakeHome />
          </HybridPage>
        } />
        
        {/* Fake login - Generates attempt logs */}
        <Route path="/login" element={<FakeLogin />} />
        
        {/* Fake dashboard - Generates access log */}
        <Route path="/dashboard" element={
          <HybridPage endpoint="/dashboard" method="GET">
            <FakeDashboard />
          </HybridPage>
        } />
        
        {/* Admin Panel - Uses frontend component */}
        <Route path="/admin" element={<FakeAdmin />} />
        
        {/* WordPress Admin - Uses frontend component */}
        <Route path="/wp-admin" element={<FakeWordPress />} />
        {/* Drupal User Login - Uses fake frontend component */}
        <Route path="/drupal/user/login" element={<FakeDrupalLogin />} />
        {/* File upload - Uses frontend component */}
        <Route path="/upload" element={<FakeSandbox />} />
        
        {/* API Documentation - Uses frontend component */}
        <Route path="/api-docs" element={<FakeAPI />} />
        
        {/* ===== ROUTES THAT REDIRECT TO BACKEND ===== */}
        
        {/* Additional administrative services */}
        <Route path="/admin/panel" element={<BackendRedirect endpoint="/admin/panel" description="admin panel" />} />
        <Route path="/admin/settings" element={<BackendRedirect endpoint="/admin/settings" description="admin settings" />} />
        <Route path="/admin/backup" element={<BackendRedirect endpoint="/admin/backup" description="admin backup" />} />
        <Route path="/admin/users" element={<BackendRedirect endpoint="/admin/users" description="user management" />} />
        
        {/* Specific WordPress login */}
        <Route path="/wp-login.php" element={<BackendRedirect endpoint="/wp-login.php" description="WordPress login" />} />
        
        {/* CVEs - Redirect to backend to simulate vulnerabilities */}
        <Route path="/cves" element={<BackendRedirect endpoint="/cves" description="CVE database" />} />
        <Route path="/struts2" element={<BackendRedirect endpoint="/struts2" description="Struts2 application" />} />
        <Route path="/spring" element={<BackendRedirect endpoint="/spring" description="Spring Boot application" />} />
        <Route path="/drupal" element={<FakeDrupalRegister />} />
        <Route path="/cgi-bin/bash" element={<BackendRedirect endpoint="/cgi-bin/bash" description="CGI script" />} />
        <Route path="/wls-wsat/CoordinatorPortType" element={<BackendRedirect endpoint="/wls-wsat/CoordinatorPortType" description="WebLogic service" />} />
        
        {/* Network services */}
        <Route path="/ftp" element={<BackendRedirect endpoint="/ftp" description="FTP service" />} />
        <Route path="/ssh" element={<BackendRedirect endpoint="/ssh" description="SSH service" />} />
        <Route path="/telnet" element={<BackendRedirect endpoint="/telnet" description="Telnet service" />} />
        <Route path="/pop3" element={<BackendRedirect endpoint="/pop3" description="POP3 service" />} />
        <Route path="/imap" element={<BackendRedirect endpoint="/imap" description="IMAP service" />} />
        
        {/* Mail services */}
        <Route path="/smtp/login" element={<BackendRedirect endpoint="/smtp/login" description="SMTP login" />} />
        <Route path="/webmail" element={<BackendRedirect endpoint="/webmail" description="webmail interface" />} />
        
        {/* Databases */}
        <Route path="/database" element={<BackendRedirect endpoint="/database" description="database interface" />} />
        <Route path="/phpmyadmin" element={
          <HybridPage endpoint="/phpmyadmin" method="GET">
            <FakePhpMyAdminLogin />
          </HybridPage>
        } />
        
        {/* APIs */}
        <Route path="/api/v1/users" element={<BackendRedirect endpoint="/api/v1/users" description="user API" />} />
        <Route path="/api/v1/settings" element={<BackendRedirect endpoint="/api/v1/settings" description="settings API" />} />
        <Route path="/api/v2/graphql" element={<BackendRedirect endpoint="/api/v2/graphql" description="GraphQL API" />} />
        <Route path="/api/v1/auth/refresh" element={<BackendRedirect endpoint="/api/v1/auth/refresh" description="auth refresh API" />} />
        <Route path="/api/v1/payments" element={<BackendRedirect endpoint="/api/v1/payments" description="payments API" />} />
        <Route path="/api/v1/session" element={<BackendRedirect endpoint="/api/v1/session" description="session API" />} />
        <Route path="/api/v1/keys" element={<BackendRedirect endpoint="/api/v1/keys" description="API keys" />} />
        
        {/* Sensitive files */}
        <Route path="/config.php" element={<BackendRedirect endpoint="/config.php" description="configuration file" />} />
        <Route path="/backup.zip" element={<BackendRedirect endpoint="/backup.zip" description="backup file" />} />
        <Route path="/debug.log" element={<BackendRedirect endpoint="/debug.log" description="debug log" />} />
        <Route path="/logs/access.log" element={<BackendRedirect endpoint="/logs/access.log" description="access log" />} />
        <Route path="/logs/error.log" element={<BackendRedirect endpoint="/logs/error.log" description="error log" />} />
        
        {/* Web vulnerabilities */}
        <Route path="/lfi" element={<BackendRedirect endpoint="/lfi" description="file inclusion test" />} />
        <Route path="/xss" element={<BackendRedirect endpoint="/xss" description="XSS test" />} />
        <Route path="/sql" element={<BackendRedirect endpoint="/sql" description="SQL injection test" />} />
        <Route path="/ssrf" element={<BackendRedirect endpoint="/ssrf" description="SSRF test" />} />
        <Route path="/rce" element={<BackendRedirect endpoint="/rce" description="RCE test" />} />
        <Route path="/xxe" element={<BackendRedirect endpoint="/xxe" description="XXE test" />} />
        <Route path="/deserialize" element={<BackendRedirect endpoint="/deserialize" description="deserialization test" />} />
        <Route path="/traversal" element={<BackendRedirect endpoint="/traversal" description="path traversal test" />} />
        <Route path="/waf" element={<BackendRedirect endpoint="/waf" description="WAF bypass test" />} />
        
        {/* CMS */}
        <Route path="/joomla/administrator" element={
          <HybridPage endpoint="/joomla/administrator" method="GET">
            <FakeJoomlaLogin />
          </HybridPage>
        } />
        <Route path="/drupal/user/login" element={<BackendRedirect endpoint="/drupal/user/login" description="Drupal login" />} />
        <Route path="/magento/admin" element={
          <HybridPage endpoint="/magento/admin" method="GET">
            <FakeMagentoLogin />
          </HybridPage>
        } />
        
        {/* Network devices */}
        <Route path="/router/login" element={<BackendRedirect endpoint="/router/login" description="router login" />} />
        <Route path="/iot/status" element={<BackendRedirect endpoint="/iot/status" description="IoT device" />} />
        
        {/* Popular webhooks */}
        <Route path="/webhook/github" element={<BackendRedirect endpoint="/webhook/github" description="GitHub webhook" />} />
        <Route path="/webhook/stripe" element={<BackendRedirect endpoint="/webhook/stripe" description="Stripe webhook" />} />
        
        {/* File Upload */}
        <Route path="/upload" element={<BackendRedirect endpoint="/upload" description="file upload" />} />
        
        {/* Internal and secret panels */}
        <Route path="/internal-panel" element={<BackendRedirect endpoint="/internal-panel" description="internal panel" />} />
        <Route path="/flag-access" element={<BackendRedirect endpoint="/flag-access" description="flag access" />} />
        <Route path="/redirect" element={<BackendRedirect endpoint="/redirect" description="redirect service" />} />
        <Route path="/stolen-cookie" element={<BackendRedirect endpoint="/stolen-cookie" description="stolen cookie" />} />
        <Route path="/unstable" element={<BackendRedirect endpoint="/unstable" description="unstable service" />} />
        <Route path="/verify" element={<BackendRedirect endpoint="/verify" description="token verification" />} />
        <Route path="/spring4shell" element={<BackendRedirect endpoint="/spring4shell" description="Spring4Shell CVE" />} />
        <Route path="/drupalgeddon2" element={<BackendRedirect endpoint="/drupalgeddon2" description="Drupalgeddon2 CVE" />} />
        <Route path="/shellshock" element={<BackendRedirect endpoint="/shellshock" description="Shellshock CVE" />} />
        <Route path="/weblogic" element={<BackendRedirect endpoint="/weblogic" description="WebLogic CVE" />} />
        
        {/* Leaked data files */}
        <Route path="/leak-database.sql" element={<BackendRedirect endpoint="/leak-database.sql" description="data leak" />} />
        <Route path="/secret-admin123.zip" element={<BackendRedirect endpoint="/secret-admin123.zip" description="secret file" />} />
        <Route path="/leak-:name.sql" element={<BackendRedirect endpoint="/leak-database.sql" description="data leak" />} />
        <Route path="/secret-:token.zip" element={<BackendRedirect endpoint="/secret-admin123.zip" description="secret file" />} />
        <Route path="/generate-secret" element={<BackendRedirect endpoint="/generate-secret" description="secret generator" />} />
        
        {/* ===== SECRET ROUTES (PROTECTED AND HIDDEN) ===== */}
        <Route 
          path={import.meta.env.VITE_REAL_DASHBOARD_ROUTE || "/rh-admin-d9a8b7c6e5f4"} 
          element={
            <UnifiedProtectedRoute variant="dashboard">
              <RealDashboard />
            </UnifiedProtectedRoute>
          } 
        />
        
        {/* ===== CATCH-ALL: Redirect unfound routes to home ===== */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  )
}

export default App
