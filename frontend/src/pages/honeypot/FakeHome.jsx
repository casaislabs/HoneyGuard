import { Link } from 'react-router-dom'
import HoneypotLayout from '../../components/layout/HoneypotLayout'

const FakeHome = () => {
  return (
    <HoneypotLayout>
      {/* Hero Section */}
      <div className="text-center mb-12">
        <h1 className="text-4xl tracking-tight font-extrabold text-gray-900 sm:text-5xl md:text-6xl">
          <span className="block">Enterprise Security</span>
          <span className="block text-blue-600">Management Platform</span>
        </h1>
        <p className="mt-3 max-w-md mx-auto text-base text-gray-500 sm:text-lg md:mt-5 md:text-xl md:max-w-3xl">
          Advanced threat detection, real-time monitoring, and comprehensive security analytics for your organization.
        </p>
        <div className="mt-5 max-w-md mx-auto sm:flex sm:justify-center md:mt-8">
          <div className="rounded-md shadow">
            <Link
              to="/login"
              className="w-full flex items-center justify-center px-8 py-3 border border-transparent text-base font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 md:py-4 md:text-lg md:px-10"
            >
              Get Started
            </Link>
          </div>
          <div className="mt-3 rounded-md shadow sm:mt-0 sm:ml-3">
            <Link
              to="/dashboard"
              className="w-full flex items-center justify-center px-8 py-3 border border-transparent text-base font-medium rounded-md text-blue-600 bg-white hover:bg-gray-50 md:py-4 md:text-lg md:px-10"
            >
              View Dashboard
            </Link>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <div className="mb-12">
        <h2 className="text-3xl font-bold text-gray-900 text-center mb-8">Platform Features</h2>
        <div className="grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-3">
          {/* Feature 1 */}
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <svg className="h-8 w-8 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <div className="ml-4">
                  <h3 className="text-lg font-medium text-gray-900">Threat Detection</h3>
                  <p className="text-gray-600">Real-time monitoring and advanced threat detection capabilities.</p>
                </div>
              </div>
            </div>
          </div>

          {/* Feature 2 */}
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <svg className="h-8 w-8 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
                <div className="ml-4">
                  <h3 className="text-lg font-medium text-gray-900">High Performance</h3>
                  <p className="text-gray-600">Optimized for speed and efficiency in large-scale deployments.</p>
                </div>
              </div>
            </div>
          </div>

          {/* Feature 3 */}
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <svg className="h-8 w-8 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                </div>
                <div className="ml-4">
                  <h3 className="text-lg font-medium text-gray-900">Analytics</h3>
                  <p className="text-gray-600">Comprehensive reporting and analytics for security insights.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Access Section */}
      <div className="mb-12">
        <h2 className="text-3xl font-bold text-gray-900 text-center mb-8">Quick Access</h2>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {/* Dashboard */}
          <div className="bg-white shadow rounded-lg p-6 hover:shadow-lg transition-shadow">
            <div className="flex items-center mb-4">
              <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7" />
              </svg>
              <h3 className="ml-2 text-lg font-medium text-gray-900">Dashboard</h3>
            </div>
            <p className="text-gray-600 mb-4">View honeypot statistics and activity.</p>
            <Link to="/dashboard" className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700">Go to Dashboard</Link>
          </div>
          {/* Admin Panel */}
          <div className="bg-white shadow rounded-lg p-6 hover:shadow-lg transition-shadow">
            <div className="flex items-center mb-4">
              <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <h3 className="ml-2 text-lg font-medium text-gray-900">Admin Panel</h3>
            </div>
            <p className="text-gray-600 mb-4">System administration and configuration management.</p>
            <Link to="/admin" className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700">Access Admin</Link>
          </div>
          {/* WordPress Admin */}
          <div className="bg-white shadow rounded-lg p-6 hover:shadow-lg transition-shadow">
            <div className="flex items-center mb-4">
              <svg className="h-6 w-6 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197" />
              </svg>
              <h3 className="ml-2 text-lg font-medium text-gray-900">WordPress Admin</h3>
            </div>
            <p className="text-gray-600 mb-4">Simulate WordPress admin attacks and logins.</p>
            <Link to="/wp-admin" className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-purple-600 hover:bg-purple-700">Go to WP Admin</Link>
          </div>
          {/* Malware Sandbox */}
          <div className="bg-white shadow rounded-lg p-6 hover:shadow-lg transition-shadow">
            <div className="flex items-center mb-4">
              <svg className="h-6 w-6 text-orange-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
              <h3 className="ml-2 text-lg font-medium text-gray-900">Malware Sandbox</h3>
            </div>
            <p className="text-gray-600 mb-4">Upload and analyze suspicious files.</p>
            <Link to="/upload" className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-orange-600 hover:bg-orange-700">Upload Files</Link>
          </div>
          {/* API Docs */}
          <div className="bg-white shadow rounded-lg p-6 hover:shadow-lg transition-shadow">
            <div className="flex items-center mb-4">
              <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 20h9" />
              </svg>
              <h3 className="ml-2 text-lg font-medium text-gray-900">API Docs</h3>
            </div>
            <p className="text-gray-600 mb-4">Explore the fake API documentation.</p>
            <Link to="/api-docs" className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700">View API Docs</Link>
          </div>
          {/* Login */}
          <div className="bg-white shadow rounded-lg p-6 hover:shadow-lg transition-shadow">
            <div className="flex items-center mb-4">
              <svg className="h-6 w-6 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.121 17.804A13.937 13.937 0 0112 15c2.5 0 4.847.657 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
              <h3 className="ml-2 text-lg font-medium text-gray-900">Fake Login</h3>
            </div>
            <p className="text-gray-600 mb-4">Simulate login attempts and brute force attacks.</p>
            <Link to="/login" className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-400 hover:bg-blue-500">Go to Login</Link>
          </div>
        </div>
      </div>

      {/* Simulated Services & Vulnerabilities Section */}
      <div className="mb-12">
        <h2 className="text-2xl font-bold text-gray-900 text-center mb-6">Simulated Services & Vulnerabilities</h2>
        {/* Administrative services */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">Admin & Management</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/admin/panel" icon="🛠️" title="Admin Panel" desc="Simulated admin panel." />
          <ServiceCard to="/admin/settings" icon="⚙️" title="Admin Settings" desc="Simulated admin settings." />
          <ServiceCard to="/admin/backup" icon="💾" title="Admin Backup" desc="Simulated backup management." />
          <ServiceCard to="/admin/users" icon="👥" title="User Management" desc="Simulated user management." />
        </div>
        {/* CMS and panels */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">CMS & Panels</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/wp-login.php" icon="📝" title="WordPress" desc="WordPress login demo." />
          <ServiceCard to="/wp-admin" icon="🔧" title="WP Admin" desc="WordPress admin demo." />
          <ServiceCard to="/admin" icon="👑" title="Admin Panel" desc="Generic admin panel demo." />
          <ServiceCard to="/dashboard" icon="📊" title="Dashboard" desc="Admin dashboard demo." />
          <ServiceCard to="/joomla/administrator" icon="🟠" title="Joomla Admin" desc="Joomla administrator panel." />
          <ServiceCard to="/drupal/user/login" icon="💧" title="Drupal Login" desc="Drupal user login." />
          <ServiceCard to="/magento/admin" icon="🛒" title="Magento Admin" desc="Magento admin panel." />
        </div>
        {/* Web vulnerabilities */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">Web Vulnerabilities</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/cves" icon="🦠" title="CVE Database" desc="Vulnerability database demo." />
          <ServiceCard to="/struts2" icon="🔥" title="Struts2" desc="Struts2 vulnerability demo." />
          <ServiceCard to="/spring" icon="🌱" title="Spring4Shell" desc="Spring Boot vulnerability demo." />
          <ServiceCard to="/drupal" icon="🔗" title="Drupal" desc="Drupal vulnerability demo." />
          <ServiceCard to="/cgi-bin/bash" icon="🐚" title="Shellshock" desc="CGI Bash vulnerability demo." />
          <ServiceCard to="/wls-wsat/CoordinatorPortType" icon="🛰️" title="WebLogic" desc="WebLogic service demo." />
          <ServiceCard to="/lfi" icon="📂" title="LFI" desc="File inclusion test." />
          <ServiceCard to="/xss" icon="💉" title="XSS" desc="Cross-site scripting demo." />
          <ServiceCard to="/sql" icon="🗄️" title="SQLi" desc="SQL injection demo." />
          <ServiceCard to="/ssrf" icon="🔄" title="SSRF" desc="Server-side request forgery demo." />
          <ServiceCard to="/rce" icon="⚡" title="RCE" desc="Remote code execution demo." />
          <ServiceCard to="/xxe" icon="📄" title="XXE" desc="XML external entity demo." />
          <ServiceCard to="/deserialize" icon="📦" title="Deserialization" desc="Deserialization test." />
          <ServiceCard to="/traversal" icon="🧭" title="Path Traversal" desc="Path traversal demo." />
          <ServiceCard to="/waf" icon="🛡️" title="WAF Bypass" desc="WAF bypass demo." />
          <ServiceCard to="/cgi-bin/bash" icon="🐚" title="CGI Bash" desc="CGI bash vulnerability demo." />
          <ServiceCard to="/cgi-bin/test" icon="📄" title="CGI Files" desc="CGI files access demo." />
        </div>
        {/* Network services */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">Network Services</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/ftp" icon="📁" title="FTP" desc="FTP service demo." />
          <ServiceCard to="/ssh" icon="🔑" title="SSH" desc="SSH service demo." />
          <ServiceCard to="/telnet" icon="📞" title="Telnet" desc="Telnet service demo." />
          <ServiceCard to="/pop3" icon="📬" title="POP3" desc="POP3 service demo." />
          <ServiceCard to="/imap" icon="✉️" title="IMAP" desc="IMAP service demo." />
        </div>
        {/* Mail services */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">Mail Services</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/smtp/login" icon="📤" title="SMTP Login" desc="SMTP login demo." />
          <ServiceCard to="/webmail" icon="📧" title="Webmail" desc="Webmail interface demo." />
        </div>
        {/* Databases */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">Database Services</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/database" icon="🗃️" title="Database" desc="Database interface demo." />
          <ServiceCard to="/phpmyadmin" icon="🛠️" title="phpMyAdmin" desc="phpMyAdmin demo." />
        </div>
        {/* CVEs & Exploits */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">CVEs & Exploits</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/cves" icon="🔍" title="CVEs Index" desc="CVE vulnerabilities index." />
          <ServiceCard to="/struts2" icon="⚡" title="Struts2 CVE" desc="Apache Struts2 vulnerability." />
          <ServiceCard to="/spring4shell" icon="🌱" title="Spring4Shell" desc="Spring4Shell vulnerability." />
          <ServiceCard to="/drupalgeddon2" icon="💊" title="Drupalgeddon2" desc="Drupal RCE vulnerability." />
          <ServiceCard to="/shellshock" icon="💥" title="Shellshock" desc="Bash shellshock vulnerability." />
          <ServiceCard to="/weblogic" icon="☕" title="WebLogic CVE" desc="Oracle WebLogic vulnerability." />
        </div>
        {/* APIs */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">APIs</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/api/v1/users" icon="👤" title="User API" desc="User API demo." />
          <ServiceCard to="/api/v1/settings" icon="⚙️" title="Settings API" desc="Settings API demo." />
          <ServiceCard to="/api/v2/graphql" icon="🔗" title="GraphQL API" desc="GraphQL API demo." />
          <ServiceCard to="/api/v1/auth/refresh" icon="🔄" title="Auth Refresh" desc="Auth refresh API demo." />
          <ServiceCard to="/api/v1/payments" icon="💳" title="Payments API" desc="Payments API demo." />
          <ServiceCard to="/api/v1/session" icon="🕒" title="Session API" desc="Session API demo." />
          <ServiceCard to="/api/v1/keys" icon="🔑" title="API Keys" desc="API keys demo." />
        </div>
        {/* Sensitive files */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">Sensitive Files</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/config.php" icon="⚙️" title="Config File" desc="Configuration file demo." />
          <ServiceCard to="/backup.zip" icon="🗜️" title="Backup File" desc="Backup file demo." />
          <ServiceCard to="/debug.log" icon="📝" title="Debug Log" desc="Debug log demo." />
          <ServiceCard to="/logs/access.log" icon="📄" title="Access Log" desc="Access log demo." />
          <ServiceCard to="/logs/error.log" icon="❌" title="Error Log" desc="Error log demo." />
        </div>
        {/* Network devices */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">Network Devices</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/router/login" icon="📡" title="Router Login" desc="Router login demo." />
          <ServiceCard to="/iot/status" icon="📶" title="IoT Device" desc="IoT device status demo." />
        </div>
        {/* Webhooks */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">Webhooks</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/webhook/github" icon="🐙" title="GitHub Webhook" desc="GitHub webhook demo." />
          <ServiceCard to="/webhook/stripe" icon="💰" title="Stripe Webhook" desc="Stripe webhook demo." />
        </div>
        {/* File Upload */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">File Upload</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/upload" icon="📁" title="File Upload" desc="Simple file upload." />
        </div>
        {/* Authentication Services */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">Authentication Services</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/login" icon="🔑" title="Login Service" desc="Generic login service demo." />
          <ServiceCard to="/verify" icon="✅" title="Token Verify" desc="Token verification demo." />
          <ServiceCard to="/refresh" icon="🔄" title="Token Refresh" desc="Token refresh demo." />
        </div>
        {/* Internal and secret panels */}
        <h3 className="text-lg font-semibold text-gray-800 mt-8 mb-4">Internal & Secret Panels</h3>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <ServiceCard to="/internal-panel" icon="🔒" title="Internal Panel" desc="Internal panel demo." />
          <ServiceCard to="/flag-access" icon="🚩" title="Flag Access" desc="Flag access demo." />
          <ServiceCard to="/redirect" icon="➡️" title="Redirect Service" desc="Redirect service demo." />
          <ServiceCard to="/stolen-cookie" icon="🍪" title="Stolen Cookie" desc="Stolen cookie demo." />
          <ServiceCard to="/unstable" icon="⚠️" title="Unstable Service" desc="Unstable service demo." />
          <ServiceCard to="/leak-database.sql" icon="💧" title="Data Leak" desc="Data leak demo." />
          <ServiceCard to="/secret-admin123.zip" icon="🗝️" title="Secret File" desc="Secret file demo." />
          <ServiceCard to="/generate-secret" icon="🔑" title="Secret Generator" desc="Secret generator demo." />
        </div>
      </div>

      {/* System Status */}
      <div className="bg-white shadow rounded-lg p-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-6">System Status</h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="flex items-center">
            <div className="w-3 h-3 bg-green-500 rounded-full mr-3"></div>
            <span className="text-gray-700">Authentication Service</span>
          </div>
          <div className="flex items-center">
            <div className="w-3 h-3 bg-green-500 rounded-full mr-3"></div>
            <span className="text-gray-700">Database</span>
          </div>
          <div className="flex items-center">
            <div className="w-3 h-3 bg-green-500 rounded-full mr-3"></div>
            <span className="text-gray-700">API Gateway</span>
          </div>
          <div className="flex items-center">
            <div className="w-3 h-3 bg-green-500 rounded-full mr-3"></div>
            <span className="text-gray-700">File Storage</span>
          </div>
        </div>
      </div>
    </HoneypotLayout>
  )
}

// Helper component for service cards
function ServiceCard({ to, icon, title, desc }) {
  return (
    <div className="bg-white shadow rounded-lg p-6 hover:shadow-lg transition-shadow">
      <div className="flex items-center mb-4">
        <span className="text-2xl mr-2">{icon}</span>
        <h3 className="text-lg font-medium text-gray-900">{title}</h3>
      </div>
      <p className="text-gray-600 mb-4">{desc}</p>
      <Link to={to} className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-gray-700 hover:bg-gray-900">Access</Link>
    </div>
  )
}

export default FakeHome