import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'

const HoneypotLayout = ({ children }) => {
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const location = useLocation()

  const navigation = [
    { name: 'Home', href: '/', current: location.pathname === '/' },
    { name: 'Login', href: '/login', current: location.pathname === '/login' },
    { name: 'Dashboard', href: '/dashboard', current: location.pathname === '/dashboard' },
    { name: 'Admin', href: '/admin', current: location.pathname === '/admin' },
    { name: 'WordPress', href: '/wp-admin', current: location.pathname === '/wp-admin' },
  ]

  const adminLinks = [
    { name: 'Admin Panel', href: '/admin', description: 'Administrative interface' },
    { name: 'WordPress Admin', href: '/wp-admin', description: 'WordPress administration' },
    { name: 'User Management', href: '/admin/users', description: 'Manage system users' },
    { name: 'System Settings', href: '/admin/settings', description: 'Configure system' },
    { name: 'Backup', href: '/admin/backup', description: 'System backup' },
  ]

  const serviceLinks = [
    { name: 'API Documentation', href: '/api-docs', description: 'REST API documentation' },
    { name: 'File Upload', href: '/upload', description: 'File upload service' },
    { name: 'Database', href: '/database', description: 'Database interface' },
    { name: 'FTP Service', href: '/ftp', description: 'File transfer protocol' },
    { name: 'SSH Access', href: '/ssh', description: 'Secure shell access' },
    { name: 'Webmail', href: '/webmail', description: 'Email interface' },
  ]

  const vulnerabilityLinks = [
    { name: 'CVE Database', href: '/cves', description: 'Vulnerability database' },
    { name: 'Struts2 Test', href: '/struts2', description: 'Apache Struts2 application' },
    { name: 'Spring4Shell', href: '/spring', description: 'Spring Boot application' },
    { name: 'File Upload', href: '/sandbox', description: 'File upload service' },
    { name: 'Debug Logs', href: '/debug.log', description: 'System debug logs' },
    { name: 'Configuration', href: '/config.php', description: 'System configuration' },
  ]

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            {/* Logo */}
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Link to="/" className="flex items-center">
                  <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                    <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  </div>
                  <span className="ml-2 text-xl font-bold text-gray-900">SecureCorp</span>
                </Link>
              </div>
            </div>

            {/* Desktop Navigation */}
            <nav className="hidden md:flex space-x-8">
              {navigation.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`px-3 py-2 rounded-md text-sm font-medium ${
                    item.current
                      ? 'bg-blue-100 text-blue-700'
                      : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
                  }`}
                >
                  {item.name}
                </Link>
              ))}
            </nav>

            {/* User Menu */}
            <div className="flex items-center space-x-4">
              <div className="hidden md:flex items-center space-x-2 text-sm text-gray-500">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span>System Online</span>
              </div>
              
              {/* Mobile menu button */}
              <button
                onClick={() => setIsMenuOpen(!isMenuOpen)}
                className="md:hidden p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <div className="md:hidden">
            <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3 bg-gray-50 border-t border-gray-200">
              {navigation.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`block px-3 py-2 rounded-md text-base font-medium ${
                    item.current
                      ? 'bg-blue-100 text-blue-700'
                      : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
                  }`}
                  onClick={() => setIsMenuOpen(false)}
                >
                  {item.name}
                </Link>
              ))}
            </div>
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {children}
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 mt-auto">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-8">
            {/* Company Info */}
            <div className="col-span-1 md:col-span-2">
              <h3 className="text-sm font-semibold text-gray-400 tracking-wider uppercase">SecureCorp Enterprise</h3>
              <p className="mt-2 text-sm text-gray-500">
                Advanced security management platform for enterprise environments.
              </p>
            </div>

            {/* Admin Links */}
            <div>
              <h3 className="text-sm font-semibold text-gray-400 tracking-wider uppercase">Administration</h3>
              <ul className="mt-2 space-y-2">
                {adminLinks.slice(0, 3).map((link) => (
                  <li key={link.name}>
                    <Link
                      to={link.href}
                      className="text-sm text-gray-500 hover:text-gray-700"
                      title={link.description}
                    >
                      {link.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            {/* Services */}
            <div>
              <h3 className="text-sm font-semibold text-gray-400 tracking-wider uppercase">Services</h3>
              <ul className="mt-2 space-y-2">
                {serviceLinks.slice(0, 3).map((link) => (
                  <li key={link.name}>
                    <Link
                      to={link.href}
                      className="text-sm text-gray-500 hover:text-gray-700"
                      title={link.description}
                    >
                      {link.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            {/* Vulnerabilities */}
            <div>
              <h3 className="text-sm font-semibold text-gray-400 tracking-wider uppercase">Security</h3>
              <ul className="mt-2 space-y-2">
                {vulnerabilityLinks.slice(0, 3).map((link) => (
                  <li key={link.name}>
                    <Link
                      to={link.href}
                      className="text-sm text-gray-500 hover:text-gray-700"
                      title={link.description}
                    >
                      {link.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="mt-8 pt-8 border-t border-gray-200">
            <p className="text-xs text-gray-400 text-center">
              © {new Date().getFullYear()} SecureCorp. All rights reserved. | Version 2.3.1 | 
              <span className="ml-2 text-green-500">●</span> Secure Connection
            </p>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default HoneypotLayout