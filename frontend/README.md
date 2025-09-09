# 🎭 HoneyGuard Frontend

**React-based Frontend for HoneyGuard Honeypot System**

The HoneyGuard frontend is a sophisticated React application that serves dual purposes: providing realistic honeypot interfaces to attract attackers and offering a comprehensive administrative dashboard for monitoring and analyzing threats in real-time.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Honeypot UI   │    │   Admin Panel   │    │   Backend API   │
│                 │    │                 │    │                 │
│ • Fake Logins   │    │ • Real Dashboard│◄──►│ • Authentication│
│ • CMS Interfaces│    │ • Log Analysis  │    │ • Log Management│
│ • Admin Panels  │    │ • Statistics    │    │ • Threat Intel  │
│ • API Endpoints │    │ • File Explorer │    │ • Real-time Data│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Dual Interface Design

**Public Honeypot Interface:**
- Realistic-looking login pages and admin panels
- Simulated vulnerabilities and services
- Automatic attack logging via LogGenerator
- Convincing error messages and responses

**Protected Admin Interface:**
- Real-time threat monitoring dashboard
- Advanced log analysis and filtering
- Statistical analysis and reporting
- File upload analysis and management

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- npm or yarn
- Running HoneyGuard backend
- Backend API running with Redis Cloud configured
- AbuseIPDB API key configured in backend (optional, for enhanced threat analysis)

### Installation

1. **Navigate to frontend directory:**
```bash
cd frontend
```

2. **Install dependencies:**
```bash
npm install
# or
yarn install
```

3. **Configure environment:**
```bash
cp env.example .env
# Edit .env with your configuration
```

4. **Start development server:**
```bash
npm run dev
# or
yarn dev
```

5. **Build for production:**
```bash
npm run build
npm run preview
# or
yarn build
yarn preview
```

## ⚙️ Configuration

### Environment Variables

```env
# Backend API Configuration
VITE_API_URL=http://localhost:5000

# Security Configuration
VITE_AUTH_ROUTE_PREFIX=your-custom-auth-prefix
VITE_REAL_DASHBOARD_ROUTE=/your-real-dashboard-route

# Development Settings
VITE_DEV_MODE=true
```

### Backend Dependencies

The frontend requires the backend to be properly configured with:
- **Redis Cloud**: For real-time data and session management
- **AbuseIPDB API**: For enhanced IP reputation analysis (optional)
- **Telegram Bot**: For notifications (optional)

### Configuration Details

- **VITE_API_URL**: Backend API base URL
- **VITE_AUTH_ROUTE_PREFIX**: Custom authentication route prefix (must match backend)
- **VITE_REAL_DASHBOARD_ROUTE**: Hidden route for real admin dashboard

## 📁 Project Structure

```
frontend/
├── src/
│   ├── App.jsx                 # Main application component
│   ├── main.jsx               # Application entry point
│   ├── index.css              # Global styles
│   ├── components/            # Reusable components
│   │   ├── auth/              # Authentication components
│   │   │   └── UnifiedProtectedRoute.jsx
│   │   ├── common/            # Common UI components
│   │   │   └── StatCard.jsx
│   │   ├── dashboard/         # Admin dashboard components
│   │   │   ├── AdvancedLogs.jsx
│   │   │   ├── AdvancedStats.jsx
│   │   │   ├── HoneypotExplorer.jsx
│   │   │   └── UploadedFiles.jsx
│   │   ├── honeypot/          # Honeypot-specific components
│   │   │   └── LogGenerator.jsx
│   │   └── layout/            # Layout components
│   │       └── HoneypotLayout.jsx
│   ├── hooks/                 # Custom React hooks
│   │   ├── useDashboard.js
│   │   └── useHoneyGuard.js
│   ├── pages/                 # Page components
│   │   ├── honeypot/          # Honeypot pages
│   │   │   ├── FakeAPI.jsx
│   │   │   ├── FakeAdmin.jsx
│   │   │   ├── FakeDashboard.jsx
│   │   │   ├── FakeDrupalLogin.jsx
│   │   │   ├── FakeDrupalRegister.jsx
│   │   │   ├── FakeHome.jsx
│   │   │   ├── FakeJoomlaLogin.jsx
│   │   │   ├── FakeLogin.jsx
│   │   │   ├── FakeMagentoLogin.jsx
│   │   │   ├── FakePhpMyAdminLogin.jsx
│   │   │   ├── FakeSandbox.jsx
│   │   │   └── FakeWordPress.jsx
│   │   └── real/              # Real admin pages
│   │       └── RealDashboard.jsx
│   ├── services/              # API services
│   │   ├── api.js
│   │   └── authService.js
│   └── utils/                 # Utility functions
│       ├── backendCheck.js
│       └── formatters.js
├── public/
│   └── shield-favicon.svg     # Application favicon
├── package.json               # Dependencies and scripts
├── vite.config.js            # Vite configuration
├── tailwind.config.js        # TailwindCSS configuration
├── postcss.config.js         # PostCSS configuration
└── eslint.config.js          # ESLint configuration
```

## 🎭 Honeypot Components

### Login Pages

#### Generic Login (`FakeLogin.jsx`)
- **Route**: `/login`
- **Purpose**: Generic admin login simulation
- **Features**: 
  - Realistic form validation
  - "Valid" credentials for deeper engagement
  - Progressive failure messages
  - Automatic log generation

#### WordPress Login (`FakeWordPress.jsx`)
- **Route**: `/wp-login.php`, `/wp-admin`
- **Purpose**: WordPress admin simulation
- **Features**:
  - Authentic WordPress styling
  - Version information display
  - Brute force detection simulation

#### CMS Logins
- **Drupal**: `/drupal/user/login` (`FakeDrupalLogin.jsx`)
- **Joomla**: `/joomla/administrator` (`FakeJoomlaLogin.jsx`)
- **Magento**: `/magento/admin` (`FakeMagentoLogin.jsx`)
- **phpMyAdmin**: `/phpmyadmin` (`FakePhpMyAdminLogin.jsx`)

### Administrative Interfaces

#### Fake Admin Panel (`FakeAdmin.jsx`)
- **Route**: `/admin`
- **Purpose**: Generic administrative interface
- **Features**:
  - Dashboard simulation
  - User management interface
  - System settings panels

#### Fake Dashboard (`FakeDashboard.jsx`)
- **Route**: `/dashboard`
- **Purpose**: Application dashboard simulation
- **Features**:
  - Statistics display
  - File management interface
  - Settings panels

### API and Development Tools

#### Fake API Explorer (`FakeAPI.jsx`)
- **Route**: `/api`
- **Purpose**: API documentation and testing interface
- **Features**:
  - Swagger-like interface
  - API endpoint documentation
  - Interactive testing tools

#### Fake Sandbox (`FakeSandbox.jsx`)
- **Route**: `/sandbox`
- **Purpose**: File analysis and testing environment
- **Features**:
  - File upload interface
  - Analysis results display
  - Security scanning simulation

### Home and Landing Pages

#### Fake Home (`FakeHome.jsx`)
- **Route**: `/`
- **Purpose**: Realistic application homepage
- **Features**:
  - Company/service information
  - Navigation to other honeypot services
  - Contact and about sections

## 🛡️ Admin Dashboard Components

### Real Dashboard (`RealDashboard.jsx`)

The main administrative interface providing comprehensive threat monitoring.

#### Features:
- **Real-time Statistics**: Live attack metrics and trends
- **Recent Attacks**: Latest honeypot interactions
- **Geographic Analysis**: Attack source mapping
- **Threat Classification**: Attack type categorization
- **System Health**: Honeypot system status

#### Sections:
1. **Overview**: High-level statistics and recent activity
2. **Advanced Logs**: Detailed log analysis and filtering
3. **Statistics**: Comprehensive attack analytics
4. **Files**: Uploaded file analysis
5. **Explorer**: Honeypot service testing

### Advanced Components

#### AdvancedLogs (`AdvancedLogs.jsx`)
- **Purpose**: Detailed log analysis interface
- **Features**:
  - Real-time log streaming
  - Advanced filtering and search
  - Export capabilities
  - Threat level classification

#### AdvancedStats (`AdvancedStats.jsx`)
- **Purpose**: Statistical analysis and reporting
- **Features**:
  - Interactive charts and graphs
  - Trend analysis
  - Geographic distribution
  - Attack pattern recognition

#### UploadedFiles (`UploadedFiles.jsx`)
- **Purpose**: File upload analysis
- **Features**:
  - File metadata display
  - Security analysis results
  - Download and quarantine options
  - Threat assessment

#### HoneypotExplorer (`HoneypotExplorer.jsx`)
- **Purpose**: Interactive honeypot testing
- **Features**:
  - Service endpoint testing
  - Response analysis
  - Custom payload testing
  - Real-time monitoring

## 🔧 Core Services

### API Service (`api.js`)

Comprehensive API client with organized service modules:

#### Authentication
```javascript
import authService from './authService'

// Login
const token = await authService.login(password)

// Verify token
const isValid = await authService.verifyToken()

// Logout
await authService.logout()
```

#### Logs Management
```javascript
import { logsService } from './api'

// Get all logs
const logs = await logsService.getAllLogs()

// Get analysis
const analysis = await logsService.getAnalysis()

// Filter by fingerprint
const filtered = await logsService.getLogsByFingerprint('wp_bruteforce')
```

#### Honeypot Services
```javascript
import { cmsHoneypotService } from './api'

// Test WordPress
const result = await cmsHoneypotService.testWordPress({
  username: 'admin',
  password: 'password123'
})
```

### Service Categories

1. **logsService**: Log management and analysis
2. **statsService**: Statistical data and analytics
3. **realtimeService**: Real-time data streaming
4. **sandboxService**: File analysis and scanning
5. **adminHoneypotService**: Admin panel simulation
6. **apiHoneypotService**: API endpoint simulation
7. **vulnerabilityHoneypotService**: Vulnerability testing
8. **cveHoneypotService**: CVE simulation
9. **networkHoneypotService**: Network service simulation
10. **cmsHoneypotService**: CMS platform simulation
11. **fileHoneypotService**: File exposure simulation
12. **panelHoneypotService**: Control panel simulation
13. **utilityHoneypotService**: Utility service simulation
14. **webhookHoneypotService**: Webhook simulation

## 🪝 Custom Hooks

### useHoneyGuard (`useHoneyGuard.js`)

Main hook for honeypot data management:

```javascript
import { useHoneyGuard } from '../hooks/useHoneyGuard'

const {
  stats,           // General statistics
  recentLogs,      // Recent attack logs
  analysisData,    // Analysis results
  loading,         // Loading state
  error,           // Error state
  refresh          // Refresh function
} = useHoneyGuard()
```

### useDashboard (`useDashboard.js`)

Specialized hook for dashboard functionality:

```javascript
import { useDashboard } from '../hooks/useDashboard'

const {
  dashboardData,   // Dashboard-specific data
  filters,         // Active filters
  setFilters,      // Filter management
  exportData       // Data export function
} = useDashboard()
```

## 🎨 Styling and UI

### TailwindCSS Configuration

Custom theme configuration for honeypot aesthetics:

```javascript
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      colors: {
        honeypot: {
          primary: '#1e40af',
          secondary: '#dc2626',
          accent: '#059669'
        }
      }
    }
  }
}
```

### Component Styling

- **Honeypot Pages**: Authentic styling mimicking real applications
- **Admin Dashboard**: Modern, professional interface
- **Responsive Design**: Mobile-friendly layouts
- **Dark/Light Themes**: Adaptive color schemes

## 🔐 Authentication and Security

### Protected Routes

```javascript
// UnifiedProtectedRoute.jsx
<UnifiedProtectedRoute>
  <RealDashboard />
</UnifiedProtectedRoute>
```

### JWT Token Management

```javascript
// Automatic token handling
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})
```

### Security Features

1. **Route Protection**: Admin routes require authentication
2. **Token Validation**: Automatic token verification
3. **Secure Storage**: Proper token storage practices
4. **Session Management**: Automatic logout on token expiry

## 📊 Real-time Features

### Log Generation

Automatic attack logging via LogGenerator component:

```javascript
// LogGenerator usage
<LogGenerator 
  endpoint="/wp-login.php"
  method="POST"
  data={{ username, password }}
  delay={1000}
/>
```

### Live Updates

- **Real-time Statistics**: Auto-refreshing metrics
- **Live Log Streaming**: Immediate attack visibility
- **Dynamic Charts**: Real-time data visualization
- **Instant Notifications**: Critical threat alerts

## 🧪 Development

### Development Server

```bash
# Start development server
npm run dev

# Access at http://localhost:5173
```

### Building for Production

```bash
# Build optimized bundle
npm run build

# Preview production build
npm run preview

# Lint code
npm run lint
```

### Adding New Honeypot Pages

1. **Create Component:**
```javascript
// src/pages/honeypot/FakeNewService.jsx
import LogGenerator from '../../components/honeypot/LogGenerator'

const FakeNewService = () => {
  return (
    <>
      <LogGenerator endpoint="/newservice" method="GET" />
      <div className="min-h-screen bg-gray-100">
        {/* Your honeypot interface */}
      </div>
    </>
  )
}

export default FakeNewService
```

2. **Add Route:**
```javascript
// src/App.jsx
import FakeNewService from './pages/honeypot/FakeNewService'

<Route path="/newservice" element={<FakeNewService />} />
```

3. **Add API Service:**
```javascript
// src/services/api.js
export const newServiceHoneypotService = {
  testNewService: async (data) => {
    const response = await api.post('/newservice', data)
    return response.data
  }
}
```

### Code Quality

```bash
# Run ESLint
npm run lint

# Build for production
npm run build
```

## 🔧 Configuration and Customization

### Vite Configuration

```javascript
// vite.config.js
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true
      }
    }
  }
})
```

### Environment-specific Builds

```bash
# Development build
npm run dev

# Production build
npm run build

# Staging build
VITE_API_URL=https://staging-api.example.com npm run build
```

## 📱 Responsive Design

### Breakpoints

- **Mobile**: 320px - 768px
- **Tablet**: 768px - 1024px
- **Desktop**: 1024px+

### Mobile Optimization

- Touch-friendly interfaces
- Optimized honeypot forms
- Responsive admin dashboard
- Mobile-specific navigation

## 🚀 Performance Optimization

### Bundle Optimization

```javascript
// Lazy loading for better performance
const RealDashboard = lazy(() => import('./pages/real/RealDashboard'))
const FakeWordPress = lazy(() => import('./pages/honeypot/FakeWordPress'))
```

### Caching Strategy

- **API Response Caching**: Intelligent cache management
- **Static Asset Caching**: Optimized asset delivery
- **Static Asset Optimization**: Vite handles asset optimization

### Performance Metrics

- **First Contentful Paint**: <1.5s
- **Largest Contentful Paint**: <2.5s
- **Time to Interactive**: <3.5s
- **Bundle Size**: <500KB gzipped

## 🐛 Debugging and Troubleshooting

### Development Tools

```javascript
// Enable debug logging
const DEBUG = import.meta.env.DEV

if (DEBUG) {
  console.log('🎯 Debug info:', data)
}
```

### Common Issues

#### API Connection Issues
```bash
# Verify environment variables
echo $VITE_API_URL
```

#### Authentication Problems
```javascript
// Clear stored tokens
localStorage.removeItem('auth_token')

// Check token validity
const token = localStorage.getItem('auth_token')
console.log('Token:', token)
```

#### Build Issues
```bash
# Clear node modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Clear Vite cache
npm run dev -- --force
```

## 📚 Dependencies

### Core Dependencies

```json
{
  "react": "^19.1.0",
  "react-dom": "^19.1.0",
  "react-router-dom": "^7.6.2",
  "axios": "^1.10.0",
  "lucide-react": "^0.522.0",
  "date-fns": "^4.1.0"
}
```

### Development Dependencies

```json
{
  "@eslint/js": "^9.25.0",
  "@types/react": "^19.1.2",
  "@types/react-dom": "^19.1.2",
  "@vitejs/plugin-react": "^4.4.1",
  "autoprefixer": "^10.4.21",
  "eslint": "^9.25.0",
  "eslint-plugin-react-hooks": "^5.2.0",
  "eslint-plugin-react-refresh": "^0.4.19",
  "globals": "^16.0.0",
  "postcss": "^8.5.6",
  "tailwindcss": "^3.4.17",
  "vite": "^6.3.5"
}
```

## 🔄 Deployment

### Static Hosting

```bash
# Build for production
npm run build

# Deploy to static hosting (Netlify, Vercel, etc.)
# Upload dist/ folder
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM node:18-alpine as build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### Environment Configuration

```bash
# Production environment
VITE_API_URL=https://api.yourdomain.com
VITE_AUTH_ROUTE_PREFIX=secure-admin-path
VITE_REAL_DASHBOARD_ROUTE=/hidden-dashboard
```

## 📈 Analytics and Monitoring

### User Interaction Tracking

- **Honeypot Engagement**: Track attacker behavior
- **Form Submissions**: Monitor credential attempts
- **Navigation Patterns**: Analyze attack flows
- **Error Rates**: Monitor application health

### Performance Monitoring

- **Build Size**: Monitor bundle size with Vite
- **API Response Times**: Monitor backend connectivity
- **Development Tools**: Use React DevTools for debugging
- **Network Monitoring**: Track API calls in browser DevTools

### External API Integration
- **AbuseIPDB**: Displays IP reputation scores and threat levels
- **Geolocation**: Shows attack origin on world map
- **Telegram**: Real-time notification system

## 🤝 Contributing

### Development Workflow

1. **Fork Repository**: Create your own fork
2. **Create Branch**: `git checkout -b feature/new-honeypot`
3. **Develop**: Add your changes
4. **Test**: Ensure all tests pass
5. **Submit PR**: Create pull request

### Code Standards

- **ESLint**: Follow configured linting rules
- **Prettier**: Use consistent code formatting
- **Component Structure**: Follow established patterns
- **Documentation**: Document new components

---

**For backend documentation, see [../backend/README.md](../backend/README.md)**

**For project overview, see [../README.md](../README.md)**