const StatCard = ({ 
  icon: Icon, 
  title, 
  value, 
  loading = false, 
  bgColor = 'bg-white', 
  iconColor = 'text-blue-500',
  textColor = 'text-gray-900',
  titleColor = 'text-gray-600'
}) => {
  return (
    <div className={`${bgColor} rounded-lg shadow p-6`}>
      <div className="flex items-center">
        <Icon className={`h-8 w-8 ${iconColor} mr-4`} />
        <div>
          <p className={`text-sm ${titleColor}`}>{title}</p>
          {loading ? (
            <div className="flex items-center space-x-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500"></div>
              <span className="text-sm text-gray-500">Loading...</span>
            </div>
          ) : (
            <p className={`text-2xl font-bold ${textColor}`}>
              {value !== undefined && value !== null ? value : '0'}
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

export default StatCard