import { useState } from 'react';

const FakeDrupalRegister = () => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(false);
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:5000'}/drupal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password })
      });
      const data = await res.json();
      if (data.success) {
        setSuccess(true);
      } else {
        setError(data.error || 'Registration failed');
      }
    } catch (err) {
      setError('Network error');
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="bg-white shadow-lg rounded-lg p-8 w-full max-w-md">
        <div className="flex flex-col items-center mb-6">
          <img src="/drupal-logo.svg" alt="Drupal" className="h-10 mb-2" />
          <h1 className="text-2xl font-bold text-gray-900">Create new account</h1>
        </div>
        {success ? (
          <div className="bg-green-50 border border-green-200 text-green-800 rounded p-4 text-center mb-4">
            Account created! (Simulated registration success)
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-6">
            <input type="hidden" name="form_id" value="user_register_form" />
            <div>
              <label className="block text-sm font-medium text-gray-700">Username</label>
              <input
                type="text"
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
                value={username}
                onChange={e => setUsername(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Email</label>
              <input
                type="email"
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Password</label>
              <input
                type="password"
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
              />
            </div>
            {error && <div className="text-red-600 text-sm">{error}</div>}
            <button
              type="submit"
              className="w-full py-2 px-4 bg-blue-700 text-white rounded hover:bg-blue-800 transition-colors"
              disabled={loading}
            >
              {loading ? 'Creating account...' : 'Create new account'}
            </button>
          </form>
        )}
        <div className="mt-6 text-center text-xs text-gray-500">
          <p>Drupal 7.58 &copy; Simulated Honeypot</p>
        </div>
      </div>
    </div>
  );
};

export default FakeDrupalRegister;