import { useState, useEffect } from 'react'
import { Lock } from 'lucide-react'

interface PasswordGateProps {
  children: React.ReactNode
}

// Access keys - from env or fallback
const getValidKeys = (): string[] => {
  const keys: string[] = []
  const envKey = import.meta.env.VITE_ACCESS_KEY
  if (envKey) keys.push(envKey)
  // Fallback for development
  if (import.meta.env.DEV) keys.push('demo123')
  return keys
}

const PasswordGate = ({ children }: PasswordGateProps) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [password, setPassword] = useState('')
  const [error, setError] = useState(false)

  useEffect(() => {
    const validKeys = getValidKeys()
    
    // Check URL param first
    const params = new URLSearchParams(window.location.search)
    const keyParam = params.get('key')
    if (keyParam && validKeys.includes(keyParam)) {
      setIsAuthenticated(true)
      // Store in session so they don't need key every time
      sessionStorage.setItem('fs_auth', 'true')
      return
    }

    // Check session storage
    if (sessionStorage.getItem('fs_auth') === 'true') {
      setIsAuthenticated(true)
      return
    }

    // Check localStorage for persistent access
    if (localStorage.getItem('fs_auth') === 'true') {
      setIsAuthenticated(true)
    }
  }, [])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const validKeys = getValidKeys()
    if (validKeys.includes(password)) {
      setIsAuthenticated(true)
      localStorage.setItem('fs_auth', 'true')
      setError(false)
    } else {
      setError(true)
    }
  }

  if (isAuthenticated) {
    return <>{children}</>
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        <div className="glass-card border border-primary/40 rounded-2xl p-8 text-center">
          <div className="w-16 h-16 bg-primary/20 rounded-2xl flex items-center justify-center mx-auto mb-6">
            <Lock className="h-8 w-8 text-primary-300" />
          </div>
          
          <h1 className="text-2xl font-ropa-sans text-white mb-2">
            Private Beta Access
          </h1>
          <p className="text-gray-400 mb-6">
            This area is restricted to testers only.
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter access code"
              className={`w-full bg-background border ${error ? 'border-red-500' : 'border-gray-700'} text-white px-4 py-3 rounded-xl outline-none focus:border-primary transition-colors`}
            />
            {error && (
              <p className="text-red-400 text-sm">Invalid access code</p>
            )}
            <button
              type="submit"
              className="w-full bg-primary hover:bg-primary-600 text-white px-4 py-3 rounded-xl font-medium transition-colors"
            >
              Access Beta
            </button>
          </form>

          <p className="text-gray-500 text-xs mt-6">
            Contact us for beta access
          </p>
        </div>
      </div>
    </div>
  )
}

export default PasswordGate

