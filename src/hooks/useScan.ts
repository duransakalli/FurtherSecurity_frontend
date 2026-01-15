/**
 * React hooks for scan operations
 * Supports authenticated scans (saved to DB) and unauthenticated scans (in-memory)
 */
import { useState, useCallback, useEffect } from 'react'
import { useAuth } from '@clerk/clerk-react'
import { api, ScanRequest, ScanStatus, ScanResult, HealthCheck } from '../lib/api'

export interface UseScanOptions {
  onComplete?: (result: ScanResult) => void
  onError?: (error: Error) => void
  pollInterval?: number
}

export function useScan(options: UseScanOptions = {}) {
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [result, setResult] = useState<ScanResult | null>(null)
  const { getToken } = useAuth()

  const startScan = useCallback(async (request: ScanRequest) => {
    setIsLoading(true)
    setError(null)
    setStatus(null)
    setResult(null)

    try {
      // Get auth token if user is logged in
      const token = await getToken()
      if (token) {
        api.setAuthToken(token)
      }

      // Start the scan
      const response = await api.startScan(request)
      
      // Poll for updates
      const finalResult = await api.pollScanStatus(
        response.scan_id,
        (status) => setStatus(status),
        options.pollInterval || 2000
      )

      setResult(finalResult)
      options.onComplete?.(finalResult)
      
      return finalResult
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err))
      setError(error)
      options.onError?.(error)
      throw error
    } finally {
      setIsLoading(false)
    }
  }, [options, getToken])

  const reset = useCallback(() => {
    setIsLoading(false)
    setError(null)
    setStatus(null)
    setResult(null)
  }, [])

  return {
    startScan,
    reset,
    isLoading,
    error,
    status,
    result,
    progress: status?.progress || 0,
    currentStep: status?.current_step || '',
    logs: status?.logs || [],
  }
}

export function useHealthCheck() {
  const [health, setHealth] = useState<HealthCheck | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const checkHealth = useCallback(async () => {
    setIsLoading(true)
    try {
      const result = await api.checkHealth()
      setHealth(result)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)))
      setHealth(null)
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    checkHealth()
  }, [checkHealth])

  return {
    health,
    isLoading,
    error,
    isHealthy: health?.status === 'ok',
    caiAvailable: health?.cai_available || false,
    apiKeyConfigured: health?.api_key_configured || false,
    refresh: checkHealth,
  }
}

export function useScanHistory() {
  const [scans, setScans] = useState<ScanStatus[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const { getToken, isSignedIn } = useAuth()

  const fetchScans = useCallback(async (limit: number = 20) => {
    setIsLoading(true)
    try {
      // Get auth token if user is logged in
      const token = await getToken()
      if (token) {
        api.setAuthToken(token)
      }
      
      const result = await api.listScans(limit)
      setScans(result)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)))
    } finally {
      setIsLoading(false)
    }
  }, [getToken])

  useEffect(() => {
    // Only fetch if user is signed in (for DB scans) or always (for in-memory)
    fetchScans()
  }, [fetchScans, isSignedIn])

  return {
    scans,
    isLoading,
    error,
    refresh: fetchScans,
  }
}

