/**
 * FurtherSecurity API Client
 */

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export type ToolFocus = 'all' | 'security_headers' | 'ssl_tls' | 'cookies'

export interface ScanRequest {
  url: string
  scan_type: 'quick' | 'standard' | 'deep'
  tool_focus?: ToolFocus  // Which specific tool to focus on
}

export interface ScanResponse {
  scan_id: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  message: string
  url: string
  scan_type: string
  created_at: string
}

export interface Finding {
  id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string
  recommendation?: string
  evidence?: string
  cve?: string
}

export interface AIAnalysis {
  // Core recommendation
  executive_summary: string
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  recommendation: 'buy' | 'caution' | 'no-buy'
  confidence: number
  reasoning: string
  
  // Business context
  business_impact: string
  positive_findings: string[]
  critical_concerns: string[]
  
  // Actionable items
  priority_fixes: Array<{
    issue: string
    urgency: 'immediate' | 'soon' | 'later'
    effort: 'low' | 'medium' | 'high'
    fix: string
  }>
  
  // Scores
  trust_score: number
  
  // Buyer/Seller specific advice
  for_buyer?: string
  for_seller?: string
  
  // AI metadata
  ai_model?: string
  ai_provider?: string
  raw_ai_response?: string
  ai_available?: boolean
  ai_error?: string
}

export interface CheckPerformed {
  name: string
  description: string
  status: 'passed' | 'warning' | 'error'
  details: string
  tool: string
}

export interface ResponseMeta {
  status_code?: string
  response_size?: string
  response_time?: string
  target_url?: string
  headers_count?: number
  missing_security_headers_count?: number
  sensitive_info_count?: number
  security_analysis?: string
}

export interface CAIThought {
  timestamp: string
  thought: string
  result: string
}

export interface ScanResult {
  target_url: string
  scan_type: string
  started_at: string
  completed_at?: string
  duration_seconds?: number
  risk_score: number
  trust_score: number
  verdict: 'buy' | 'caution' | 'no-buy'
  findings: Finding[]
  findings_by_severity: Record<string, Finding[]>
  checks_performed?: CheckPerformed[]
  summary: string
  ai_analysis?: AIAnalysis
  // Raw CAI output and parsed data
  cai_raw_output?: string
  response_headers?: Record<string, string>
  response_meta?: ResponseMeta
  // CAI Think tool reasoning trace
  cai_thoughts?: CAIThought[]
}

export interface ScanStatus {
  scan_id: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  progress: number
  current_step: string
  logs: string[]
  result?: ScanResult
}

export interface HealthCheck {
  status: string
  cai_available: boolean
  api_key_configured: boolean
}

export interface UserProfile {
  id: string
  clerk_id: string
  email: string
  name?: string
  avatar_url?: string
  plan: string
  scans_this_month: number
  scan_limit: number
  total_scans?: number
  can_scan?: boolean
}

class APIClient {
  private baseUrl: string
  private authToken?: string

  constructor(baseUrl: string = API_BASE) {
    this.baseUrl = baseUrl
  }

  // Set auth token for authenticated requests
  setAuthToken(token: string) {
    this.authToken = token
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...options.headers as Record<string, string>,
    }
    
    // Add auth token if available
    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`
    }
    
    const response = await fetch(url, {
      ...options,
      headers,
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
      throw new Error(error.detail || `HTTP ${response.status}`)
    }

    return response.json()
  }

  // Health check
  async checkHealth(): Promise<HealthCheck> {
    return this.request<HealthCheck>('/api/scans/health/check')
  }

  // Start a new scan
  async startScan(request: ScanRequest): Promise<ScanResponse> {
    return this.request<ScanResponse>('/api/scans', {
      method: 'POST',
      body: JSON.stringify(request),
    })
  }

  // Get scan status
  async getScanStatus(scanId: string): Promise<ScanStatus> {
    return this.request<ScanStatus>(`/api/scans/${scanId}`)
  }

  // Get scan result
  async getScanResult(scanId: string): Promise<ScanResult> {
    return this.request<ScanResult>(`/api/scans/${scanId}/result`)
  }

  // List all scans
  async listScans(limit: number = 20): Promise<ScanStatus[]> {
    return this.request<ScanStatus[]>(`/api/scans?limit=${limit}`)
  }

  // Poll scan status until complete
  async pollScanStatus(
    scanId: string,
    onUpdate?: (status: ScanStatus) => void,
    intervalMs: number = 2000
  ): Promise<ScanResult> {
    return new Promise((resolve, reject) => {
      const poll = async () => {
        try {
          const status = await this.getScanStatus(scanId)
          
          if (onUpdate) {
            onUpdate(status)
          }

          if (status.status === 'completed' && status.result) {
            resolve(status.result)
          } else if (status.status === 'failed') {
            reject(new Error(status.current_step || 'Scan failed'))
          } else {
            setTimeout(poll, intervalMs)
          }
        } catch (error) {
          reject(error)
        }
      }

      poll()
    })
  }

  // ==================== User API ====================

  // Sync user from Clerk to database (call after sign-in)
  async syncUser(token: string): Promise<{ message: string; user: UserProfile }> {
    this.setAuthToken(token)
    return this.request('/api/users/sync', { method: 'POST' })
  }

  // Get current user profile
  async getProfile(token: string): Promise<UserProfile> {
    this.setAuthToken(token)
    return this.request('/api/users/me')
  }

  // Get user's scan history
  async getUserScans(token: string, limit: number = 20): Promise<{ total: number; scans: ScanStatus[] }> {
    this.setAuthToken(token)
    return this.request(`/api/users/scans?limit=${limit}`)
  }

  // Get scan from database (requires auth)
  async getScanFromHistory(scanId: string): Promise<ScanResult> {
    return this.request<ScanResult>(`/api/scans/history/${scanId}`)
  }
}

// Export singleton instance
export const api = new APIClient()

// Export class for custom instances
export { APIClient }

