import { useState, useEffect } from 'react'
import { 
  Search, 
  Globe, 
  Shield, 
  FileText, 
  Server, 
  Code, 
  AlertTriangle,
  CheckCircle,
  Clock,
  Zap,
  Brain,
  Settings,
  ChevronRight,
  Loader2,
  XCircle,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  History,
  Play,
  Target,
  Eye,
  Database,
  Lock,
  Cookie,
  Radar,
  FileSearch,
  ShieldCheck,
  TrendingUp,
  Menu,
  X,
  Network,
  Fingerprint,
  Bug,
  Wrench,
  FileWarning,
  ShieldAlert,
  Skull,
  Activity,
  BookOpen,
  BarChart3,
  FileJson,
  FileType,
  Key,
  Cpu,
  type LucideIcon
} from 'lucide-react'
import { useUser, useAuth, UserButton } from '@clerk/clerk-react'
import { useScan, useHealthCheck, useScanHistory } from '../hooks/useScan'
import type { ScanResult, Finding, CheckPerformed } from '../lib/api'
import { api } from '../lib/api'

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL & CATEGORY DEFINITIONS - 7 Categories, 37 Tools (15 Ready ✅, 22 Coming Soon 🔜)
// 
// CAI Tools Used:
//   - cai.tools.web.headers.web_request_framework (Security Headers, SSL/TLS, Cookies)
//   - cai.tools.misc.reasoning.think (AI Reasoning logging)
//   - cai.tools.reconnaissance.shodan (Coming: shodan_search, shodan_host_info)
//   - cai.tools.reconnaissance.generic_linux_command (Coming: nmap, dig, subfinder)
//   - Claude AI (claude-sonnet-4-20250514) for AI analysis
// ═══════════════════════════════════════════════════════════════════════════════

interface Tool {
  id: string
  name: string
  description: string        // Short tagline (user-benefit focused)
  longDescription: string    // Detailed explanation
  userBenefit: string        // "You'll learn..." / "Know if..."
  status: 'available' | 'coming-soon'
  icon: LucideIcon
  caiTool: string            // The actual CAI tool/function used
  caiAgent: string           // Which CAI agent powers this tool
}

interface Category {
  id: string
  name: string
  description: string
  icon: LucideIcon
  color: string
  emoji: string
  tools: Tool[]
}

const categories: Category[] = [
  // ─────────────────────────────────────────────────────────────────────────────
  // 1️⃣ RECONNAISSANCE (6 tools) - 0 ready, 6 coming soon
  // CAI Agent: bug_bounter_agent, one_tool_agent
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'reconnaissance',
    name: 'Reconnaissance',
    description: 'Discover what attackers can see from the outside',
    icon: Search,
    color: 'blue',
    emoji: '🔍',
    tools: [
      { 
        id: 'network-scan', 
        name: 'Network Scanning', 
        description: 'See what\'s visible to attackers',
        longDescription: 'Discover live hosts and network topology. Find out what an attacker can see when they first look at the target.',
        userBenefit: 'Know the full attack surface before buying',
        status: 'coming-soon', 
        icon: Network, 
        caiTool: 'generic_linux_command (nmap)',
        caiAgent: 'one_tool_agent'
      },
      { 
        id: 'port-scan', 
        name: 'Port Scanning', 
        description: 'Find open doors hackers could enter',
        longDescription: 'Identify open ports, running services, and potential entry points. Every open port is a potential vulnerability.',
        userBenefit: 'Discover hidden services that shouldn\'t be exposed',
        status: 'coming-soon', 
        icon: Server, 
        caiTool: 'generic_linux_command (nmap)',
        caiAgent: 'bug_bounter_agent'
      },
      { 
        id: 'subdomain-enum', 
        name: 'Subdomain Discovery', 
        description: 'Find forgotten or hidden subdomains',
        longDescription: 'Discover all subdomains including staging servers, old apps, and forgotten assets that might be vulnerable.',
        userBenefit: 'Uncover hidden assets the seller might have forgotten',
        status: 'coming-soon', 
        icon: Globe, 
        caiTool: 'generic_linux_command (subfinder)',
        caiAgent: 'bug_bounter_agent'
      },
      { 
        id: 'dns-analysis', 
        name: 'Email Security Check', 
        description: 'Check if emails can be spoofed',
        longDescription: 'Analyze SPF, DKIM, and DMARC records to see if the domain is protected against email spoofing and phishing.',
        userBenefit: 'Know if the domain can be used for phishing attacks',
        status: 'coming-soon', 
        icon: FileSearch, 
        caiTool: 'generic_linux_command (dig)',
        caiAgent: 'dns_smtp_agent'
      },
      { 
        id: 'service-fingerprint', 
        name: 'Technology Versions', 
        description: 'Find outdated software with known exploits',
        longDescription: 'Identify exact versions of running services. Old versions often have known vulnerabilities (CVEs) that attackers exploit.',
        userBenefit: 'Discover if the site runs vulnerable software versions',
        status: 'coming-soon', 
        icon: Fingerprint, 
        caiTool: 'generic_linux_command (nmap -sV)',
        caiAgent: 'bug_bounter_agent'
      },
      { 
        id: 'shodan-search', 
        name: 'Shodan Exposure Check', 
        description: 'See what\'s already publicly indexed',
        longDescription: 'Search Shodan\'s database of internet-connected devices. If it\'s in Shodan, hackers already know about it.',
        userBenefit: 'Find out what attackers already know about this target',
        status: 'coming-soon', 
        icon: Radar, 
        caiTool: 'shodan_search + shodan_host_info',
        caiAgent: 'bug_bounter_agent'
      },
    ]
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 2️⃣ WEB & APP SECURITY (6 tools) - 3 ready ✅, 3 coming soon
  // CAI Agent: web_agent, penetration_tester_agent
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'web-security',
    name: 'Web & App Security',
    description: 'Check how secure the website really is',
    icon: Shield,
    color: 'purple',
    emoji: '🛡️',
    tools: [
      { 
        id: 'security-headers', 
        name: 'Security Headers Check', 
        description: 'Are basic protections in place?',
        longDescription: 'Check essential HTTP headers that protect against XSS, clickjacking, and content sniffing attacks. Missing headers = easy targets.',
        userBenefit: 'Know if the site has basic security hygiene',
        status: 'available', 
        icon: Shield, 
        caiTool: 'cai.tools.web.headers.web_request_framework',
        caiAgent: 'web_agent'
      },
      { 
        id: 'ssl-tls', 
        name: 'SSL/TLS Grade', 
        description: 'Is the connection truly secure?',
        longDescription: 'Analyze the SSL certificate and encryption. Expired certs, weak ciphers, or old TLS versions are serious red flags.',
        userBenefit: 'Ensure customer data is encrypted properly',
        status: 'available', 
        icon: Lock, 
        caiTool: 'cai.tools.web.headers.web_request_framework',
        caiAgent: 'web_agent'
      },
      { 
        id: 'cookie-security', 
        name: 'Session Security', 
        description: 'Can user sessions be hijacked?',
        longDescription: 'Analyze cookies for security flags. Insecure cookies can lead to session hijacking and account takeovers.',
        userBenefit: 'Know if user accounts can be easily stolen',
        status: 'available', 
        icon: Cookie, 
        caiTool: 'cai.tools.web.headers.web_request_framework',
        caiAgent: 'web_agent'
      },
      { 
        id: 'endpoint-discovery', 
        name: 'Hidden Endpoint Finder', 
        description: 'Find exposed admin panels & APIs',
        longDescription: 'Discover hidden API endpoints, admin panels, backup files, and sensitive directories that shouldn\'t be public.',
        userBenefit: 'Uncover exposed admin panels and sensitive files',
        status: 'coming-soon', 
        icon: FileSearch, 
        caiTool: 'generic_linux_command (ffuf)',
        caiAgent: 'penetration_tester_agent'
      },
      { 
        id: 'param-fuzzing', 
        name: 'Injection Vulnerability Test', 
        description: 'Can attackers inject malicious code?',
        longDescription: 'Test for SQL injection, XSS, command injection and other input validation vulnerabilities that lead to data breaches.',
        userBenefit: 'Know if the site is vulnerable to common attacks',
        status: 'coming-soon', 
        icon: Code, 
        caiTool: 'generic_linux_command (ffuf)',
        caiAgent: 'penetration_tester_agent'
      },
      { 
        id: 'auth-flow', 
        name: 'Login Security Audit', 
        description: 'Is the authentication system secure?',
        longDescription: 'Analyze authentication mechanisms, session handling, token management, and password policies for weaknesses.',
        userBenefit: 'Ensure user accounts cannot be easily compromised',
        status: 'coming-soon', 
        icon: Key, 
        caiTool: 'web_request_framework + custom',
        caiAgent: 'web_agent'
      },
    ]
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 3️⃣ VULNERABILITY ANALYSIS (5 tools) - 1 ready ✅, 4 coming soon
  // CAI Agent: vulnerability_scanner_agent, penetration_tester_agent
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'vulnerability',
    name: 'Vulnerability Analysis',
    description: 'Find known security holes before you buy',
    icon: AlertTriangle,
    color: 'red',
    emoji: '⚠️',
    tools: [
      { 
        id: 'cve-correlation', 
        name: 'Known Vulnerability Check', 
        description: 'Are there published exploits?',
        longDescription: 'Search CVE databases for known vulnerabilities in detected software versions. Known CVEs = attackers have ready-made exploits.',
        userBenefit: 'Find out if hackers have published exploits for this site',
        status: 'coming-soon', 
        icon: Bug, 
        caiTool: 'shodan_host_info + CVE API',
        caiAgent: 'vulnerability_scanner_agent'
      },
      { 
        id: 'dependency-analysis', 
        name: 'Vulnerable Libraries', 
        description: 'Are third-party packages safe?',
        longDescription: 'Check if the site uses npm/pip packages with known security vulnerabilities. One bad library = entire site compromised.',
        userBenefit: 'Know if outdated libraries put the site at risk',
        status: 'coming-soon', 
        icon: Database, 
        caiTool: 'execute_code (npm audit)',
        caiAgent: 'code_review_agent'
      },
      { 
        id: 'config-weakness', 
        name: 'Security Misconfiguration', 
        description: 'Are default settings still in place?',
        longDescription: 'Detect default credentials, debug modes left on, exposed config files, and other dangerous misconfigurations.',
        userBenefit: 'Find security settings that were never properly configured',
        status: 'coming-soon', 
        icon: Settings, 
        caiTool: 'generic_linux_command (nuclei)',
        caiAgent: 'penetration_tester_agent'
      },
      { 
        id: 'exposure-scoring', 
        name: 'Risk Score Calculator', 
        description: 'What\'s the overall security grade?',
        longDescription: 'AI-powered risk assessment that weighs all findings and calculates a 0-100 risk score you can compare across sites.',
        userBenefit: 'Get a single number to compare security across acquisitions',
        status: 'available', 
        icon: BarChart3, 
        caiTool: 'internal + Claude AI',
        caiAgent: 'reasoning_agent'
      },
      { 
        id: 'tech-detection', 
        name: 'Tech Stack Analysis', 
        description: 'What technologies power this site?',
        longDescription: 'Identify CMS (WordPress, Shopify), frameworks (React, Laravel), and their versions. Old tech = old vulnerabilities.',
        userBenefit: 'Understand what you\'re inheriting before you buy',
        status: 'coming-soon', 
        icon: Cpu, 
        caiTool: 'web_request_framework + parsing',
        caiAgent: 'web_agent'
      },
    ]
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 4️⃣ DEFENSIVE / MITIGATION (5 tools) - 2 ready ✅, 3 coming soon
  // CAI Agent: reasoning_agent (Claude AI powered)
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'defensive',
    name: 'Fix & Remediation Guides',
    description: 'Know exactly how to fix what\'s broken',
    icon: Wrench,
    color: 'green',
    emoji: '🔧',
    tools: [
      { 
        id: 'header-remediation', 
        name: 'Header Fix Guide', 
        description: 'Step-by-step header implementation',
        longDescription: 'AI-generated guide with exact code snippets to add missing security headers for Apache, Nginx, and Cloudflare.',
        userBenefit: 'Get copy-paste code to fix header issues immediately',
        status: 'available', 
        icon: Shield, 
        caiTool: 'Claude AI + think',
        caiAgent: 'reasoning_agent'
      },
      { 
        id: 'ssl-config-guide', 
        name: 'SSL/TLS Fix Guide', 
        description: 'Secure certificate configuration',
        longDescription: 'Best practices guide for SSL/TLS setup including certificate renewal, cipher selection, and protocol configuration.',
        userBenefit: 'Know exactly how to upgrade to A+ SSL rating',
        status: 'available', 
        icon: Lock, 
        caiTool: 'Claude AI + think',
        caiAgent: 'reasoning_agent'
      },
      { 
        id: 'security-hardening', 
        name: 'Server Hardening Guide', 
        description: 'Lock down the server configuration',
        longDescription: 'AI-tailored recommendations to harden your server based on detected OS, web server, and tech stack.',
        userBenefit: 'Get a personalized security checklist for your specific setup',
        status: 'coming-soon', 
        icon: ShieldCheck, 
        caiTool: 'Claude AI + think',
        caiAgent: 'reasoning_agent'
      },
      { 
        id: 'waf-recommendations', 
        name: 'WAF Setup Guide', 
        description: 'Add a security layer with firewall rules',
        longDescription: 'Web Application Firewall configuration guide with recommended rules for common attacks.',
        userBenefit: 'Know exactly which WAF rules to enable',
        status: 'coming-soon', 
        icon: ShieldAlert, 
        caiTool: 'Claude AI + think',
        caiAgent: 'reasoning_agent'
      },
      { 
        id: 'compliance-checklist', 
        name: 'Compliance Roadmap', 
        description: 'Path to OWASP & PCI-DSS compliance',
        longDescription: 'Gap analysis against OWASP Top 10, PCI-DSS, and SOC 2 requirements with remediation steps.',
        userBenefit: 'Know what\'s needed for compliance before you buy',
        status: 'coming-soon', 
        icon: BookOpen, 
        caiTool: 'Claude AI + think',
        caiAgent: 'reasoning_agent'
      },
    ]
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 5️⃣ THREAT INTELLIGENCE (4 tools) - 0 ready, 4 coming soon
  // CAI Agent: bug_bounter_agent + External APIs (VirusTotal, HIBP, URLScan)
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'threat-intel',
    name: 'Threat Intelligence',
    description: 'Check the site\'s reputation history',
    icon: Eye,
    color: 'orange',
    emoji: '🕵️',
    tools: [
      { 
        id: 'ip-reputation', 
        name: 'IP Reputation Check', 
        description: 'Is this IP flagged as malicious?',
        longDescription: 'Search threat databases for the server\'s IP. A bad IP reputation can get your emails blocked and customers warned.',
        userBenefit: 'Know if you\'re buying a server with a bad history',
        status: 'coming-soon', 
        icon: Activity, 
        caiTool: 'shodan_search + shodan_host_info',
        caiAgent: 'bug_bounter_agent'
      },
      { 
        id: 'domain-reputation', 
        name: 'Domain Blacklist Check', 
        description: 'Is the domain flagged for spam or malware?',
        longDescription: 'Check if the domain is on spam blacklists, Google Safe Browsing, or phishing databases. Blacklisted = lost traffic.',
        userBenefit: 'Avoid buying a domain that Google will flag as dangerous',
        status: 'coming-soon', 
        icon: Globe, 
        caiTool: 'VirusTotal API',
        caiAgent: 'external_api'
      },
      { 
        id: 'malware-history', 
        name: 'Malware History', 
        description: 'Was this site ever infected?',
        longDescription: 'Search historical scans for malware infections, SEO spam injections, and defacements. Past infections often leave hidden backdoors.',
        userBenefit: 'Discover if the site was hacked before (and maybe still is)',
        status: 'coming-soon', 
        icon: Skull, 
        caiTool: 'URLScan API',
        caiAgent: 'external_api'
      },
      { 
        id: 'breach-database', 
        name: 'Data Breach Check', 
        description: 'Was user data ever leaked?',
        longDescription: 'Check HaveIBeenPwned for breaches involving this domain. A breach history means legal liability and reputation damage.',
        userBenefit: 'Know if you\'re inheriting a data breach liability',
        status: 'coming-soon', 
        icon: FileWarning, 
        caiTool: 'HaveIBeenPwned API',
        caiAgent: 'external_api'
      },
    ]
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 6️⃣ AI REASONING & DECISION (7 tools) - 6 ready ✅, 1 coming soon ⭐ CORE VALUE
  // CAI Agent: reasoning_agent (cai.tools.misc.reasoning.think + Claude claude-sonnet-4-20250514)
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'ai-reasoning',
    name: 'AI Analysis & Decision',
    description: '⭐ Our secret sauce - AI-powered insights',
    icon: Brain,
    color: 'pink',
    emoji: '🧠',
    tools: [
      { 
        id: 'ai-risk-assessment', 
        name: 'AI Risk Assessment', 
        description: 'What\'s the real risk here?',
        longDescription: 'AI analyzes all technical findings and explains what they actually mean for your business in plain English.',
        userBenefit: 'Understand the real-world impact of each security issue',
        status: 'available', 
        icon: Brain, 
        caiTool: 'cai.tools.misc.reasoning.think + Claude',
        caiAgent: 'reasoning_agent'
      },
      { 
        id: 'ai-verdict', 
        name: 'Buy / Caution / No-Buy', 
        description: 'Should you buy this asset?',
        longDescription: 'AI weighs all findings and gives you a clear recommendation with confidence score. Like a security expert in your pocket.',
        userBenefit: 'Get a clear yes/no/maybe with reasoning you can trust',
        status: 'available', 
        icon: TrendingUp, 
        caiTool: 'cai.tools.misc.reasoning.think + Claude',
        caiAgent: 'reasoning_agent'
      },
      { 
        id: 'executive-summary', 
        name: 'Executive Summary', 
        description: 'The bottom line in 60 seconds',
        longDescription: 'A clear, jargon-free summary written for business owners and investors, not security engineers.',
        userBenefit: 'Share with partners or investors without technical translation',
        status: 'available', 
        icon: FileText, 
        caiTool: 'cai.tools.misc.reasoning.think + Claude',
        caiAgent: 'reasoning_agent'
      },
      { 
        id: 'priority-fixes', 
        name: 'Fix Priority List', 
        description: 'What to fix first?',
        longDescription: 'AI-ranked list of issues by urgency, business impact, and effort required. Know where to start.',
        userBenefit: 'Negotiate price based on required fixes',
        status: 'available', 
        icon: Target, 
        caiTool: 'cai.tools.misc.reasoning.think + Claude',
        caiAgent: 'reasoning_agent'
      },
      { 
        id: 'buyer-advice', 
        name: 'Buyer\'s Guide', 
        description: 'What to ask before signing',
        longDescription: 'AI-generated questions to ask the seller, red flags to watch for, and negotiation points based on findings.',
        userBenefit: 'Go into negotiations fully prepared',
        status: 'available', 
        icon: ShieldCheck, 
        caiTool: 'cai.tools.misc.reasoning.think + Claude',
        caiAgent: 'reasoning_agent'
      },
      { 
        id: 'seller-advice', 
        name: 'Seller\'s Prep Guide', 
        description: 'Increase your sale price',
        longDescription: 'Quick wins the seller can fix before sale to improve the security score and justify a higher price.',
        userBenefit: 'Help sellers understand what quick fixes add value',
        status: 'available', 
        icon: Wrench, 
        caiTool: 'cai.tools.misc.reasoning.think + Claude',
        caiAgent: 'reasoning_agent'
      },
      { 
        id: 'comparative-analysis', 
        name: 'Industry Benchmark', 
        description: 'How does it compare to competitors?',
        longDescription: 'See how this asset\'s security stacks up against industry averages and similar sites.',
        userBenefit: 'Know if security is above or below average for this niche',
        status: 'coming-soon', 
        icon: BarChart3, 
        caiTool: 'cai.tools.misc.reasoning.think + Claude',
        caiAgent: 'reasoning_agent'
      },
    ]
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 7️⃣ REPORTING (4 tools) - 3 ready ✅, 1 coming soon
  // Internal: Supabase DB, FastAPI, WeasyPrint/ReportLab
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'reporting',
    name: 'Reports & Export',
    description: 'Save, share, and integrate your results',
    icon: FileText,
    color: 'gray',
    emoji: '📄',
    tools: [
      { 
        id: 'json-report', 
        name: 'JSON Export', 
        description: 'Raw data for developers',
        longDescription: 'Export the complete technical report in JSON format. Perfect for integrating with your own tools or CI/CD pipelines.',
        userBenefit: 'Integrate security checks into your existing workflow',
        status: 'available', 
        icon: FileJson, 
        caiTool: 'Internal (FastAPI response)',
        caiAgent: 'internal'
      },
      { 
        id: 'pdf-report', 
        name: 'PDF Report', 
        description: 'Share with stakeholders',
        longDescription: 'Generate a professional PDF report with branding. Perfect for due diligence packages and investor presentations.',
        userBenefit: 'Include in acquisition documentation',
        status: 'coming-soon', 
        icon: FileType, 
        caiTool: 'WeasyPrint / ReportLab',
        caiAgent: 'internal'
      },
      { 
        id: 'scan-history', 
        name: 'Assessment History', 
        description: 'Track security over time',
        longDescription: 'View all your past assessments. Compare security improvements over time or across multiple acquisition targets.',
        userBenefit: 'Compare multiple sites side-by-side',
        status: 'available', 
        icon: History, 
        caiTool: 'Supabase PostgreSQL',
        caiAgent: 'internal'
      },
      { 
        id: 'api-access', 
        name: 'API Access', 
        description: 'Automate your security checks',
        longDescription: 'RESTful API for programmatic access. Build security checks into your acquisition workflow or portfolio monitoring.',
        userBenefit: 'Automate security checks for your deal flow',
        status: 'available', 
        icon: Code, 
        caiTool: 'FastAPI REST endpoints',
        caiAgent: 'internal'
      },
    ]
  },
]

// Calculate totals
const TOTAL_TOOLS = categories.reduce((acc, cat) => acc + cat.tools.length, 0)
const AVAILABLE_TOOLS = categories.reduce((acc, cat) => 
  acc + cat.tools.filter(t => t.status === 'available').length, 0)

// ═══════════════════════════════════════════════════════════════════════════════
// SCAN RESULT COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

function ScanResultView({ result, onClose, isHistorical = false }: { result: ScanResult; onClose: () => void; isHistorical?: boolean }) {
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'headers' | 'thoughts' | 'raw'>('overview')
  
  const criticalCount = result.findings.filter(f => f.severity === 'critical').length
  const highCount = result.findings.filter(f => f.severity === 'high').length
  const mediumCount = result.findings.filter(f => f.severity === 'medium').length
  const lowCount = result.findings.filter(f => f.severity === 'low').length

  return (
    <div className="bg-gray-900/80 backdrop-blur-sm border border-gray-700/50 rounded-2xl overflow-hidden">
      {/* Historical indicator */}
      {isHistorical && (
        <div className="px-4 py-2 bg-purple-500/10 border-b border-purple-500/20 flex items-center gap-2 flex-wrap">
          <History className="h-4 w-4 text-purple-400" />
          <span className="text-purple-400 text-sm font-medium">Viewing from history</span>
          {(result as any).tool_name && (
            <span className="px-2 py-0.5 bg-purple-500/20 text-purple-300 text-xs rounded font-medium">
              {(result as any).tool_name}
            </span>
          )}
          {result.completed_at && (
            <span className="text-gray-500 text-sm ml-auto">
              {new Date(result.completed_at).toLocaleString()}
            </span>
          )}
        </div>
      )}
      
      {/* Empty report warning */}
      {isHistorical && result.findings.length === 0 && !result.ai_analysis && (
        <div className="px-4 py-3 bg-amber-500/10 border-b border-amber-500/20">
          <div className="flex items-start gap-2">
            <AlertCircle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-amber-400 text-sm font-medium">Incomplete Report</p>
              <p className="text-amber-400/70 text-xs">
                This is an older scan that wasn't fully stored. Run a new scan with the same URL to get complete results.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className={`p-4 ${
        result.verdict === 'buy' ? 'bg-gradient-to-r from-green-500/20 to-transparent' :
        result.verdict === 'caution' ? 'bg-gradient-to-r from-amber-500/20 to-transparent' :
        'bg-gradient-to-r from-red-500/20 to-transparent'
      }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3 flex-wrap">
            <span className={`px-3 py-1 rounded-full text-sm font-bold ${
              result.verdict === 'buy' ? 'bg-green-500 text-white' :
              result.verdict === 'caution' ? 'bg-amber-500 text-black' :
              'bg-red-500 text-white'
            }`}>
              {result.verdict === 'buy' ? '✓ SAFE TO BUY' : 
               result.verdict === 'caution' ? '⚠ CAUTION' : 
               '✗ NOT RECOMMENDED'}
            </span>
            <span className="text-white font-medium">{result.target_url}</span>
            <span className="text-gray-500 text-sm">
              Risk: <span className={result.risk_score <= 30 ? 'text-green-400' : result.risk_score <= 60 ? 'text-amber-400' : 'text-red-400'}>{result.risk_score}/100</span>
            </span>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white p-1">
            <XCircle className="h-5 w-5" />
          </button>
        </div>
      </div>

      {/* AI Summary */}
      {result.ai_analysis?.executive_summary && (
        <div className="px-4 py-3 border-b border-gray-700/50 bg-pink-500/5">
          <div className="flex items-start gap-3">
            <Brain className="h-5 w-5 text-pink-400 shrink-0 mt-0.5" />
            <p className="text-gray-300 text-sm">{result.ai_analysis.executive_summary}</p>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-gray-700/50 text-sm overflow-x-auto">
        {[
          { id: 'overview', label: 'Overview' },
          { id: 'findings', label: `Findings (${result.findings.length})` },
          { id: 'headers', label: 'Headers' },
          { id: 'thoughts', label: `CAI Reasoning (${result.cai_thoughts?.length || 0})` },
          { id: 'raw', label: 'Raw Output' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-4 py-2 transition-colors whitespace-nowrap ${
              activeTab === tab.id ? 'text-primary border-b-2 border-primary' : 'text-gray-500 hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="p-4 max-h-[400px] overflow-y-auto">
        {activeTab === 'overview' && (
          <div className="space-y-4">
            {/* Severity counts */}
            <div className="flex gap-2 flex-wrap">
              {[
                { label: 'Critical', count: criticalCount, bg: 'bg-red-500/10', text: 'text-red-400' },
                { label: 'High', count: highCount, bg: 'bg-orange-500/10', text: 'text-orange-400' },
                { label: 'Medium', count: mediumCount, bg: 'bg-amber-500/10', text: 'text-amber-400' },
                { label: 'Low', count: lowCount, bg: 'bg-blue-500/10', text: 'text-blue-400' },
              ].map(s => (
                <div key={s.label} className={`px-3 py-1.5 rounded-lg ${s.bg} ${s.text} text-sm`}>
                  {s.count} {s.label}
                </div>
              ))}
            </div>

            {/* Priority Fixes */}
            {result.ai_analysis?.priority_fixes?.slice(0, 3).map((fix: any, i: number) => (
              <div key={i} className={`p-3 rounded-lg border-l-4 ${
                fix.urgency === 'immediate' ? 'bg-red-500/10 border-l-red-500' :
                fix.urgency === 'soon' ? 'bg-amber-500/10 border-l-amber-500' :
                'bg-blue-500/10 border-l-blue-500'
              }`}>
                <p className="text-white text-sm font-medium">{fix.issue}</p>
                {fix.fix && <p className="text-gray-400 text-xs mt-1">{fix.fix}</p>}
              </div>
            ))}

            {/* For Buyer/Seller */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {result.ai_analysis?.for_buyer && (
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
                  <h4 className="text-blue-400 text-xs font-medium mb-1">💡 For Buyers</h4>
                  <p className="text-gray-300 text-xs">{result.ai_analysis.for_buyer}</p>
                </div>
              )}
              {result.ai_analysis?.for_seller && (
                <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-3">
                  <h4 className="text-purple-400 text-xs font-medium mb-1">📝 For Sellers</h4>
                  <p className="text-gray-300 text-xs">{result.ai_analysis.for_seller}</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'findings' && (
          <div className="space-y-2">
            {result.findings.length === 0 ? (
              <div className="text-center py-6">
                <CheckCircle className="h-10 w-10 text-green-500 mx-auto mb-2" />
                <p className="text-gray-400 text-sm">No issues found!</p>
              </div>
            ) : (
              result.findings.map((f, i) => (
                <div key={i} className="bg-gray-800/50 rounded-lg p-3">
                  <div className="flex items-start justify-between">
                    <h4 className="text-white text-sm font-medium">{f.title}</h4>
                    <span className={`px-2 py-0.5 rounded text-xs ${
                      f.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      f.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      f.severity === 'medium' ? 'bg-amber-500/20 text-amber-400' :
                      'bg-blue-500/20 text-blue-400'
                    }`}>{f.severity}</span>
                  </div>
                  <p className="text-gray-400 text-xs mt-1">{f.description}</p>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'headers' && (
          <div className="space-y-1">
            {result.response_headers && Object.entries(result.response_headers)
              .filter(([k]) => !k.startsWith('_'))
              .map(([k, v], i) => (
                <div key={i} className="flex text-xs font-mono">
                  <span className="text-gray-400 w-48 shrink-0">{k}:</span>
                  <span className="text-gray-500 break-all">{v}</span>
                </div>
              ))
            }
          </div>
        )}

        {activeTab === 'thoughts' && (
          <div className="space-y-3">
            {result.cai_thoughts && result.cai_thoughts.length > 0 ? (
              <>
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3 mb-4">
                  <p className="text-blue-400 text-xs">
                    🧠 <strong>CAI Think Tool:</strong> These are the reasoning steps CAI used during the assessment.
                  </p>
                </div>
                {result.cai_thoughts.map((thought, i) => (
                  <div key={i} className="bg-gray-800/50 rounded-lg p-3 border-l-2 border-pink-500/50">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-pink-400 text-xs font-medium">Step {i + 1}</span>
                      <span className="text-gray-600 text-xs">
                        {new Date(thought.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <p className="text-gray-300 text-sm">{thought.thought}</p>
                  </div>
                ))}
              </>
            ) : (
              <div className="text-center py-6">
                <Brain className="h-10 w-10 text-gray-600 mx-auto mb-2" />
                <p className="text-gray-500 text-sm">No CAI reasoning logs available</p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'raw' && (
          <pre className="text-xs font-mono text-gray-400 whitespace-pre-wrap">
            {result.cai_raw_output || 'No raw output available'}
          </pre>
        )}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════

const Dashboard = () => {
  const [selectedTool, setSelectedTool] = useState<Tool | null>(null)
  const [expandedCategories, setExpandedCategories] = useState<string[]>(['web-security'])
  const [url, setUrl] = useState('')
  const [userSynced, setUserSynced] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [showHistory, setShowHistory] = useState(false)
  const [historicalResult, setHistoricalResult] = useState<ScanResult | null>(null)
  const [loadingHistory, setLoadingHistory] = useState(false)
  const [historyFilter, setHistoryFilter] = useState<string>('all')
  const [historySearch, setHistorySearch] = useState('')

  const { user, isLoaded: userLoaded } = useUser()
  const { getToken } = useAuth()
  const { isHealthy, caiAvailable } = useHealthCheck()
  const { startScan, isLoading, error, result, progress, currentStep, logs, reset } = useScan()
  const { scans, refresh: refreshScans } = useScanHistory()

  // Sync user
  useEffect(() => {
    const syncUser = async () => {
      if (!userLoaded || !user || userSynced) return
      try {
        const token = await getToken()
        if (token) {
          await api.syncUser(token)
          setUserSynced(true)
        }
      } catch (e) {
        console.error('Failed to sync user:', e)
      }
    }
    syncUser()
  }, [userLoaded, user, userSynced, getToken])

  useEffect(() => {
    if (result) refreshScans()
  }, [result, refreshScans])

  // Load a scan from history
  const loadScanFromHistory = async (scanId: string) => {
    setLoadingHistory(true)
    setHistoricalResult(null)
    try {
      const token = await getToken()
      if (token) {
        api.setAuthToken(token)
      }
      const scanResult = await api.getScanFromHistory(scanId)
      setHistoricalResult(scanResult)
      setShowHistory(false)  // Close history view
      setSelectedTool(null)  // Deselect tool
    } catch (e) {
      console.error('Failed to load scan:', e)
    } finally {
      setLoadingHistory(false)
    }
  }

  // Clear historical result when starting a new scan
  const handleNewScan = () => {
    setHistoricalResult(null)
    reset()
  }

  const toggleCategory = (categoryId: string) => {
    setExpandedCategories(prev => 
      prev.includes(categoryId) 
        ? prev.filter(id => id !== categoryId)
        : [...prev, categoryId]
    )
  }

  const handleScan = async () => {
    if (!url || !selectedTool) return
    let targetUrl = url
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl
    }
    
    // Map tool ID to tool_focus
    const toolFocusMap: Record<string, 'all' | 'security_headers' | 'ssl_tls' | 'cookies'> = {
      'security-headers': 'security_headers',
      'ssl-tls': 'ssl_tls',
      'cookie-security': 'cookies',
    }
    const tool_focus = toolFocusMap[selectedTool.id] || 'all'
    
    try {
      await startScan({ url: targetUrl, scan_type: 'quick', tool_focus })
    } catch (e) {
      console.error('Scan failed:', e)
    }
  }

  const canScan = isHealthy && caiAvailable && url.length > 0 && !isLoading && selectedTool?.status === 'available'

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Header */}
      <header className="glass-nav border-b border-gray-800 px-4 py-3 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="lg:hidden p-2 text-gray-400 hover:text-white"
          >
            {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
          <div className="w-8 h-8 bg-gradient-to-br from-primary to-purple-600 rounded-lg flex items-center justify-center">
            <Shield className="h-4 w-4 text-white" />
          </div>
          <span className="text-white font-bold hidden sm:inline">FurtherSecurity</span>
          <span className="text-xs bg-primary/20 text-primary-300 px-2 py-0.5 rounded">BETA</span>
        </div>
        
        <div className="flex items-center gap-3">
          {/* History Button */}
          <button
            onClick={() => setShowHistory(!showHistory)}
            className={`flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg transition-colors ${
              showHistory 
                ? 'bg-primary/20 text-primary-300' 
                : 'bg-gray-800/50 text-gray-400 hover:text-white hover:bg-gray-800'
            }`}
          >
            <History className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">History</span>
            {scans.length > 0 && (
              <span className="bg-gray-700 text-gray-300 text-[10px] px-1.5 rounded-full">{scans.length}</span>
            )}
          </button>
          
          <div className="hidden md:flex items-center gap-2 text-xs bg-gray-800/50 px-3 py-1.5 rounded-lg">
            <Zap className="h-3 w-3 text-amber-400" />
            <span className="text-gray-400">{AVAILABLE_TOOLS}/{TOTAL_TOOLS} tools</span>
          </div>
          <div className={`flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg ${
            isHealthy ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'
          }`}>
            <div className={`w-2 h-2 rounded-full ${isHealthy ? 'bg-green-400' : 'bg-red-400'}`} />
            <span className="hidden sm:inline">{isHealthy ? 'CAI Ready' : 'Offline'}</span>
          </div>
          {user && <UserButton afterSignOutUrl="/" />}
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* ═══════════════════════════════════════════════════════════════════
            LEFT SIDEBAR - 7 Categories (Collapsible)
        ═══════════════════════════════════════════════════════════════════ */}
        <aside className={`${sidebarOpen ? 'w-72' : 'w-0'} lg:w-72 shrink-0 border-r border-gray-800 bg-gray-900/50 overflow-y-auto transition-all`}>
          <div className="p-2">
            {categories.map(category => {
              const isExpanded = expandedCategories.includes(category.id)
              const availableCount = category.tools.filter(t => t.status === 'available').length
              const Icon = category.icon
              
              return (
                <div key={category.id} className="mb-1">
                  {/* Category Header */}
                  <button
                    onClick={() => toggleCategory(category.id)}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-all hover:bg-gray-800/50 ${
                      isExpanded ? 'bg-gray-800/30' : ''
                    }`}
                  >
                    <div className={`p-1.5 rounded-lg bg-${category.color}-500/20`}>
                      <Icon className={`h-4 w-4 text-${category.color}-400`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-white text-sm font-medium">{category.emoji} {category.name}</span>
                      </div>
                      <span className="text-gray-500 text-xs">
                        {availableCount}/{category.tools.length} ready
                      </span>
                    </div>
                    {isExpanded ? (
                      <ChevronUp className="h-4 w-4 text-gray-500" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-gray-500" />
                    )}
                  </button>
                  
                  {/* Tools List */}
                  {isExpanded && (
                    <div className="ml-3 pl-3 border-l border-gray-800 mt-1 space-y-0.5">
                      {category.tools.map(tool => {
                        const ToolIcon = tool.icon
                        const isSelected = selectedTool?.id === tool.id
                        const isAvailable = tool.status === 'available'
                        
                        return (
                          <button
                            key={tool.id}
                            onClick={() => {
                              setSelectedTool(tool)
                              // Reset scan result, historical result, and close history when selecting a new tool
                              reset()
                              setHistoricalResult(null)
                              setShowHistory(false)
                            }}
                            className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left transition-all ${
                              isSelected 
                                ? 'bg-primary/20 text-white' 
                                : isAvailable
                                  ? 'text-gray-300 hover:bg-gray-800/50 hover:text-white'
                                  : 'text-gray-600 hover:bg-gray-800/30'
                            }`}
                          >
                            <ToolIcon className={`h-4 w-4 shrink-0 ${isSelected ? 'text-primary' : ''}`} />
                            <span className="text-sm flex-1 truncate">{tool.name}</span>
                            {isAvailable ? (
                              <CheckCircle className="h-3 w-3 text-green-500 shrink-0" />
                            ) : (
                              <span className="text-[10px] text-gray-600 shrink-0">Soon</span>
                            )}
                          </button>
                        )
                      })}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </aside>

        {/* ═══════════════════════════════════════════════════════════════════
            RIGHT PANEL - Tool Details + Scan Input + Results
        ═══════════════════════════════════════════════════════════════════ */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          
          {/* History Panel */}
          {showHistory && (() => {
            // Stats calculation
            const buyCount = scans.filter((s: any) => s.verdict === 'buy').length
            const cautionCount = scans.filter((s: any) => s.verdict === 'caution').length
            const noBuyCount = scans.filter((s: any) => s.verdict === 'no-buy').length
            
            // Get unique tools from scans
            const toolFilters = [
              { id: 'all', name: 'All Tools', focus: null },
              { id: 'security_headers', name: 'Security Headers', focus: 'security_headers' },
              { id: 'ssl_tls', name: 'SSL/TLS', focus: 'ssl_tls' },
              { id: 'cookies', name: 'Cookies', focus: 'cookies' },
            ]
            
            // Apply filters
            let filteredScans = scans
            if (historyFilter !== 'all') {
              filteredScans = filteredScans.filter((s: any) => s.tool_focus === historyFilter)
            }
            if (historySearch) {
              filteredScans = filteredScans.filter((s: any) => 
                s.url?.toLowerCase().includes(historySearch.toLowerCase())
              )
            }
            
            return (
            <div className="space-y-4">
              {/* Header */}
              <div className="bg-gray-900/50 border border-gray-700/50 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-xl bg-primary/20">
                      <History className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <h2 className="text-white text-xl font-semibold">Scan History</h2>
                      <p className="text-gray-500 text-sm">{scans.length} total assessments</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => refreshScans()}
                      className="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition-colors"
                    >
                      <RefreshCw className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => setShowHistory(false)}
                      className="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition-colors"
                    >
                      <XCircle className="h-4 w-4" />
                    </button>
                  </div>
                </div>
                
                {/* Stats Summary */}
                <div className="grid grid-cols-3 gap-3 mb-4">
                  <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-3 text-center">
                    <p className="text-2xl font-bold text-green-400">{buyCount}</p>
                    <p className="text-green-400/70 text-xs">Safe to Buy</p>
                  </div>
                  <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-3 text-center">
                    <p className="text-2xl font-bold text-amber-400">{cautionCount}</p>
                    <p className="text-amber-400/70 text-xs">Caution</p>
                  </div>
                  <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-3 text-center">
                    <p className="text-2xl font-bold text-red-400">{noBuyCount}</p>
                    <p className="text-red-400/70 text-xs">Not Recommended</p>
                  </div>
                </div>
                
                {/* Search */}
                <div className="relative mb-4">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
                  <input
                    type="text"
                    placeholder="Search by URL..."
                    value={historySearch}
                    onChange={(e) => setHistorySearch(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-white text-sm placeholder-gray-500 focus:border-primary focus:outline-none"
                  />
                </div>
                
                {/* Tool Filters */}
                <div className="flex gap-2 flex-wrap">
                  {toolFilters.map(filter => {
                    const count = filter.focus 
                      ? scans.filter((s: any) => s.tool_focus === filter.focus).length
                      : scans.length
                    return (
                      <button
                        key={filter.id}
                        onClick={() => setHistoryFilter(filter.focus || 'all')}
                        className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                          (historyFilter === filter.focus || (historyFilter === 'all' && !filter.focus))
                            ? 'bg-primary text-white'
                            : 'bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700'
                        }`}
                      >
                        {filter.name}
                        <span className="ml-1.5 text-xs opacity-70">({count})</span>
                      </button>
                    )
                  })}
                </div>
              </div>
              
              {/* Scan List */}
              <div className="bg-gray-900/50 border border-gray-700/50 rounded-2xl overflow-hidden">
                {filteredScans.length === 0 ? (
                  <div className="text-center py-12">
                    <History className="h-12 w-12 text-gray-700 mx-auto mb-3" />
                    <p className="text-gray-500">
                      {historySearch ? 'No matching scans found' : 'No assessments yet'}
                    </p>
                    <p className="text-gray-600 text-sm">
                      {historySearch ? 'Try a different search term' : 'Run a scan to see your history here'}
                    </p>
                  </div>
                ) : (
                  <div className="divide-y divide-gray-800">
                    {filteredScans.map((scan: any) => (
                      <button 
                        key={scan.scan_id || scan.id}
                        onClick={() => loadScanFromHistory(scan.scan_id || scan.id)}
                        disabled={loadingHistory}
                        className="w-full flex items-center justify-between p-4 hover:bg-gray-800/50 transition-colors cursor-pointer disabled:opacity-50"
                      >
                        <div className="flex items-center gap-4">
                          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                            scan.verdict === 'buy' ? 'bg-green-500/20' :
                            scan.verdict === 'caution' ? 'bg-amber-500/20' :
                            scan.verdict === 'no-buy' ? 'bg-red-500/20' :
                            'bg-gray-700/50'
                          }`}>
                            {scan.verdict === 'buy' ? (
                              <CheckCircle className="h-5 w-5 text-green-400" />
                            ) : scan.verdict === 'caution' ? (
                              <AlertCircle className="h-5 w-5 text-amber-400" />
                            ) : scan.verdict === 'no-buy' ? (
                              <XCircle className="h-5 w-5 text-red-400" />
                            ) : (
                              <Globe className="h-5 w-5 text-gray-500" />
                            )}
                          </div>
                          <div className="text-left">
                            <div className="flex items-center gap-2 flex-wrap">
                              <p className="text-white font-medium">{scan.url}</p>
                              {scan.tool_name && (
                                <span className={`px-2 py-0.5 text-xs rounded font-medium ${
                                  scan.tool_focus === 'security_headers' ? 'bg-blue-500/20 text-blue-400' :
                                  scan.tool_focus === 'ssl_tls' ? 'bg-purple-500/20 text-purple-400' :
                                  scan.tool_focus === 'cookies' ? 'bg-orange-500/20 text-orange-400' :
                                  'bg-primary/20 text-primary'
                                }`}>
                                  {scan.tool_name}
                                </span>
                              )}
                            </div>
                            <p className="text-gray-500 text-sm">
                              {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Just now'}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-4">
                          {scan.risk_score !== null && scan.risk_score !== undefined && (
                            <div className="text-right">
                              <span className={`text-xl font-bold ${
                                scan.risk_score <= 30 ? 'text-green-400' :
                                scan.risk_score <= 60 ? 'text-amber-400' :
                                'text-red-400'
                              }`}>
                                {scan.risk_score}
                              </span>
                              <span className="text-gray-500 text-xs block">risk</span>
                            </div>
                          )}
                          {scan.verdict && (
                            <span className={`px-3 py-1 rounded-lg text-sm font-medium ${
                              scan.verdict === 'buy' ? 'bg-green-500/20 text-green-400' :
                              scan.verdict === 'caution' ? 'bg-amber-500/20 text-amber-400' :
                              'bg-red-500/20 text-red-400'
                            }`}>
                              {scan.verdict.toUpperCase()}
                            </span>
                          )}
                          <ChevronRight className="h-5 w-5 text-gray-600" />
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
            )
          })()}

          {/* No tool selected */}
          {!selectedTool && !result && !historicalResult && !showHistory && (
            <div className="h-full flex items-center justify-center">
              <div className="text-center max-w-md">
                <div className="w-16 h-16 bg-gray-800/50 rounded-2xl flex items-center justify-center mx-auto mb-4">
                  <Shield className="h-8 w-8 text-gray-600" />
                </div>
                <h2 className="text-white text-xl font-semibold mb-2">Select a Tool</h2>
                <p className="text-gray-500 text-sm mb-4">
                  Choose a security tool from the sidebar to start your assessment.
                  We have {AVAILABLE_TOOLS} tools ready and {TOTAL_TOOLS - AVAILABLE_TOOLS} more coming soon!
                </p>
                <div className="flex flex-wrap justify-center gap-2">
                  {categories.slice(0, 3).map(cat => (
                    <button
                      key={cat.id}
                      onClick={() => {
                        setExpandedCategories([cat.id])
                        setSelectedTool(cat.tools.find(t => t.status === 'available') || cat.tools[0])
                      }}
                      className="px-3 py-1.5 bg-gray-800/50 hover:bg-gray-800 text-gray-400 hover:text-white text-sm rounded-lg transition-colors"
                    >
                      {cat.emoji} {cat.name}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Selected Tool Info + Input (hidden when viewing historical result) */}
          {selectedTool && !showHistory && !historicalResult && (
            <div className="bg-gray-900/50 border border-gray-700/50 rounded-2xl p-6">
              <div className="flex items-start gap-4 mb-6">
                <div className={`p-3 rounded-xl ${
                  selectedTool.status === 'available' ? 'bg-primary/20' : 'bg-gray-700/50'
                }`}>
                  <selectedTool.icon className={`h-6 w-6 ${
                    selectedTool.status === 'available' ? 'text-primary' : 'text-gray-500'
                  }`} />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <h2 className="text-white text-xl font-semibold">{selectedTool.name}</h2>
                    {selectedTool.status === 'available' ? (
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded">Ready</span>
                    ) : (
                      <span className="px-2 py-0.5 bg-gray-700/50 text-gray-500 text-xs rounded">Coming Soon</span>
                    )}
                  </div>
                  <p className="text-gray-400 text-sm">{selectedTool.longDescription}</p>
                  {selectedTool.userBenefit && (
                    <p className="text-primary-400 text-sm mt-2 flex items-center gap-1.5">
                      <span className="text-primary-500">💡</span> {selectedTool.userBenefit}
                    </p>
                  )}
                  <div className="flex flex-wrap gap-2 mt-2">
                    <span className="text-gray-600 text-xs">
                      Powered by: <code className="text-purple-400 bg-gray-800 px-1.5 py-0.5 rounded">{selectedTool.caiAgent}</code>
                    </span>
                    <span className="text-gray-700">•</span>
                    <span className="text-gray-600 text-xs">
                      CAI Tool: <code className="text-primary-300 bg-gray-800 px-1.5 py-0.5 rounded">{selectedTool.caiTool}</code>
                    </span>
                  </div>
                </div>
              </div>

              {selectedTool.status === 'available' ? (
                <div className="flex gap-3">
                  <div className="flex-1 relative">
                    <Globe className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-500" />
                    <input
                      type="text"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="Enter URL to scan (e.g., example.com)"
                      className="w-full bg-gray-800 border border-gray-700 rounded-xl pl-12 pr-4 py-3 text-white placeholder-gray-500 focus:border-primary focus:outline-none transition-colors"
                      onKeyDown={(e) => e.key === 'Enter' && canScan && handleScan()}
                    />
                  </div>
                  <button
                    onClick={handleScan}
                    disabled={!canScan}
                    className={`px-6 py-3 rounded-xl font-medium flex items-center gap-2 transition-all ${
                      canScan
                        ? 'bg-gradient-to-r from-primary to-purple-600 text-white hover:shadow-lg hover:shadow-primary/30'
                        : 'bg-gray-800 text-gray-500 cursor-not-allowed'
                    }`}
                  >
                    {isLoading ? (
                      <Loader2 className="h-5 w-5 animate-spin" />
                    ) : (
                      <Play className="h-5 w-5" />
                    )}
                    Scan
                  </button>
                </div>
              ) : (
                <div className="bg-gray-800/50 border border-dashed border-gray-700 rounded-xl p-6 text-center">
                  <Clock className="h-8 w-8 text-gray-600 mx-auto mb-2" />
                  <p className="text-gray-400 text-sm font-medium">Coming Soon!</p>
                  <p className="text-gray-600 text-xs mt-1">This tool is under development. Check back later!</p>
                </div>
              )}
            </div>
          )}

          {/* Scan Progress with Real-time Logs */}
          {isLoading && !showHistory && (
            <div className="bg-gray-900/50 border border-primary/30 rounded-xl overflow-hidden">
              {/* Header */}
              <div className="p-4 border-b border-gray-700/50">
                <div className="flex items-center gap-3 mb-3">
                  <div className="relative">
                    <Loader2 className="h-6 w-6 text-primary animate-spin" />
                    <div className="absolute inset-0 h-6 w-6 bg-primary/20 rounded-full animate-ping" />
                  </div>
                  <div className="flex-1">
                    <p className="text-white font-medium">Scanning in progress...</p>
                    <p className="text-primary-300 text-sm">{currentStep || 'Initializing CAI tools...'}</p>
                  </div>
                  <span className="text-gray-500 text-sm">{progress}%</span>
                </div>
                <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-primary to-purple-500 transition-all" style={{ width: `${progress}%` }} />
                </div>
              </div>
              
              {/* Real-time Logs */}
              {logs.length > 0 && (
                <div className="p-4 bg-gray-950/50 max-h-48 overflow-y-auto">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                    <span className="text-gray-500 text-xs font-medium uppercase tracking-wider">Live Activity</span>
                  </div>
                  <div className="space-y-1 font-mono text-xs">
                    {logs.slice(-10).map((log, i) => {
                      // Parse timestamp and message
                      const match = log.match(/\[([^\]]+)\]\s*(.*)/)
                      const timestamp = match ? match[1].split('T')[1]?.substring(0, 8) : ''
                      const message = match ? match[2] : log
                      
                      // Determine color based on message content
                      const isSuccess = message.includes('✓') || message.includes('complete')
                      const isError = message.includes('✗') || message.includes('ERROR')
                      const isCAI = message.includes('CAI')
                      const isAI = message.includes('AI')
                      
                      return (
                        <div 
                          key={i} 
                          className={`flex items-start gap-2 ${
                            i === logs.length - 1 ? 'text-white' : 'text-gray-500'
                          }`}
                        >
                          <span className="text-gray-600 shrink-0">{timestamp}</span>
                          <span className={`${
                            isSuccess ? 'text-green-400' :
                            isError ? 'text-red-400' :
                            isCAI ? 'text-purple-400' :
                            isAI ? 'text-pink-400' :
                            ''
                          }`}>
                            {isCAI && '🔧 '}
                            {isAI && '🧠 '}
                            {isSuccess && '✓ '}
                            {message}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Error */}
          {error && !showHistory && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-red-400 shrink-0" />
              <p className="text-red-400">{error.message}</p>
            </div>
          )}

          {/* Loading Historical Scan */}
          {loadingHistory && (
            <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-8 flex items-center justify-center">
              <Loader2 className="h-8 w-8 text-primary animate-spin" />
              <span className="ml-3 text-gray-400">Loading scan report...</span>
            </div>
          )}

          {/* Scan Result (current or historical) */}
          {(result || historicalResult) && !showHistory && !loadingHistory && (
            <ScanResultView 
              result={result || historicalResult!} 
              onClose={() => {
                reset()
                setHistoricalResult(null)
              }}
              isHistorical={!!historicalResult && !result}
            />
          )}

          {/* Recent Scans (shown only when not in history view and no result displayed) */}
          {!isLoading && !showHistory && !result && !historicalResult && scans.length > 0 && (() => {
            // Map tool ID to tool_focus for filtering
            const toolFocusMap: Record<string, string> = {
              'security-headers': 'security_headers',
              'ssl-tls': 'ssl_tls',
              'cookie-security': 'cookies',
            }
            const currentToolFocus = selectedTool ? toolFocusMap[selectedTool.id] : null
            
            // Filter scans by selected tool, or show all if no tool selected
            const filteredScans = currentToolFocus 
              ? scans.filter((scan: any) => scan.tool_focus === currentToolFocus)
              : scans
            
            if (filteredScans.length === 0 && currentToolFocus) {
              return (
                <div className="text-center py-8 bg-gray-800/30 rounded-xl">
                  <History className="h-8 w-8 text-gray-600 mx-auto mb-2" />
                  <p className="text-gray-500 text-sm">No {selectedTool?.name} scans yet</p>
                  <p className="text-gray-600 text-xs">Run a scan to see history here</p>
                </div>
              )
            }
            
            return (
            <div>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-gray-400 text-sm font-medium flex items-center gap-2">
                  <History className="h-4 w-4" />
                  {selectedTool ? `${selectedTool.name} History` : 'Recent Assessments'}
                  {currentToolFocus && (
                    <span className="text-gray-600 text-xs">({filteredScans.length})</span>
                  )}
                </h3>
                <div className="flex items-center gap-2">
                  <button 
                    onClick={() => setShowHistory(true)} 
                    className="text-primary-300 hover:text-primary text-xs"
                  >
                    View All →
                  </button>
                  <button onClick={() => refreshScans()} className="text-gray-500 hover:text-white p-1">
                    <RefreshCw className="h-4 w-4" />
                  </button>
                </div>
              </div>
              <div className="space-y-2">
                {filteredScans.slice(0, 5).map((scan: any) => (
                  <button 
                    key={scan.scan_id || scan.id}
                    onClick={() => loadScanFromHistory(scan.scan_id || scan.id)}
                    disabled={loadingHistory}
                    className="w-full flex items-center justify-between p-3 rounded-lg bg-gray-800/30 hover:bg-gray-800/50 transition-colors cursor-pointer border border-transparent hover:border-gray-700/50 disabled:opacity-50"
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                        scan.verdict === 'buy' ? 'bg-green-500/20' :
                        scan.verdict === 'caution' ? 'bg-amber-500/20' :
                        scan.verdict === 'no-buy' ? 'bg-red-500/20' :
                        'bg-gray-700/50'
                      }`}>
                        {scan.verdict === 'buy' ? (
                          <CheckCircle className="h-4 w-4 text-green-400" />
                        ) : scan.verdict === 'caution' ? (
                          <AlertCircle className="h-4 w-4 text-amber-400" />
                        ) : scan.verdict === 'no-buy' ? (
                          <XCircle className="h-4 w-4 text-red-400" />
                        ) : (
                          <Globe className="h-4 w-4 text-gray-500" />
                        )}
                      </div>
                      <div className="text-left">
                        <div className="flex items-center gap-2">
                          <p className="text-white text-sm truncate max-w-xs">{scan.url}</p>
                          {scan.tool_name && (
                            <span className="px-1.5 py-0.5 bg-primary/20 text-primary text-[10px] rounded font-medium">
                              {scan.tool_name}
                            </span>
                          )}
                        </div>
                        <p className="text-gray-600 text-xs">
                          {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Just now'}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {scan.risk_score !== undefined && scan.risk_score !== null && (
                        <span className={`text-sm font-medium ${
                          scan.risk_score <= 30 ? 'text-green-400' :
                          scan.risk_score <= 60 ? 'text-amber-400' :
                          'text-red-400'
                        }`}>{scan.risk_score}</span>
                      )}
                      <ChevronRight className="h-4 w-4 text-gray-600" />
                    </div>
                  </button>
                ))}
              </div>
            </div>
            )
          })()}

        </main>
      </div>
    </div>
  )
}

export default Dashboard
