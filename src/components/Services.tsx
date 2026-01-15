import { 
  Globe, 
  Brain, 
  Shield, 
  FileCheck, 
  FileText, 
  Award,
  Zap,
  CheckCircle
} from 'lucide-react'

const services = [
  {
    priority: 1,
    icon: Globe,
    title: 'Instant SaaS Risk Scanner',
    tagline: 'Your Hero Feature',
    description: 'Enter a URL, get instant security intelligence. Zero setup, immediate Buy / Caution / No-Buy verdict.',
    features: [
      'DNS & SSL inspection',
      'Security headers analysis',
      'Breach & reputation signals',
      'Overall Risk Score (0-100)',
    ],
    highlight: true,
  },
  {
    priority: 2,
    icon: Brain,
    title: 'CAI Risk Reasoning Engine',
    tagline: 'Your Core IP',
    description: 'AI-powered risk correlation that explains WHY something is risky and what it means for your business.',
    features: [
      'Weighted risk reasoning',
      'Business impact explanation',
      'Priority ranking',
      'Top 3 risks that matter',
    ],
    highlight: true,
  },
  {
    priority: 3,
    icon: Shield,
    title: 'Light Black-Box AppSec Tester',
    tagline: 'Safe & Legal',
    description: 'Heuristic OWASP Top-10 checks without exploitation. Safe signals for security posture assessment.',
    features: [
      'HTTP probing & analysis',
      'Auth & session detection',
      'CORS & rate-limit checks',
      'Confidence-based findings',
    ],
    highlight: false,
  },
  {
    priority: 4,
    icon: FileCheck,
    title: 'Compliance Mapper',
    tagline: 'SOC2 / GDPR Lite',
    description: 'Maps findings to compliance language. Decision-friendly readiness gaps, not auditor-grade reports.',
    features: [
      'SOC 2 control mapping',
      'GDPR data handling checks',
      'Pass / Partial / Fail verdicts',
      'Missing evidence highlights',
    ],
    highlight: false,
  },
  {
    priority: 5,
    icon: FileText,
    title: 'Executive Report Generator',
    tagline: 'This Sells The Platform',
    description: 'Beautiful PDF reports for founders, investors, and procurement. Clear verdicts with actionable roadmaps.',
    features: [
      'Buy / Caution / No-Buy verdict',
      'Top 5 risks summary',
      '30-60-90 day fix roadmap',
      'Shareable links & PDFs',
    ],
    highlight: false,
  },
  {
    priority: 6,
    icon: Award,
    title: 'Trust Score & Badge',
    tagline: 'Distribution Engine',
    description: 'Public-facing trust scores with embeddable badges. Build trust and drive viral adoption.',
    features: [
      'Embeddable widget',
      'Real-time score updates',
      'Last checked timestamp',
      'Marketplace ready',
    ],
    highlight: false,
  },
]

const Services = () => {
  return (
    <section id="services" className="w-full relative overflow-hidden bg-background-deep py-16 sm:py-24">
      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-12 md:mb-16">
          <p className="text-primary-200 text-base sm:text-lg font-medium uppercase tracking-wider mb-2">
            V1 TOOL STACK
          </p>
          <h2 className="text-white text-4xl sm:text-5xl font-normal font-ropa-sans mb-4 leading-tight">
            Should You Trust This SaaS?
          </h2>
          <p className="text-gray-300 text-base leading-7 max-w-2xl mx-auto">
            Instantly answer the question: "Should I buy / integrate / trust this SaaS?" — with AI-powered security intelligence.
          </p>
        </div>

        {/* Hero Tools (1 & 2) */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          {services.slice(0, 2).map((service) => (
            <div
              key={service.priority}
              className="relative flex flex-col rounded-2xl border glass-card border-primary/60 overflow-hidden shadow-lg"
            >
              {/* Priority Badge */}
              <div className="absolute top-4 right-4">
                <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-primary text-white text-sm font-bold">
                  {service.priority}
                </span>
              </div>

              <div className="flex flex-col flex-1 p-8">
                {/* Status Badge */}
                <div className="mb-4">
                  <div className="inline-flex items-center px-3 py-1.5 rounded-full border bg-amber-500/20 border-amber-500/50 text-amber-400 text-xs font-medium uppercase tracking-wider">
                    <Zap className="w-3 h-3 mr-1.5" />
                    COMING SOON
                  </div>
                </div>

                {/* Icon & Tagline */}
                <div className="flex items-center gap-3 mb-4">
                  <service.icon className="h-10 w-10 text-primary-300" />
                  <span className="text-primary-300 text-sm font-medium">{service.tagline}</span>
                </div>

                {/* Title & Description */}
                <h3 className="text-white text-2xl font-semibold leading-tight mb-3">
                  {service.title}
                </h3>
                <p className="text-gray-300 text-base leading-relaxed mb-6">
                  {service.description}
                </p>

                {/* Features */}
                <div className="grid grid-cols-2 gap-3 flex-1">
                  {service.features.map((feature, featureIndex) => (
                    <div key={featureIndex} className="flex items-start">
                      <CheckCircle className="w-4 h-4 flex-shrink-0 mr-2 mt-0.5 text-primary-400" />
                      <span className="text-sm leading-relaxed text-gray-200">
                        {feature}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* CTA */}
              <div className="p-6 pt-0">
                <button
                  disabled
                  className="inline-flex items-center justify-center w-full bg-primary/30 text-primary-200 px-4 py-3 rounded-xl text-base font-medium cursor-not-allowed border border-primary/40"
                >
                  Coming Soon
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Secondary Tools (3-6) */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {services.slice(2).map((service) => (
            <div
              key={service.priority}
              className="relative flex flex-col rounded-2xl border glass-card-muted border-gray-700/50 overflow-hidden shadow-lg"
            >
              {/* Priority Badge */}
              <div className="absolute top-4 right-4">
                <span className="inline-flex items-center justify-center w-7 h-7 rounded-full bg-gray-700 text-gray-300 text-xs font-bold">
                  {service.priority}
                </span>
              </div>

              <div className="flex flex-col flex-1 p-6">
                {/* Status Badge */}
                <div className="mb-4">
                  <div className="inline-flex items-center px-2.5 py-1 rounded-full border bg-gray-700/40 border-gray-600/40 text-gray-400 text-xs font-medium uppercase tracking-wider">
                    COMING SOON
                  </div>
                </div>

                {/* Icon */}
                <service.icon className="h-8 w-8 text-gray-500 mb-3" />

                {/* Tagline */}
                <span className="text-gray-500 text-xs font-medium mb-2">{service.tagline}</span>

                {/* Title & Description */}
                <h3 className="text-white text-lg font-semibold leading-tight mb-2">
                  {service.title}
                </h3>
                <p className="text-gray-400 text-sm leading-relaxed mb-4 flex-1">
                  {service.description}
                </p>

                {/* Features (compact) */}
                <div className="space-y-1.5">
                  {service.features.slice(0, 3).map((feature, featureIndex) => (
                    <div key={featureIndex} className="flex items-center">
                      <div className="w-1 h-1 rounded-full bg-gray-600 mr-2" />
                      <span className="text-xs text-gray-500">
                        {feature}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Bottom Note */}
        <div className="mt-12 text-center">
          <p className="text-gray-500 text-sm">
            Building the platform that answers: <span className="text-primary-300">"Is this safe enough to buy?"</span>
          </p>
        </div>
      </div>
    </section>
  )
}

export default Services
