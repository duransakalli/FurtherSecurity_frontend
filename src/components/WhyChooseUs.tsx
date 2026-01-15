import { Zap, Brain, Shield, Target } from 'lucide-react'

const features = [
  {
    icon: Zap,
    title: 'Zero Setup',
    description: 'Just enter a URL. No agents, no integrations, no complex onboarding. Get results in seconds.',
  },
  {
    icon: Brain,
    title: 'Decision Intelligence',
    description: 'Not just data — actionable verdicts. Buy / Caution / No-Buy recommendations you can trust.',
  },
  {
    icon: Shield,
    title: 'Buyer-Focused',
    description: 'Built for procurement teams, investors, and founders who need to make fast, informed decisions.',
  },
]

const audiences = [
  { 
    title: 'Investors & Acquirers', 
    description: 'Security due diligence before signing term sheets. Know what risks you\'re buying.',
    emoji: '💼'
  },
  { 
    title: 'Procurement Teams', 
    description: 'Evaluate vendor security in minutes, not weeks. Streamline your approval process.',
    emoji: '🛒'
  },
  { 
    title: 'SaaS Founders', 
    description: 'Prove your security posture to enterprise buyers. Build trust with verifiable scores.',
    emoji: '🚀'
  },
  { 
    title: 'Security Teams', 
    description: 'Quick third-party assessments without lengthy vendor questionnaires.',
    emoji: '🔒'
  },
]

const WhyChooseUs = () => {
  return (
    <section id="about" className="w-full relative overflow-hidden bg-background py-16 sm:py-24">
      {/* Background Effect */}
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 -z-10">
        <div className="absolute inset-0 gradient-purple" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-12 md:mb-16">
          <p className="text-primary-200 text-base sm:text-lg font-medium uppercase tracking-wider mb-2">
            WHY FURTHERSECURITY
          </p>
          <h2 className="text-white text-4xl sm:text-5xl font-normal font-ropa-sans mb-4 leading-tight">
            Security Intelligence, Not Noise
          </h2>
          <p className="text-gray-300 text-base leading-7 max-w-2xl mx-auto">
            We're not another security scanner. We're the decision layer that tells you if a SaaS is safe to buy.
          </p>
        </div>

        {/* Differentiator */}
        <div className="max-w-4xl mx-auto mb-16">
          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-red-500/10 border border-red-500/30 rounded-2xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <Target className="h-5 w-5 text-red-400" />
                <span className="text-red-400 font-medium">Others Show</span>
              </div>
              <ul className="space-y-2 text-gray-400 text-sm">
                <li>• Raw security findings</li>
                <li>• Complex dashboards</li>
                <li>• Requires integrations</li>
                <li>• Security team jargon</li>
              </ul>
            </div>
            <div className="bg-green-500/10 border border-green-500/30 rounded-2xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <Shield className="h-5 w-5 text-green-400" />
                <span className="text-green-400 font-medium">We Deliver</span>
              </div>
              <ul className="space-y-2 text-gray-300 text-sm">
                <li>• Buy / Caution / No-Buy verdicts</li>
                <li>• Plain English explanations</li>
                <li>• URL-only, zero setup</li>
                <li>• Executive-ready reports</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto mb-20">
          {features.map((feature, index) => (
            <div key={index} className="text-center">
              <div className="p-4 bg-primary/20 rounded-2xl w-20 h-20 mx-auto mb-6 flex items-center justify-center border border-primary/30">
                <feature.icon className="h-10 w-10 text-primary-200" />
              </div>
              <h4 className="text-white text-xl font-semibold mb-3">
                {feature.title}
              </h4>
              <p className="text-gray-300 text-base leading-relaxed">
                {feature.description}
              </p>
            </div>
          ))}
        </div>

        {/* Who We Help */}
        <div className="pt-16 border-t border-gray-800">
          <div className="text-center mb-12">
            <h3 className="text-white text-3xl font-normal font-ropa-sans mb-4">
              Built For Decision Makers
            </h3>
            <p className="text-gray-400 text-base max-w-2xl mx-auto">
              Whether you're buying, building, or investing — get the security clarity you need.
            </p>
          </div>
          <div className="grid md:grid-cols-4 gap-6 max-w-6xl mx-auto">
            {audiences.map((item, index) => (
              <div key={index} className="glass-card-muted border border-gray-700/50 rounded-xl p-6 text-center">
                <span className="text-3xl mb-4 block">{item.emoji}</span>
                <h4 className="text-white text-lg font-semibold mb-2">
                  {item.title}
                </h4>
                <p className="text-gray-400 text-sm leading-relaxed">
                  {item.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}

export default WhyChooseUs
