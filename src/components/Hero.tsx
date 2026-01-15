import { Shield, Zap, Brain, FileText } from 'lucide-react'

const Hero = () => {
  return (
    <section className="relative overflow-hidden py-24 sm:py-32 pt-32">
      {/* Background Effects */}
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 -z-10">
        <div className="absolute left-1/2 top-[-12rem] h-[40rem] w-[80rem] -translate-x-1/2 gradient-hero blur-3xl" />
        <div className="absolute inset-0 gradient-radial" />
      </div>

      <div className="container mx-auto px-4">
        <div className="mx-auto max-w-6xl text-center">
          {/* Badge */}
          <div className="mb-8">
            <div className="inline-flex items-center rounded-full border border-primary-200/30 text-primary-200 bg-primary-200/5 px-6 py-3 text-sm font-medium">
              <Shield className="h-4 w-4 mr-2" />
              SaaS Security Intelligence Platform
            </div>
          </div>

          {/* Headline */}
          <h1 className="text-balance text-5xl md:text-7xl lg:text-8xl font-normal font-ropa-sans tracking-tight text-white leading-[0.95] mb-8">
            Should You
            <span className="bg-gradient-to-r from-primary-200 to-primary-400 bg-clip-text text-transparent">
              {' '}Trust{' '}
            </span>
            This SaaS?
          </h1>

          {/* Subtitle */}
          <p className="mx-auto max-w-3xl text-xl md:text-2xl text-gray-300 leading-relaxed mb-12 font-light">
            Instant security intelligence for buyers, investors, and procurement teams. 
            Enter a URL, get a <span className="text-white font-medium">Buy / Caution / No-Buy</span> verdict in seconds.
          </p>

          {/* URL Input Preview (Coming Soon) */}
          <div className="max-w-2xl mx-auto mb-12">
            <div className="relative">
              <div className="flex items-center bg-background-deep/80 border border-gray-700 rounded-2xl p-2 backdrop-blur-sm">
                <div className="flex-1 flex items-center px-4">
                  <Globe className="h-5 w-5 text-gray-500 mr-3" />
                  <input
                    type="text"
                    placeholder="Enter SaaS URL to scan..."
                    className="flex-1 bg-transparent text-gray-400 placeholder-gray-600 outline-none text-lg"
                    disabled
                  />
                </div>
                <button
                  disabled
                  className="bg-primary/50 text-primary-200 px-6 py-3 rounded-xl text-base font-medium cursor-not-allowed flex items-center gap-2"
                >
                  <Zap className="h-4 w-4" />
                  Scan Now
                </button>
              </div>
              {/* Coming Soon Overlay */}
              <div className="absolute inset-0 flex items-center justify-center bg-background/60 backdrop-blur-[2px] rounded-2xl">
                <span className="bg-amber-500/20 text-amber-400 border border-amber-500/30 px-4 py-2 rounded-full text-sm font-medium">
                  🚀 Coming Soon
                </span>
              </div>
            </div>
          </div>

          {/* Feature Badges */}
          <div className="flex flex-wrap items-center justify-center gap-4 md:gap-6">
            <div className="inline-flex items-center rounded-full border border-green-400/30 text-green-400 bg-green-400/5 px-5 py-3 text-sm font-medium">
              <Zap className="h-4 w-4 mr-2" />
              Instant URL Scanning
            </div>
            <div className="inline-flex items-center rounded-full border border-blue-400/30 text-blue-400 bg-blue-400/5 px-5 py-3 text-sm font-medium">
              <Brain className="h-4 w-4 mr-2" />
              AI Risk Reasoning
            </div>
            <div className="inline-flex items-center rounded-full border border-purple-400/30 text-purple-400 bg-purple-400/5 px-5 py-3 text-sm font-medium">
              <FileText className="h-4 w-4 mr-2" />
              Executive Reports
            </div>
          </div>

          {/* CTA Buttons */}
          <div className="mt-12 flex flex-col sm:flex-row items-center justify-center gap-4">
            <a
              href="#services"
              className="inline-flex items-center justify-center bg-primary hover:bg-primary-600 text-white px-8 py-4 rounded-xl text-lg font-medium transition-colors duration-200"
            >
              Explore Tools
            </a>
            <a
              href="#contact"
              className="inline-flex items-center justify-center border border-gray-600 hover:border-gray-500 text-white px-8 py-4 rounded-xl text-lg font-medium transition-colors duration-200"
            >
              Get Early Access
            </a>
          </div>
        </div>
      </div>
    </section>
  )
}

// Globe icon component
const Globe = ({ className }: { className?: string }) => (
  <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/>
    <line x1="2" y1="12" x2="22" y2="12"/>
    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
  </svg>
)

export default Hero
