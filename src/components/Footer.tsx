const Footer = () => {
  return (
    <footer className="w-full relative overflow-hidden bg-background-deep py-16 sm:py-20">
      {/* Background Effect */}
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 -z-10">
        <div className="absolute inset-0 gradient-purple" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid gap-8 md:grid-cols-4 mb-12">
          {/* Brand */}
          <div className="md:col-span-2">
            <a href="/" className="flex items-center mb-4">
              <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center mr-3">
                <span className="text-white font-bold text-lg">FS</span>
              </div>
              <span className="text-white text-xl font-semibold font-ropa-sans">
                FurtherSecurity
              </span>
            </a>
            <p className="text-gray-400 text-base leading-relaxed max-w-md">
              SaaS security intelligence for informed decisions. Instant risk scanning, 
              AI-powered reasoning, and executive-ready reports.
            </p>
          </div>

          {/* Tools */}
          <div>
            <h4 className="text-white text-sm font-semibold mb-4 uppercase tracking-wider">
              Tools
            </h4>
            <ul className="space-y-3 text-sm text-gray-400">
              <li>
                <a href="#services" className="hover:text-white transition-colors duration-200">
                  SaaS Risk Scanner
                </a>
              </li>
              <li>
                <a href="#services" className="hover:text-white transition-colors duration-200">
                  Risk Reasoning Engine
                </a>
              </li>
              <li>
                <a href="#services" className="hover:text-white transition-colors duration-200">
                  Compliance Mapper
                </a>
              </li>
              <li>
                <a href="#services" className="hover:text-white transition-colors duration-200">
                  Executive Reports
                </a>
              </li>
            </ul>
          </div>

          {/* Company */}
          <div>
            <h4 className="text-white text-sm font-semibold mb-4 uppercase tracking-wider">
              Company
            </h4>
            <ul className="space-y-3 text-sm text-gray-400">
              <li>
                <a href="#about" className="hover:text-white transition-colors duration-200">
                  About
                </a>
              </li>
              <li>
                <a href="#contact" className="hover:text-white transition-colors duration-200">
                  Contact
                </a>
              </li>
              <li>
                <a href="#contact" className="hover:text-white transition-colors duration-200">
                  Early Access
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom */}
        <div className="pt-8 border-t border-gray-800">
          <p className="text-gray-500 text-xs">
            © {new Date().getFullYear()} FurtherSecurity. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  )
}

export default Footer
