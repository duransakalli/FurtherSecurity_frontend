import { Mail, ArrowRight, Bell } from 'lucide-react'

const Contact = () => {
  return (
    <section id="contact" className="w-full relative overflow-hidden bg-primary py-16 sm:py-24">
      <div className="relative z-10 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-white/10 rounded-2xl mb-8">
          <Bell className="h-8 w-8 text-white" />
        </div>
        
        <h2 className="text-white text-3xl sm:text-4xl font-normal font-ropa-sans mb-4">
          Get Early Access
        </h2>
        
        <p className="text-white/80 text-lg leading-relaxed mb-8 max-w-2xl mx-auto">
          Be the first to know when we launch. Join our waitlist for early access to the SaaS security intelligence platform.
        </p>

        {/* Email Signup Form */}
        <div className="max-w-md mx-auto mb-8">
          <div className="flex flex-col sm:flex-row gap-3">
            <input
              type="email"
              placeholder="Enter your email"
              className="flex-1 bg-white/10 border border-white/20 text-white placeholder-white/50 px-4 py-3 rounded-xl outline-none focus:border-white/40 transition-colors"
            />
            <button
              className="bg-white text-primary hover:bg-gray-100 px-6 py-3 rounded-xl font-medium transition-colors duration-200 flex items-center justify-center gap-2"
            >
              Join Waitlist
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        <p className="text-white/50 text-sm mb-12">
          No spam. Just product updates and early access.
        </p>

        {/* Alternative Contact */}
        <div className="pt-8 border-t border-white/10">
          <p className="text-white/60 text-sm mb-4">
            Want to chat about partnerships or have questions?
          </p>
          <a
            href="mailto:hello@furthersecurity.com"
            className="inline-flex items-center text-white hover:text-white/80 transition-colors"
          >
            <Mail className="w-4 h-4 mr-2" />
            hello@furthersecurity.com
          </a>
        </div>
      </div>
    </section>
  )
}

export default Contact
