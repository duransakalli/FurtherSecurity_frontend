import { useState } from 'react'
import { Menu, X, LogIn } from 'lucide-react'
import { SignedIn, SignedOut, UserButton } from '@clerk/clerk-react'
import { Link } from 'react-router-dom'

const Header = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const navLinks = [
    { href: '#services', label: 'Tools' },
    { href: '#about', label: 'About' },
  ]

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 w-full glass-nav">
      <div className="w-full px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center">
            <a className="flex items-center" href="/">
              <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center mr-3">
                <span className="text-white font-bold text-lg">FS</span>
              </div>
              <span className="text-neutral-50 font-inter text-xl font-semibold">
                FurtherSecurity
              </span>
            </a>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            {navLinks.map((link) => (
              <a
                key={link.href}
                href={link.href}
                className="text-gray-50 hover:text-primary-300 text-sm font-medium transition-colors duration-200"
              >
                {link.label}
              </a>
            ))}
            
            {/* Auth Buttons */}
            <SignedOut>
              <Link
                to="/sign-in"
                className="text-gray-50 hover:text-primary-300 text-sm font-medium transition-colors duration-200"
              >
                Sign In
              </Link>
              <Link
                to="/sign-up"
              className="bg-primary hover:bg-primary-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200"
            >
                Get Started
              </Link>
            </SignedOut>
            
            <SignedIn>
              <Link
                to="/app"
                className="text-gray-50 hover:text-primary-300 text-sm font-medium transition-colors duration-200"
              >
                Dashboard
              </Link>
              <UserButton 
                afterSignOutUrl="/"
                appearance={{
                  elements: {
                    avatarBox: 'w-9 h-9',
                  }
                }}
              />
            </SignedIn>
          </div>

          {/* Mobile Menu Button */}
          <div className="md:hidden flex items-center gap-3">
            <SignedIn>
              <UserButton 
                afterSignOutUrl="/"
                appearance={{
                  elements: {
                    avatarBox: 'w-8 h-8',
                  }
                }}
              />
            </SignedIn>
            <button
              className="inline-flex items-center justify-center p-2 rounded-md text-primary-100 hover:text-primary-300 focus:outline-none"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? (
                <X className="h-6 w-6" />
              ) : (
                <Menu className="h-6 w-6" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Navigation */}
      {mobileMenuOpen && (
        <div className="md:hidden glass-nav border-t border-gray-800">
          <div className="px-4 pt-2 pb-4 space-y-2">
            {navLinks.map((link) => (
              <a
                key={link.href}
                href={link.href}
                className="text-gray-50 hover:text-primary-300 block px-3 py-2 text-base font-medium transition-colors duration-200"
                onClick={() => setMobileMenuOpen(false)}
              >
                {link.label}
              </a>
            ))}
            
            <SignedOut>
              <Link
                to="/sign-in"
                className="text-gray-50 hover:text-primary-300 block px-3 py-2 text-base font-medium transition-colors duration-200"
                onClick={() => setMobileMenuOpen(false)}
              >
                Sign In
              </Link>
              <Link
                to="/sign-up"
                className="block bg-primary hover:bg-primary-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200 text-center mt-4"
                onClick={() => setMobileMenuOpen(false)}
              >
                Get Started
              </Link>
            </SignedOut>
            
            <SignedIn>
              <Link
                to="/app"
              className="block bg-primary hover:bg-primary-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200 text-center mt-4"
              onClick={() => setMobileMenuOpen(false)}
            >
                Go to Dashboard
              </Link>
            </SignedIn>
          </div>
        </div>
      )}
    </nav>
  )
}

export default Header
