import { SignIn } from '@clerk/clerk-react'
import { Link } from 'react-router-dom'

export default function SignInPage() {
  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Simple Header */}
      <header className="border-b border-gray-800 py-4">
        <div className="max-w-7xl mx-auto px-4 flex items-center justify-between">
          <Link to="/" className="flex items-center">
            <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center mr-3">
              <span className="text-white font-bold text-lg">FS</span>
            </div>
            <span className="text-white text-xl font-semibold">FurtherSecurity</span>
          </Link>
          <Link to="/" className="text-gray-400 hover:text-white text-sm">
            ← Back to Home
          </Link>
        </div>
      </header>

      {/* Sign In Form */}
      <main className="flex-1 flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <SignIn 
            appearance={{
              elements: {
                rootBox: 'mx-auto',
                card: 'bg-gray-900 border border-gray-800 shadow-2xl',
                headerTitle: 'text-white',
                headerSubtitle: 'text-gray-400',
                socialButtonsBlockButton: 'bg-gray-800 border-gray-700 text-white hover:bg-gray-700',
                socialButtonsBlockButtonText: 'text-white',
                dividerLine: 'bg-gray-700',
                dividerText: 'text-gray-500',
                formFieldLabel: 'text-gray-300',
                formFieldInput: 'bg-gray-800 border-gray-700 text-white',
                formButtonPrimary: 'bg-primary hover:bg-primary-600',
                footerActionLink: 'text-primary-300 hover:text-primary-200',
                identityPreviewText: 'text-white',
                identityPreviewEditButton: 'text-primary-300',
              },
              variables: {
                colorPrimary: '#8b5cf6',
                colorBackground: '#111111',
                colorText: '#ffffff',
                colorTextSecondary: '#9ca3af',
                colorInputBackground: '#1f2937',
                colorInputText: '#ffffff',
              }
            }}
            routing="path"
            path="/sign-in"
            signUpUrl="/sign-up"
            afterSignInUrl="/app"
          />
        </div>
      </main>
    </div>
  )
}

