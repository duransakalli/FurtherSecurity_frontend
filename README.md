# FurtherSecurity Frontend

React-based UI for the FurtherSecurity platform.

## Tech Stack

- React 18
- Vite
- TypeScript
- Tailwind CSS
- Lucide Icons

## Setup

```bash
# Install dependencies
npm install

# Create environment file
cp .env.example .env

# Start development server
npm run dev
```

## Environment Variables

Create a `.env` file:

```env
# Backend API URL
VITE_API_URL=http://localhost:8000

# Beta access key
VITE_ACCESS_KEY=furthersec2026
```

## Available Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start dev server on port 5173 |
| `npm run build` | Build for production |
| `npm run preview` | Preview production build |

## Deploy to Vercel

1. Connect GitHub repo to Vercel
2. Set root directory: `frontend`
3. Set environment variables:
   - `VITE_API_URL` = your backend URL (e.g., `https://api.furthersecurity.com`)
4. Deploy

## Folder Structure

```
frontend/
├── src/
│   ├── components/     # UI components
│   ├── pages/          # Page components
│   ├── hooks/          # React hooks
│   ├── lib/            # API client
│   └── App.tsx         # Main app
├── public/             # Static assets
├── index.html          # Entry HTML
└── package.json        # Dependencies
```

