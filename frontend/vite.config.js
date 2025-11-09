import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000
  },
  define: {
    'process.env.VITE_BACKEND_URL': JSON.stringify(
      process.env.NODE_ENV === 'production' 
        ? 'https://pr-agent-backend.onrender.com' 
        : 'http://localhost:8000'
    )
  }
})
