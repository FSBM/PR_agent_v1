/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Deep dashboard blacks/grays
        'app-bg': '#08090A',
        'panel-bg': '#0D0E10',
        'border-dark': '#1F2128',
        'accent-purple': '#6E3FF3',
        // Status colors
        'status-green': '#22C55E',
        'status-red': '#EF4444',
        'status-blue': '#3B82F6',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
