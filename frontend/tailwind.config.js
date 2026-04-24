/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // UMEagleEye brand palette
        eagle: {
          50: '#eef7ff',
          100: '#d9edff',
          200: '#bce0ff',
          300: '#8eceff',
          400: '#59b3ff',
          500: '#3393ff',
          600: '#1b75f5',
          700: '#145ee1',
          800: '#174db6',
          900: '#19438f',
          950: '#142a57',
        },
        dark: {
          50: '#f6f6f7',
          100: '#e2e3e5',
          200: '#c4c6cb',
          300: '#9fa2a9',
          400: '#7b7f87',
          500: '#60646d',
          600: '#4c4f57',
          700: '#3e4047',
          800: '#1e2028',
          850: '#191b22',
          900: '#14161d',
          950: '#0d0e13',
        },
        accent: {
          cyan: '#00e5ff',
          green: '#00e676',
          amber: '#ffc400',
          red: '#ff5252',
          purple: '#b388ff',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(51, 147, 255, 0.3)' },
          '100%': { boxShadow: '0 0 20px rgba(51, 147, 255, 0.6)' },
        },
      },
    },
  },
  plugins: [],
}
