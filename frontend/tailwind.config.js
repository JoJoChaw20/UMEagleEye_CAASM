/** @type {import('tailwindcss').Config} */

// Every colour is a CSS variable (an "R G B" triplet) set per theme in src/index.css,
// so dark, light and system modes switch without touching component code.
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`
const scale = (prefix, steps) => Object.fromEntries(steps.map((s) => [s, v(`${prefix}-${s}`)]))

export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Brand blue, sampled from the EagleEye logo (bright "Eye" top → deep base)
        eagle: scale('eagle', [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950]),
        // Navy-tinted neutrals. Named "dark" for history: 50 is the strongest text,
        // 950 the page ground, in both themes.
        dark: scale('dark', [50, 100, 200, 300, 400, 500, 600, 700, 800, 850, 900, 950]),
        accent: {
          cyan: v('accent-cyan'),
          green: v('accent-green'),
          amber: v('accent-amber'),
          red: v('accent-red'),
          purple: v('accent-purple'),
        },
        // The navy rail is the same in every theme: it carries the logo's world.
        rail: {
          DEFAULT: v('rail'),
          raised: v('rail-raised'),
          line: v('rail-line'),
          text: v('rail-text'),
          muted: v('rail-muted'),
        },
        // Categorical data series (device types, chart series), logo-derived first
        series: scale('series', [1, 2, 3, 4, 5, 6]),
        sev: {
          critical: v('sev-critical'),
          high: v('sev-high'),
          medium: v('sev-medium'),
          low: v('sev-low'),
        },
      },
      fontFamily: {
        sans: ['"Geist Variable"', 'Geist', 'system-ui', '-apple-system', '"Segoe UI"', 'sans-serif'],
        display: ['"Chakra Petch"', '"Geist Variable"', 'system-ui', 'sans-serif'],
        mono: ['"Geist Mono Variable"', '"Geist Mono"', 'ui-monospace', '"Cascadia Code"', 'Consolas', 'monospace'],
      },
      // Tighter corners than Tailwind's defaults: the logo is angular.
      borderRadius: {
        sm: '3px',
        DEFAULT: '4px',
        md: '6px',
        lg: '8px',
        xl: '10px',
        '2xl': '12px',
        '3xl': '16px',
      },
      boxShadow: {
        panel: '0 1px 2px rgb(var(--shadow) / 0.06), 0 2px 8px -2px rgb(var(--shadow) / 0.10)',
        float: '0 12px 32px -8px rgb(var(--shadow) / 0.35), 0 2px 6px rgb(var(--shadow) / 0.12)',
      },
      transitionTimingFunction: {
        out: 'cubic-bezier(0.16, 1, 0.3, 1)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
}
