/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Barlow', 'sans-serif'],
        condensed: ['"Barlow Condensed"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      colors: {
        bg: 'var(--bg)',
        card: 'var(--card)',
        inset: 'var(--inset)',
        hover: 'var(--hover)',
        bd: 'var(--bd)',
        bd2: 'var(--bd2)',
        t1: 'var(--t1)',
        t2: 'var(--t2)',
        t3: 'var(--t3)',
        ac: 'var(--ac)',
        'ac-hover': 'var(--ac-hover)',
        ok: 'var(--ok)',
        crit: 'var(--crit)',
        hi: 'var(--hi)',
        med: 'var(--med)',
        low: 'var(--low)',
        cyber: {
          canvas: "#0b0f19",
          panel: "#111827",
          emerald: "#10b981",
          crimson: "#ef4444",
          amber: "#f59e0b",
          slate: "#64748b"
        }
      }
    },
  },
  plugins: [],
}
