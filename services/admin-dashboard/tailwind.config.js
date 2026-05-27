/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          canvas: "#0b0f19",
          panel: "#111827", // dark slate gray-900
          emerald: "#10b981", // emerald-500
          crimson: "#ef4444", // crimson-500
          amber: "#f59e0b", // amber-500
          slate: "#64748b" // slate-500
        }
      }
    },
  },
  plugins: [],
}
