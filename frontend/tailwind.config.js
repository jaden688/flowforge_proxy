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
        background: '#0B0F17',
        surface: '#151D2A',
        'surface-hover': '#1E293B',
        border: '#1E293B',
        'border-light': '#334155',
        primary: {
          DEFAULT: '#38BDF8', // Cyan-400
          hover: '#0EA5E9',   // Cyan-500
          light: '#7DD3FC',
          dark: '#0284C7',
        },
        success: '#10B981', // Emerald-500
        warning: '#F59E0B', // Amber-500
        danger: '#EF4444',  // Rose/Red-500
        mutation: '#A855F7',// Purple-500
        idor: '#F97316',    // Orange-500
        reflection: '#EAB308', // Yellow-500
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
