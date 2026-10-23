/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./index.html', './js/**/*.js'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['system-ui', '-apple-system', '"Segoe UI"', 'Roboto', 'Ubuntu', 'sans-serif'],
        mono: ['ui-monospace', '"Cascadia Code"', '"JetBrains Mono"', 'Consolas', '"DejaVu Sans Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
};
