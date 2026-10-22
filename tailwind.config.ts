import type { Config } from 'tailwindcss';

const v = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

// Brand palette: #13798A (primary), #8BA277 (secondary), #95A575 (accent). Everything else is derived tints/shades.
const config: Config = {
  darkMode: ['selector', '[data-theme="dark"]'],
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        primary: { DEFAULT: v('primary'), 50: '#e8f4f6', 100: '#c9e5ea', 200: '#9acbd4', 300: '#5fa9b8', 400: '#2f8c9c', 500: '#13798a', 600: '#0f6270', 700: '#0c4d58', 800: '#093a43', 900: '#06272d' },
        secondary: { DEFAULT: v('secondary'), 50: '#f1f5ee', 100: '#e0e9d9', 200: '#c4d4b8', 300: '#a6bd95', 400: '#8ba277', 500: '#738a60', 600: '#5b6f4c', 700: '#46563b' },
        accent: { DEFAULT: v('accent'), 100: '#e6ebdc', 300: '#b9c6a1', 500: '#95a575', 700: '#667350' },
        bg: v('bg'),
        surface: v('surface'),
        surface2: v('surface2'),
        ink: v('ink'),
        muted: v('muted'),
        line: v('line'),
      },
      fontFamily: { sans: ['var(--font-sans)', 'ui-sans-serif', 'system-ui', 'sans-serif'] },
      boxShadow: {
        card: '0 1px 2px rgb(var(--shadow) / .08), 0 12px 32px -12px rgb(var(--shadow) / .25)',
        lift: '0 2px 4px rgb(var(--shadow) / .1), 0 28px 48px -16px rgb(var(--shadow) / .4)',
        glow: '0 0 0 1px rgb(19 121 138 / .25), 0 0 32px rgb(19 121 138 / .35)',
      },
      keyframes: {
        shimmer: { '100%': { transform: 'translateX(100%)' } },
        blob: { '0%,100%': { transform: 'translate3d(0,0,0) scale(1)' }, '50%': { transform: 'translate3d(30px,-40px,0) scale(1.12)' } },
        pulseRing: { '0%': { boxShadow: '0 0 0 0 rgb(19 121 138 / .55)' }, '100%': { boxShadow: '0 0 0 10px rgb(19 121 138 / 0)' } },
      },
      animation: {
        shimmer: 'shimmer 1.6s infinite',
        blob: 'blob 18s ease-in-out infinite',
        pulseRing: 'pulseRing 1.8s ease-out infinite',
      },
    },
  },
  plugins: [],
};
export default config;
