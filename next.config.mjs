import path from 'node:path';

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  outputFileTracingRoot: import.meta.dirname,
  poweredByHeader: false,
  // Explicit alias: tsconfig path resolution proved unreliable for project paths containing parentheses.
  webpack(config) {
    config.resolve.alias['@'] = path.join(import.meta.dirname, 'src');
    return config;
  },
  experimental: { optimizePackageImports: ['lucide-react', 'recharts', 'framer-motion'] },
  // Spec-named URLs that map onto existing screens. Middleware still authorises the visible URL first.
  async rewrites() {
    return [
      { source: '/admin/dashboard', destination: '/admin' },
      { source: '/admin/employees', destination: '/admin/users' },
      { source: '/admin/clients', destination: '/clients' },
      { source: '/development/dashboard', destination: '/development' },
      { source: '/marketing/dashboard', destination: '/marketing' },
      { source: '/creative/dashboard', destination: '/creative' },
    ];
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        ],
      },
    ];
  },
};
export default nextConfig;
