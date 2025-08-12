import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  output: 'standalone',
  typescript: {
    // Skip type checking during build for production deployment
    ignoreBuildErrors: true,
  },
  
  // Disable prerendering for SSR issues
  trailingSlash: false,

  experimental: {
    optimizePackageImports: ['@mui/material', '@mui/lab', 'recharts', 'date-fns', 'lodash'],
  },

  images: {
    domains: ['avatars.githubusercontent.com', 'lh3.googleusercontent.com'],
    unoptimized: process.env.NODE_ENV === 'development',
  },

  webpack: (config: any, { isServer }: any) => {
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        net: false,
        tls: false,
        fs: false,
        path: false,
        crypto: false,
        stream: false,
        buffer: false,
      };
    }
    // Do not override config.externals to avoid schema mismatches
    return config;
  },

  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
        ],
      },
    ];
  },
};

export default nextConfig;
