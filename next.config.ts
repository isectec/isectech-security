import type { NextConfig } from "next";

const isProd = process.env.NODE_ENV === 'production';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // swcMinify is removed in Next.js 15; SWC minification is always on
  
  // Experimental features for optimization
  experimental: {
    // migrate to supported key
    serverExternalPackages: ['sharp'],
    optimizePackageImports: ['@mui/material', '@mui/icons-material', 'lodash-es'],
  },

  // Performance optimizations
  compress: true,
  poweredByHeader: false,
  generateEtags: true,

  // Image optimization
  images: {
    formats: ['image/avif', 'image/webp'],
    deviceSizes: [640, 750, 828, 1080, 1200, 1920],
    imageSizes: [16, 32, 48, 64, 96, 128, 256],
    minimumCacheTTL: 3600,
  },

  // Webpack optimizations
  webpack: (config, { dev, isServer }) => {
    // Optimize chunks for better caching
    if (!dev && !isServer) {
      config.optimization.splitChunks = {
        chunks: 'all',
        cacheGroups: {
          mui: {
            test: /[\\/]node_modules[\\/]@mui[\\/]/,
            name: 'mui',
            priority: 10,
          },
          vendor: {
            test: /[\\/]node_modules[\\/]/,
            name: 'vendors',
            priority: -10,
          },
        },
      };
    }
    return config;
  },

  // Mobile-first headers
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block'
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin'
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), notification=(self)'
          }
        ]
      }
    ];
  },
};

export default nextConfig;
