import type { NextConfig } from "next";

/**
 * iSECTECH Frontend - Production Next.js Configuration
 * Optimized for security, performance, and Cloud Run deployment
 * Author: Claude Code - iSECTECH Infrastructure Team
 * Version: 2.0.0
 */

const nextConfig: NextConfig = {
  // Enable standalone output for containerization
  output: 'standalone',
  
  // Experimental features for optimization
  experimental: {
    // Required for standalone output
    outputFileTracingRoot: process.cwd(),
    
    // Optimize for serverless environments
    serverComponentsExternalPackages: ['sharp'],
    
    // Enable modern bundling
    turbo: {
      rules: {
        '*.svg': {
          loaders: ['@svgr/webpack'],
          as: '*.js',
        },
      },
    },
  },

  // Compiler optimizations
  compiler: {
    // Remove console logs in production
    removeConsole: process.env.NODE_ENV === 'production' ? {
      exclude: ['error', 'warn'],
    } : false,
    
    // Enable React optimizations
    reactRemoveProperties: process.env.NODE_ENV === 'production',
  },

  // Performance optimizations
  compress: true,
  poweredByHeader: false,
  generateEtags: true,
  trailingSlash: false,
  
  // Asset optimization
  optimizeFonts: true,
  optimizeCss: true,

  // Image optimization configuration
  images: {
    // Allowed domains for external images
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'isectech.com',
        pathname: '/**',
      },
      {
        protocol: 'https',
        hostname: 'cdn.isectech.com',
        pathname: '/**',
      },
      {
        protocol: 'https',
        hostname: 'assets.isectech.com',
        pathname: '/**',
      },
    ],
    
    // Supported formats (in order of preference)
    formats: ['image/avif', 'image/webp'],
    
    // Image sizes for responsive images
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
    
    // Cache optimization
    minimumCacheTTL: 3600, // 1 hour
    
    // Security: Disable SVG optimization
    dangerouslyAllowSVG: false,
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
  },

  // Security headers
  async headers() {
    const securityHeaders = [
      {
        key: 'X-DNS-Prefetch-Control',
        value: 'on'
      },
      {
        key: 'X-Frame-Options',
        value: 'DENY'
      },
      {
        key: 'X-Content-Type-Options',
        value: 'nosniff'
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
        value: [
          'camera=()',
          'microphone=()',
          'geolocation=()',
          'interest-cohort=()',
          'payment=()',
          'usb=()',
          'bluetooth=()',
          'magnetometer=()',
          'gyroscope=()',
          'accelerometer=()',
        ].join(', ')
      },
    ];

    // Add HSTS only in production with HTTPS
    if (process.env.NODE_ENV === 'production' && process.env.HSTS_ENABLED === 'true') {
      securityHeaders.push({
        key: 'Strict-Transport-Security',
        value: 'max-age=31536000; includeSubDomains; preload'
      });
    }

    // Content Security Policy
    if (process.env.CSP_ENABLED === 'true') {
      const cspDirectives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "img-src 'self' data: https: blob:",
        "font-src 'self' data: https://fonts.gstatic.com",
        "connect-src 'self' https://api.isectech.com https://gateway.isectech.com wss://ws.isectech.com https://www.google-analytics.com",
        "media-src 'self' data: blob:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "upgrade-insecure-requests",
      ];

      securityHeaders.push({
        key: 'Content-Security-Policy',
        value: cspDirectives.join('; ')
      });
    }

    return [
      {
        // Apply security headers to all routes
        source: '/(.*)',
        headers: securityHeaders,
      },
      {
        // Cache static assets for 1 year
        source: '/static/(.*)',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
        ],
      },
      {
        // Cache images for 1 week
        source: '/_next/image(.*)',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=604800, immutable',
          },
        ],
      },
      {
        // Cache Next.js static files for 1 year
        source: '/_next/static/(.*)',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
        ],
      },
    ];
  },

  // Redirects for security and SEO
  async redirects() {
    return [
      // Redirect HTTP to HTTPS in production
      ...(process.env.NODE_ENV === 'production' ? [
        {
          source: '/:path*',
          has: [
            {
              type: 'header',
              key: 'x-forwarded-proto',
              value: 'http',
            },
          ],
          destination: 'https://protect.isectech.com/:path*',
          permanent: true,
        },
      ] : []),
      
      // Legacy route redirects
      {
        source: '/dashboard',
        destination: '/',
        permanent: true,
      },
      {
        source: '/login',
        destination: '/auth/login',
        permanent: true,
      },
    ];
  },

  // Rewrites for API proxying and routing
  async rewrites() {
    return {
      beforeFiles: [
        // Health check endpoint
        {
          source: '/health',
          destination: '/api/health',
        },
        // Robots.txt
        {
          source: '/robots.txt',
          destination: '/api/robots',
        },
        // Sitemap
        {
          source: '/sitemap.xml',
          destination: '/api/sitemap',
        },
      ],
      afterFiles: [
        // API gateway proxy
        {
          source: '/api/v1/:path*',
          destination: `${process.env.NEXT_PUBLIC_API_GATEWAY_URL || 'http://localhost:8080'}/api/v1/:path*`,
        },
      ],
      fallback: [
        // Catch-all for SPA routing
        {
          source: '/((?!api|_next|_static|favicon.ico).*)',
          destination: '/',
        },
      ],
    };
  },

  // Bundle analysis (enable with ANALYZE=true)
  webpack: (config, { buildId, dev, isServer, defaultLoaders, webpack }) => {
    // Bundle analyzer
    if (process.env.ANALYZE === 'true' && !dev && !isServer) {
      const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer');
      config.plugins.push(
        new BundleAnalyzerPlugin({
          analyzerMode: 'static',
          openAnalyzer: false,
          reportFilename: 'bundle-analyzer-report.html',
        })
      );
    }

    // Optimize SVG imports
    config.module.rules.push({
      test: /\.svg$/,
      use: ['@svgr/webpack'],
    });

    // Source maps in production for debugging (can be disabled)
    if (!dev && process.env.GENERATE_SOURCEMAP !== 'false') {
      config.devtool = 'source-map';
    }

    // Optimize chunks
    if (!dev && !isServer) {
      config.optimization.splitChunks = {
        chunks: 'all',
        cacheGroups: {
          default: {
            minChunks: 2,
            priority: -20,
            reuseExistingChunk: true,
          },
          vendor: {
            test: /[\\/]node_modules[\\/]/,
            name: 'vendors',
            priority: -10,
            chunks: 'all',
          },
          mui: {
            test: /[\\/]node_modules[\\/]@mui[\\/]/,
            name: 'mui',
            priority: 10,
            chunks: 'all',
          },
          react: {
            test: /[\\/]node_modules[\\/](react|react-dom)[\\/]/,
            name: 'react',
            priority: 20,
            chunks: 'all',
          },
        },
      };
    }

    return config;
  },

  // Environment variables validation and exposure
  env: {
    // Build information
    BUILD_DATE: process.env.BUILD_DATE || new Date().toISOString(),
    BUILD_VERSION: process.env.BUILD_VERSION || '2.0.0',
    BUILD_COMMIT: process.env.BUILD_COMMIT || 'unknown',
    
    // Security configuration
    SECURITY_HEADERS_ENABLED: process.env.SECURITY_HEADERS_ENABLED || 'true',
    CSP_ENABLED: process.env.CSP_ENABLED || 'true',
    HSTS_ENABLED: process.env.HSTS_ENABLED || 'true',
    
    // Performance monitoring
    PERFORMANCE_MONITORING: process.env.PERFORMANCE_MONITORING || 'false',
    ANALYTICS_ENABLED: process.env.ANALYTICS_ENABLED || 'false',
  },

  // TypeScript and ESLint configuration
  typescript: {
    // Dangerously allow production builds to successfully complete even if
    // your project has type errors (not recommended for production)
    ignoreBuildErrors: false,
  },
  eslint: {
    // Warning: This allows production builds to successfully complete even if
    // your project has ESLint errors (not recommended for production)
    ignoreDuringBuilds: false,
  },

  // Disable telemetry
  ...(process.env.NEXT_TELEMETRY_DISABLED === '1' && {
    telemetry: {
      enabled: false,
    },
  }),
};

export default nextConfig;