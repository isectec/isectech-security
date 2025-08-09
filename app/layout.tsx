import type { Metadata, Viewport } from "next";
import { Inter } from 'next/font/google';
import { Providers } from './providers';
import { StoreInitializer } from './components/store-initializer';
import "./globals.css";

const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-inter',
});

export const metadata: Metadata = {
  title: "iSECTECH Protect - Enterprise Cybersecurity Command Center",
  description: "Advanced cybersecurity platform for enterprise threat detection, compliance management, and security operations.",
  keywords: ["cybersecurity", "threat detection", "compliance", "SIEM", "SOC", "security operations"],
  authors: [{ name: "iSECTECH" }],
  creator: "iSECTECH",
  publisher: "iSECTECH",
  robots: {
    index: false,
    follow: false,
  },
  icons: {
    icon: "/favicon.ico",
    shortcut: "/favicon-16x16.png",
    apple: "/apple-touch-icon.png",
  },
  manifest: "/manifest.json",
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://protect.isectech.com",
    title: "iSECTECH Protect",
    description: "Enterprise Cybersecurity Command Center",
    siteName: "iSECTECH Protect",
  },
  twitter: {
    card: "summary_large_image",
    title: "iSECTECH Protect",
    description: "Enterprise Cybersecurity Command Center",
    creator: "@isectech",
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#ffffff' },
    { media: '(prefers-color-scheme: dark)', color: '#0a0e1a' },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={inter.variable} suppressHydrationWarning>
      <head>
        <meta name="format-detection" content="telephone=no" />
        <meta name="msapplication-TileColor" content="#3a9fc5" />
        <meta name="theme-color" content="#3a9fc5" />
        
        {/* Security Headers */}
        <meta httpEquiv="X-Content-Type-Options" content="nosniff" />
        <meta httpEquiv="X-Frame-Options" content="DENY" />
        <meta httpEquiv="X-XSS-Protection" content="1; mode=block" />
        <meta httpEquiv="Referrer-Policy" content="strict-origin-when-cross-origin" />
        
        {/* Preconnect to improve performance */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body className={inter.className} suppressHydrationWarning>
        <Providers>
          <StoreInitializer />
          {children}
        </Providers>
      </body>
    </html>
  );
}
