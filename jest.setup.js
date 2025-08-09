/**
 * Jest Test Setup for iSECTECH Protect
 * Production-grade testing configuration for cybersecurity components
 */

import '@testing-library/jest-dom';
import 'jest-axe/extend-expect';

// Mock IntersectionObserver for virtualized components
global.IntersectionObserver = class IntersectionObserver {
  constructor() {}
  observe() {
    return null;
  }
  disconnect() {
    return null;
  }
  unobserve() {
    return null;
  }
};

// Mock ResizeObserver for responsive components
global.ResizeObserver = class ResizeObserver {
  constructor(cb) {
    this.cb = cb;
  }
  observe() {
    return null;
  }
  unobserve() {
    return null;
  }
  disconnect() {
    return null;
  }
};

// Mock Canvas for chart components
HTMLCanvasElement.prototype.getContext = jest.fn(() => ({
  fillRect: jest.fn(),
  clearRect: jest.fn(),
  getImageData: jest.fn(() => ({ data: new Array(4) })),
  putImageData: jest.fn(),
  createImageData: jest.fn(() => []),
  setTransform: jest.fn(),
  drawImage: jest.fn(),
  save: jest.fn(),
  fillText: jest.fn(),
  restore: jest.fn(),
  beginPath: jest.fn(),
  moveTo: jest.fn(),
  lineTo: jest.fn(),
  closePath: jest.fn(),
  stroke: jest.fn(),
  translate: jest.fn(),
  scale: jest.fn(),
  rotate: jest.fn(),
  arc: jest.fn(),
  fill: jest.fn(),
  measureText: jest.fn(() => ({ width: 0 })),
  transform: jest.fn(),
  rect: jest.fn(),
  clip: jest.fn(),
}));

// Mock WebGL for 3D visualizations
HTMLCanvasElement.prototype.getContext = jest.fn((type) => {
  if (type === 'webgl' || type === 'webgl2') {
    return {
      canvas: {},
      drawingBufferWidth: 1024,
      drawingBufferHeight: 768,
      getExtension: jest.fn(),
      getParameter: jest.fn(),
      createShader: jest.fn(),
      shaderSource: jest.fn(),
      compileShader: jest.fn(),
      createProgram: jest.fn(),
      attachShader: jest.fn(),
      linkProgram: jest.fn(),
      useProgram: jest.fn(),
      createBuffer: jest.fn(),
      bindBuffer: jest.fn(),
      bufferData: jest.fn(),
      enableVertexAttribArray: jest.fn(),
      vertexAttribPointer: jest.fn(),
      drawArrays: jest.fn(),
      clear: jest.fn(),
      clearColor: jest.fn(),
      enable: jest.fn(),
      viewport: jest.fn(),
    };
  }
  return null;
});

// Mock audio context for audio alerts
global.AudioContext = jest.fn().mockImplementation(() => ({
  createOscillator: jest.fn(() => ({
    connect: jest.fn(),
    start: jest.fn(),
    stop: jest.fn(),
    frequency: { value: 0 },
    type: 'sine',
  })),
  createGain: jest.fn(() => ({
    connect: jest.fn(),
    gain: { value: 0 },
  })),
  destination: {},
  currentTime: 0,
  close: jest.fn(),
}));

// Mock Web Crypto API for security testing
Object.defineProperty(global, 'crypto', {
  value: {
    getRandomValues: jest.fn((arr) => {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = Math.floor(Math.random() * 256);
      }
      return arr;
    }),
    randomUUID: jest.fn(() => '123e4567-e89b-12d3-a456-426614174000'),
    subtle: {
      encrypt: jest.fn(),
      decrypt: jest.fn(),
      sign: jest.fn(),
      verify: jest.fn(),
      digest: jest.fn(),
      generateKey: jest.fn(),
      importKey: jest.fn(),
      exportKey: jest.fn(),
    },
  },
});

// Mock notification API for alert testing
global.Notification = jest.fn().mockImplementation((title, options) => ({
  title,
  ...options,
  close: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
}));

Object.defineProperty(global.Notification, 'permission', {
  value: 'granted',
  writable: true,
});

Object.defineProperty(global.Notification, 'requestPermission', {
  value: jest.fn(() => Promise.resolve('granted')),
  writable: true,
});

// Mock geolocation for location-based security features
global.navigator.geolocation = {
  getCurrentPosition: jest.fn((success) => {
    success({
      coords: {
        latitude: 40.7128,
        longitude: -74.006,
        accuracy: 10,
      },
    });
  }),
  watchPosition: jest.fn(),
  clearWatch: jest.fn(),
};

// Mock clipboard API for secure copy operations
Object.defineProperty(global.navigator, 'clipboard', {
  value: {
    writeText: jest.fn(() => Promise.resolve()),
    readText: jest.fn(() => Promise.resolve('mocked text')),
  },
  writable: true,
});

// Mock service worker for PWA testing
Object.defineProperty(global.navigator, 'serviceWorker', {
  value: {
    register: jest.fn(() => Promise.resolve()),
    ready: Promise.resolve({
      unregister: jest.fn(() => Promise.resolve(true)),
    }),
  },
  writable: true,
});

// Mock performance API for metrics testing
global.performance = global.performance || {
  now: jest.fn(() => Date.now()),
  mark: jest.fn(),
  measure: jest.fn(),
  getEntriesByName: jest.fn(() => []),
  getEntriesByType: jest.fn(() => []),
  clearMarks: jest.fn(),
  clearMeasures: jest.fn(),
  timing: {
    navigationStart: Date.now(),
    loadEventEnd: Date.now() + 1000,
  },
};

// Mock fetch for API testing
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    status: 200,
    statusText: 'OK',
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(''),
    blob: () => Promise.resolve(new Blob()),
    headers: new Map(),
  })
);

// Mock WebSocket for real-time testing
global.WebSocket = jest.fn().mockImplementation(() => ({
  send: jest.fn(),
  close: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
  readyState: 1, // OPEN
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3,
}));

// Mock localStorage and sessionStorage
const mockStorage = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
  length: 0,
  key: jest.fn(),
};

Object.defineProperty(global, 'localStorage', { value: mockStorage });
Object.defineProperty(global, 'sessionStorage', { value: mockStorage });

// Mock URL and URLSearchParams
global.URL = class URL {
  constructor(url, base) {
    this.href = base ? `${base}/${url}` : url;
    this.origin = 'http://localhost:3000';
    this.pathname = '/';
    this.search = '';
    this.hash = '';
  }

  toString() {
    return this.href;
  }
};

global.URLSearchParams = class URLSearchParams {
  constructor(init) {
    this.params = new Map();
    if (init) {
      if (typeof init === 'string') {
        // Parse string
        init.split('&').forEach((pair) => {
          const [key, value] = pair.split('=');
          if (key) this.params.set(decodeURIComponent(key), decodeURIComponent(value || ''));
        });
      }
    }
  }

  get(name) {
    return this.params.get(name);
  }

  set(name, value) {
    this.params.set(name, value);
  }

  toString() {
    return Array.from(this.params.entries())
      .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
      .join('&');
  }
};

// Security-specific test utilities
global.testUtils = {
  // Generate mock security events
  mockSecurityEvent: (type = 'threat_detected', severity = 'high') => ({
    id: Math.random().toString(36).substr(2, 9),
    timestamp: new Date().toISOString(),
    type,
    severity,
    source: 'test-source',
    description: `Mock ${type} event`,
    metadata: {
      source_ip: '192.168.1.100',
      destination_ip: '10.0.0.1',
      protocol: 'TCP',
      port: 443,
    },
  }),

  // Generate mock threat intelligence
  mockThreatIntel: (confidence = 'high') => ({
    id: Math.random().toString(36).substr(2, 9),
    indicator: '192.168.1.100',
    type: 'ip',
    confidence,
    tags: ['malware', 'botnet'],
    source: 'test-feed',
    created: new Date().toISOString(),
  }),

  // Generate mock user session
  mockUserSession: (role = 'analyst') => ({
    id: Math.random().toString(36).substr(2, 9),
    user: {
      id: 'test-user',
      email: 'test@isectech.com',
      name: 'Test User',
      role,
      permissions: ['read:alerts', 'read:threats'],
    },
    token: 'mock-jwt-token',
    expires: new Date(Date.now() + 3600000).toISOString(),
  }),
};

// Error boundary for testing error states
global.ErrorBoundary = ({ children, fallback }) => {
  try {
    return children;
  } catch (error) {
    return fallback || null;
  }
};

// Suppress console errors in tests unless debugging
const originalError = console.error;
console.error = (...args) => {
  if (process.env.DEBUG_TESTS === 'true') {
    originalError(...args);
  }
};

// Custom matchers for security testing
expect.extend({
  toBeSecureComponent(received) {
    const hasAriaLabels = received.getAttribute('aria-label') !== null;
    const hasRole = received.getAttribute('role') !== null;
    const hasTabIndex = received.getAttribute('tabindex') !== null;

    return {
      message: () => `expected component to have security accessibility attributes`,
      pass: hasAriaLabels || hasRole || hasTabIndex,
    };
  },

  toHaveSecurityLevel(received, level) {
    const securityAttr = received.getAttribute('data-security-level');
    return {
      message: () => `expected component to have security level ${level}`,
      pass: securityAttr === level,
    };
  },
});
