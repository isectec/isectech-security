/**
 * Jest Module Name Mapping Configuration
 * Maps module imports for testing environment
 */

module.exports = {
  // SVG files
  '\\.svg$': '<rootDir>/__mocks__/svg.js',

  // Image files
  '\\.(jpg|jpeg|png|gif|webp|avif)$': '<rootDir>/__mocks__/image.js',

  // Font files
  '\\.(woff|woff2|eot|ttf|otf)$': '<rootDir>/__mocks__/font.js',

  // CSS modules
  '\\.module\\.(css|scss|sass)$': 'identity-obj-proxy',

  // Regular CSS
  '\\.(css|scss|sass)$': '<rootDir>/__mocks__/style.js',

  // Video files
  '\\.(mp4|webm|ogg|avi|mov)$': '<rootDir>/__mocks__/video.js',

  // Audio files
  '\\.(mp3|wav|ogg|flac|aac)$': '<rootDir>/__mocks__/audio.js',

  // Data files
  '\\.(json|yaml|yml|xml)$': '<rootDir>/__mocks__/data.js',

  // PDF files
  '\\.pdf$': '<rootDir>/__mocks__/pdf.js',

  // WebAssembly
  '\\.wasm$': '<rootDir>/__mocks__/wasm.js',

  // Worker files
  '\\.worker\\.(js|ts)$': '<rootDir>/__mocks__/worker.js',
};
