/**
 * Web Worker Mock for Jest Testing
 */

class MockWorker {
  constructor(stringUrl) {
    this.url = stringUrl;
    this.onmessage = null;
    this.onerror = null;
  }

  postMessage(msg) {
    // Mock immediate response
    setTimeout(() => {
      if (this.onmessage) {
        this.onmessage({ data: { ...msg, result: 'mock-result' } });
      }
    }, 0);
  }

  terminate() {
    // Mock termination
  }

  addEventListener(type, listener) {
    if (type === 'message') {
      this.onmessage = listener;
    } else if (type === 'error') {
      this.onerror = listener;
    }
  }

  removeEventListener(type, listener) {
    if (type === 'message' && this.onmessage === listener) {
      this.onmessage = null;
    } else if (type === 'error' && this.onerror === listener) {
      this.onerror = null;
    }
  }
}

module.exports = MockWorker;
