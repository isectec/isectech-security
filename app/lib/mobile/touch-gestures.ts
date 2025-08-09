/**
 * Touch Gesture Utilities for iSECTECH Protect PWA
 * Provides enhanced touch interactions for mobile devices
 */

interface TouchPoint {
  x: number;
  y: number;
  timestamp: number;
}

interface SwipeGesture {
  direction: 'left' | 'right' | 'up' | 'down';
  distance: number;
  velocity: number;
  duration: number;
}

interface PinchGesture {
  scale: number;
  center: TouchPoint;
  velocity: number;
}

interface TapGesture {
  point: TouchPoint;
  tapCount: number;
  duration: number;
}

interface TouchGestureOptions {
  swipeThreshold?: number;
  velocityThreshold?: number;
  doubleTapDelay?: number;
  longPressDelay?: number;
  pinchThreshold?: number;
}

export class TouchGestureHandler {
  private element: HTMLElement;
  private options: Required<TouchGestureOptions>;
  private startTouch: TouchPoint | null = null;
  private lastTouch: TouchPoint | null = null;
  private touchCount = 0;
  private lastTapTime = 0;
  private longPressTimeout: NodeJS.Timeout | null = null;
  private initialPinchDistance = 0;

  // Gesture callbacks
  public onSwipe?: (gesture: SwipeGesture) => void;
  public onPinch?: (gesture: PinchGesture) => void;
  public onTap?: (gesture: TapGesture) => void;
  public onDoubleTap?: (gesture: TapGesture) => void;
  public onLongPress?: (point: TouchPoint) => void;
  public onPan?: (delta: { x: number; y: number }, point: TouchPoint) => void;

  constructor(element: HTMLElement, options: TouchGestureOptions = {}) {
    this.element = element;
    this.options = {
      swipeThreshold: options.swipeThreshold || 50,
      velocityThreshold: options.velocityThreshold || 0.3,
      doubleTapDelay: options.doubleTapDelay || 300,
      longPressDelay: options.longPressDelay || 500,
      pinchThreshold: options.pinchThreshold || 10,
    };

    this.bindEvents();
  }

  private bindEvents() {
    // Prevent default touch behaviors that might interfere
    this.element.style.touchAction = 'pan-x pan-y';
    
    this.element.addEventListener('touchstart', this.handleTouchStart, { passive: false });
    this.element.addEventListener('touchmove', this.handleTouchMove, { passive: false });
    this.element.addEventListener('touchend', this.handleTouchEnd, { passive: false });
    this.element.addEventListener('touchcancel', this.handleTouchCancel, { passive: false });

    // Add mouse events for testing on desktop
    this.element.addEventListener('mousedown', this.handleMouseDown);
    this.element.addEventListener('mousemove', this.handleMouseMove);
    this.element.addEventListener('mouseup', this.handleMouseUp);
  }

  private getTouchPoint(touch: Touch | MouseEvent): TouchPoint {
    const clientX = 'clientX' in touch ? touch.clientX : touch.touches[0].clientX;
    const clientY = 'clientY' in touch ? touch.clientY : touch.touches[0].clientY;
    
    return {
      x: clientX,
      y: clientY,
      timestamp: Date.now(),
    };
  }

  private getDistance(point1: TouchPoint, point2: TouchPoint): number {
    const dx = point2.x - point1.x;
    const dy = point2.y - point1.y;
    return Math.sqrt(dx * dx + dy * dy);
  }

  private getDirection(start: TouchPoint, end: TouchPoint): SwipeGesture['direction'] {
    const dx = end.x - start.x;
    const dy = end.y - start.y;
    
    if (Math.abs(dx) > Math.abs(dy)) {
      return dx > 0 ? 'right' : 'left';
    } else {
      return dy > 0 ? 'down' : 'up';
    }
  }

  private getPinchDistance(touches: TouchList): number {
    if (touches.length < 2) return 0;
    
    const touch1 = touches[0];
    const touch2 = touches[1];
    
    const dx = touch2.clientX - touch1.clientX;
    const dy = touch2.clientY - touch1.clientY;
    
    return Math.sqrt(dx * dx + dy * dy);
  }

  private getPinchCenter(touches: TouchList): TouchPoint {
    if (touches.length < 2) {
      return this.getTouchPoint(touches[0]);
    }
    
    const touch1 = touches[0];
    const touch2 = touches[1];
    
    return {
      x: (touch1.clientX + touch2.clientX) / 2,
      y: (touch1.clientY + touch2.clientY) / 2,
      timestamp: Date.now(),
    };
  }

  private handleTouchStart = (event: TouchEvent) => {
    this.touchCount = event.touches.length;
    
    if (this.touchCount === 1) {
      this.startTouch = this.getTouchPoint(event.touches[0]);
      this.lastTouch = { ...this.startTouch };
      
      // Start long press timer
      this.longPressTimeout = setTimeout(() => {
        if (this.startTouch && this.onLongPress) {
          this.onLongPress(this.startTouch);
        }
      }, this.options.longPressDelay);
      
    } else if (this.touchCount === 2) {
      // Handle pinch start
      this.initialPinchDistance = this.getPinchDistance(event.touches);
      this.clearLongPressTimeout();
    }
  };

  private handleTouchMove = (event: TouchEvent) => {
    if (!this.startTouch) return;
    
    // Prevent scrolling when handling gestures
    event.preventDefault();
    
    if (this.touchCount === 1) {
      const currentTouch = this.getTouchPoint(event.touches[0]);
      
      // Handle pan gesture
      if (this.lastTouch && this.onPan) {
        const delta = {
          x: currentTouch.x - this.lastTouch.x,
          y: currentTouch.y - this.lastTouch.y,
        };
        this.onPan(delta, currentTouch);
      }
      
      this.lastTouch = currentTouch;
      
      // Clear long press if moved too far
      const distance = this.getDistance(this.startTouch, currentTouch);
      if (distance > this.options.swipeThreshold / 2) {
        this.clearLongPressTimeout();
      }
      
    } else if (this.touchCount === 2 && this.onPinch) {
      // Handle pinch gesture
      const currentDistance = this.getPinchDistance(event.touches);
      const scale = currentDistance / this.initialPinchDistance;
      const center = this.getPinchCenter(event.touches);
      
      this.onPinch({
        scale,
        center,
        velocity: 0, // Could calculate this with timestamps
      });
    }
  };

  private handleTouchEnd = (event: TouchEvent) => {
    this.clearLongPressTimeout();
    
    if (!this.startTouch || !this.lastTouch) return;
    
    const endTouch = this.lastTouch;
    const distance = this.getDistance(this.startTouch, endTouch);
    const duration = endTouch.timestamp - this.startTouch.timestamp;
    const velocity = distance / duration;
    
    if (distance > this.options.swipeThreshold && velocity > this.options.velocityThreshold) {
      // Handle swipe gesture
      if (this.onSwipe) {
        this.onSwipe({
          direction: this.getDirection(this.startTouch, endTouch),
          distance,
          velocity,
          duration,
        });
      }
    } else if (distance < this.options.swipeThreshold / 4) {
      // Handle tap gesture
      const now = Date.now();
      const timeSinceLastTap = now - this.lastTapTime;
      
      const tapGesture: TapGesture = {
        point: endTouch,
        tapCount: 1,
        duration,
      };
      
      if (timeSinceLastTap < this.options.doubleTapDelay) {
        // Double tap
        tapGesture.tapCount = 2;
        if (this.onDoubleTap) {
          this.onDoubleTap(tapGesture);
        }
      } else {
        // Single tap (delay to check for double tap)
        setTimeout(() => {
          const finalTimeSinceLastTap = Date.now() - now;
          if (finalTimeSinceLastTap >= this.options.doubleTapDelay) {
            if (this.onTap) {
              this.onTap(tapGesture);
            }
          }
        }, this.options.doubleTapDelay);
      }
      
      this.lastTapTime = now;
    }
    
    this.startTouch = null;
    this.lastTouch = null;
    this.touchCount = 0;
  };

  private handleTouchCancel = () => {
    this.clearLongPressTimeout();
    this.startTouch = null;
    this.lastTouch = null;
    this.touchCount = 0;
  };

  private clearLongPressTimeout() {
    if (this.longPressTimeout) {
      clearTimeout(this.longPressTimeout);
      this.longPressTimeout = null;
    }
  }

  // Mouse event handlers for desktop testing
  private handleMouseDown = (event: MouseEvent) => {
    this.startTouch = this.getTouchPoint(event);
    this.lastTouch = { ...this.startTouch };
    this.touchCount = 1;
  };

  private handleMouseMove = (event: MouseEvent) => {
    if (!this.startTouch) return;
    
    const currentTouch = this.getTouchPoint(event);
    
    if (this.lastTouch && this.onPan) {
      const delta = {
        x: currentTouch.x - this.lastTouch.x,
        y: currentTouch.y - this.lastTouch.y,
      };
      this.onPan(delta, currentTouch);
    }
    
    this.lastTouch = currentTouch;
  };

  private handleMouseUp = (event: MouseEvent) => {
    if (!this.startTouch || !this.lastTouch) return;
    
    const endTouch = this.getTouchPoint(event);
    const distance = this.getDistance(this.startTouch, endTouch);
    const duration = endTouch.timestamp - this.startTouch.timestamp;
    
    if (distance < this.options.swipeThreshold / 4) {
      // Handle click as tap
      if (this.onTap) {
        this.onTap({
          point: endTouch,
          tapCount: 1,
          duration,
        });
      }
    }
    
    this.startTouch = null;
    this.lastTouch = null;
    this.touchCount = 0;
  };

  public destroy() {
    this.element.removeEventListener('touchstart', this.handleTouchStart);
    this.element.removeEventListener('touchmove', this.handleTouchMove);
    this.element.removeEventListener('touchend', this.handleTouchEnd);
    this.element.removeEventListener('touchcancel', this.handleTouchCancel);
    this.element.removeEventListener('mousedown', this.handleMouseDown);
    this.element.removeEventListener('mousemove', this.handleMouseMove);
    this.element.removeEventListener('mouseup', this.handleMouseUp);
    
    this.clearLongPressTimeout();
  }
}

// Haptic feedback utilities
export const hapticFeedback = {
  // Light haptic feedback for UI interactions
  light() {
    if ('vibrate' in navigator) {
      navigator.vibrate(10);
    }
  },

  // Medium haptic feedback for confirmations
  medium() {
    if ('vibrate' in navigator) {
      navigator.vibrate(20);
    }
  },

  // Heavy haptic feedback for errors or important actions
  heavy() {
    if ('vibrate' in navigator) {
      navigator.vibrate([30, 10, 30]);
    }
  },

  // Custom vibration pattern
  custom(pattern: number | number[]) {
    if ('vibrate' in navigator) {
      navigator.vibrate(pattern);
    }
  },

  // Success pattern
  success() {
    if ('vibrate' in navigator) {
      navigator.vibrate([20, 10, 20]);
    }
  },

  // Error pattern
  error() {
    if ('vibrate' in navigator) {
      navigator.vibrate([50, 20, 50, 20, 50]);
    }
  },
};

// Touch accessibility utilities
export const touchAccessibility = {
  // Ensure touch targets meet minimum size requirements (44px)
  enhanceTouchTargets(selector: string = 'button, a, [role="button"]') {
    const elements = document.querySelectorAll(selector);
    
    elements.forEach(element => {
      const computedStyle = getComputedStyle(element as Element);
      const width = parseFloat(computedStyle.width);
      const height = parseFloat(computedStyle.height);
      
      if (width < 44 || height < 44) {
        (element as HTMLElement).style.minWidth = '44px';
        (element as HTMLElement).style.minHeight = '44px';
        (element as HTMLElement).style.display = 'inline-flex';
        (element as HTMLElement).style.alignItems = 'center';
        (element as HTMLElement).style.justifyContent = 'center';
      }
    });
  },

  // Add touch feedback to interactive elements
  addTouchFeedback(selector: string = 'button, a, [role="button"]') {
    const elements = document.querySelectorAll(selector);
    
    elements.forEach(element => {
      const htmlElement = element as HTMLElement;
      
      const addActiveClass = () => {
        htmlElement.classList.add('touch-active');
        hapticFeedback.light();
      };
      
      const removeActiveClass = () => {
        htmlElement.classList.remove('touch-active');
      };
      
      htmlElement.addEventListener('touchstart', addActiveClass, { passive: true });
      htmlElement.addEventListener('touchend', removeActiveClass, { passive: true });
      htmlElement.addEventListener('touchcancel', removeActiveClass, { passive: true });
    });
    
    // Add CSS for touch feedback if not already present
    if (!document.querySelector('#touch-feedback-styles')) {
      const style = document.createElement('style');
      style.id = 'touch-feedback-styles';
      style.textContent = `
        .touch-active {
          opacity: 0.7;
          transform: scale(0.98);
          transition: opacity 0.1s ease, transform 0.1s ease;
        }
      `;
      document.head.appendChild(style);
    }
  },
};

// Responsive utilities for mobile
export const responsiveUtils = {
  // Get current viewport size category
  getViewportCategory(): 'mobile' | 'tablet' | 'desktop' {
    const width = window.innerWidth;
    
    if (width < 768) return 'mobile';
    if (width < 1024) return 'tablet';
    return 'desktop';
  },

  // Check if device is in portrait mode
  isPortrait(): boolean {
    return window.innerHeight > window.innerWidth;
  },

  // Get safe area insets for devices with notches
  getSafeAreaInsets() {
    const style = getComputedStyle(document.documentElement);
    return {
      top: parseInt(style.getPropertyValue('--sat') || '0px'),
      right: parseInt(style.getPropertyValue('--sar') || '0px'),
      bottom: parseInt(style.getPropertyValue('--sab') || '0px'),
      left: parseInt(style.getPropertyValue('--sal') || '0px'),
    };
  },

  // Adjust layout for keyboard on mobile
  handleVirtualKeyboard() {
    if (!('visualViewport' in window)) return;
    
    const viewport = window.visualViewport;
    
    const updateLayout = () => {
      const keyboardHeight = window.innerHeight - viewport!.height;
      document.documentElement.style.setProperty(
        '--keyboard-height',
        `${keyboardHeight}px`
      );
      
      document.documentElement.classList.toggle(
        'keyboard-visible',
        keyboardHeight > 100
      );
    };
    
    viewport!.addEventListener('resize', updateLayout);
    return () => viewport!.removeEventListener('resize', updateLayout);
  },

  // Optimize for dark mode
  handleDarkMode() {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    const updateTheme = (e: MediaQueryListEvent) => {
      document.documentElement.classList.toggle('dark-mode', e.matches);
      
      // Update meta theme color
      const metaTheme = document.querySelector('meta[name="theme-color"]');
      if (metaTheme) {
        metaTheme.setAttribute('content', e.matches ? '#0a0e1a' : '#ffffff');
      }
    };
    
    // Initial setup
    updateTheme({ matches: mediaQuery.matches } as MediaQueryListEvent);
    
    mediaQuery.addEventListener('change', updateTheme);
    return () => mediaQuery.removeEventListener('change', updateTheme);
  },
};

export default {
  TouchGestureHandler,
  hapticFeedback,
  touchAccessibility,
  responsiveUtils,
};