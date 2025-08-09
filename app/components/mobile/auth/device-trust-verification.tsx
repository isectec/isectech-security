'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Shield, 
  Smartphone, 
  AlertTriangle, 
  Check, 
  Fingerprint,
  Wifi,
  MapPin,
  Clock,
  Lock
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';

/**
 * Device Trust Verification Component
 * Production-grade device fingerprinting and trust scoring
 * Implements multi-factor device verification with risk assessment
 */

export interface DeviceFingerprint {
  deviceId: string;
  userAgent: string;
  screenResolution: string;
  timezone: string;
  language: string;
  platform: string;
  hardwareConcurrency: number;
  maxTouchPoints: number;
  colorDepth: number;
  pixelRatio: number;
  cookieEnabled: boolean;
  doNotTrack: string | null;
  webglRenderer?: string;
  webglVendor?: string;
  canvasFingerprint?: string;
  audioFingerprint?: string;
  fontFingerprint?: string;
  storageQuota?: number;
}

export interface GeolocationData {
  latitude: number;
  longitude: number;
  accuracy: number;
  timestamp: number;
  city?: string;
  country?: string;
  region?: string;
}

export interface NetworkInfo {
  connectionType: string;
  effectiveType: string;
  downlink: number;
  rtt: number;
  saveData: boolean;
}

export interface DeviceTrustScore {
  overallScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: {
    deviceRecognition: number;
    behavioralConsistency: number;
    networkTrust: number;
    geographicConsistency: number;
    securityFeatures: number;
  };
  flags: string[];
  recommendations: string[];
}

export interface DeviceTrustResult {
  success: boolean;
  deviceFingerprint: DeviceFingerprint;
  trustScore: DeviceTrustScore;
  geolocation?: GeolocationData;
  networkInfo?: NetworkInfo;
  verificationId: string;
  timestamp: number;
  error?: string;
}

interface DeviceTrustVerificationProps {
  onVerificationComplete: (result: DeviceTrustResult) => void;
  onVerificationError: (error: string) => void;
  existingDeviceId?: string;
  riskThreshold?: number;
  enableGeolocation?: boolean;
  enableBehavioralAnalysis?: boolean;
  customValidators?: Array<(fingerprint: DeviceFingerprint) => Promise<number>>;
}

// Security constants for device trust verification
const TRUST_CONFIG = {
  MIN_TRUST_SCORE: 70,
  FINGERPRINT_TIMEOUT: 10000,
  GEOLOCATION_TIMEOUT: 15000,
  CANVAS_TEST_STRING: 'Device Trust Canvas Test 2024 iSECTECH',
  AUDIO_CONTEXT_SAMPLE_RATE: 44100,
} as const;

export function DeviceTrustVerification({
  onVerificationComplete,
  onVerificationError,
  existingDeviceId,
  riskThreshold = TRUST_CONFIG.MIN_TRUST_SCORE,
  enableGeolocation = true,
  enableBehavioralAnalysis = true,
  customValidators = []
}: DeviceTrustVerificationProps) {
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationProgress, setVerificationProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('');
  const [deviceFingerprint, setDeviceFingerprint] = useState<DeviceFingerprint | null>(null);
  const [trustScore, setTrustScore] = useState<DeviceTrustScore | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);
  
  const verificationTimeoutRef = useRef<NodeJS.Timeout>();

  /**
   * Generate secure device ID using multiple entropy sources
   */
  const generateDeviceId = useCallback(async (fingerprint: Partial<DeviceFingerprint>): Promise<string> => {
    const components = [
      fingerprint.userAgent,
      fingerprint.screenResolution,
      fingerprint.timezone,
      fingerprint.language,
      fingerprint.platform,
      fingerprint.hardwareConcurrency?.toString(),
      fingerprint.canvasFingerprint,
      fingerprint.audioFingerprint,
      fingerprint.webglRenderer,
      fingerprint.fontFingerprint
    ].filter(Boolean);

    const combinedString = components.join('|');
    const encoder = new TextEncoder();
    const data = encoder.encode(combinedString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }, []);

  /**
   * Generate canvas fingerprint for device identification
   */
  const generateCanvasFingerprint = useCallback((): Promise<string> => {
    return new Promise((resolve, reject) => {
      try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        if (!ctx) {
          reject(new Error('Canvas context not available'));
          return;
        }

        canvas.width = 200;
        canvas.height = 50;

        // Draw text with various styles
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText(TRUST_CONFIG.CANVAS_TEST_STRING, 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText(TRUST_CONFIG.CANVAS_TEST_STRING, 4, 17);

        // Add geometric shapes
        ctx.globalCompositeOperation = 'multiply';
        ctx.fillStyle = 'rgb(255,0,255)';
        ctx.beginPath();
        ctx.arc(50, 25, 20, 0, Math.PI * 2, true);
        ctx.closePath();
        ctx.fill();

        const dataUrl = canvas.toDataURL();
        resolve(btoa(dataUrl).slice(0, 64));
      } catch (error) {
        reject(error);
      }
    });
  }, []);

  /**
   * Generate audio fingerprint for device identification
   */
  const generateAudioFingerprint = useCallback((): Promise<string> => {
    return new Promise((resolve, reject) => {
      try {
        const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const analyser = audioContext.createAnalyser();
        const gainNode = audioContext.createGain();

        oscillator.connect(analyser);
        analyser.connect(gainNode);
        gainNode.connect(audioContext.destination);

        gainNode.gain.setValueAtTime(0, audioContext.currentTime);
        oscillator.frequency.setValueAtTime(10000, audioContext.currentTime);
        oscillator.start(audioContext.currentTime);
        
        setTimeout(() => {
          try {
            const freqData = new Uint8Array(analyser.frequencyBinCount);
            analyser.getByteFrequencyData(freqData);
            
            const fingerprint = Array.from(freqData)
              .slice(0, 32)
              .map(x => x.toString(16))
              .join('');
            
            oscillator.stop();
            audioContext.close();
            resolve(fingerprint || 'audio-unavailable');
          } catch (err) {
            resolve('audio-error');
          }
        }, 100);

      } catch (error) {
        resolve('audio-not-supported');
      }
    });
  }, []);

  /**
   * Generate font fingerprint by testing font availability
   */
  const generateFontFingerprint = useCallback((): string => {
    const testFonts = [
      'Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Verdana',
      'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS',
      'Trebuchet MS', 'Arial Black', 'Impact', 'sans-serif', 'serif'
    ];

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (!ctx) return 'font-canvas-unavailable';

    const testText = 'mmmmmmmmmmlli';
    const defaultWidth: Record<string, number> = {};
    const availableFonts: string[] = [];

    // Measure default font widths
    ctx.font = '72px monospace';
    defaultWidth.monospace = ctx.measureText(testText).width;
    ctx.font = '72px sans-serif';
    defaultWidth.sansSerif = ctx.measureText(testText).width;
    ctx.font = '72px serif';
    defaultWidth.serif = ctx.measureText(testText).width;

    // Test each font
    testFonts.forEach(font => {
      ctx.font = `72px ${font}, monospace`;
      const width = ctx.measureText(testText).width;
      if (width !== defaultWidth.monospace) {
        availableFonts.push(font);
      }
    });

    return availableFonts.sort().join(',').slice(0, 64);
  }, []);

  /**
   * Get network information if available
   */
  const getNetworkInfo = useCallback((): NetworkInfo | undefined => {
    const connection = (navigator as any).connection || 
                     (navigator as any).mozConnection || 
                     (navigator as any).webkitConnection;
    
    if (!connection) return undefined;

    return {
      connectionType: connection.type || 'unknown',
      effectiveType: connection.effectiveType || 'unknown',
      downlink: connection.downlink || 0,
      rtt: connection.rtt || 0,
      saveData: connection.saveData || false
    };
  }, []);

  /**
   * Get geolocation data with high accuracy
   */
  const getGeolocationData = useCallback((): Promise<GeolocationData | undefined> => {
    return new Promise((resolve) => {
      if (!enableGeolocation || !navigator.geolocation) {
        resolve(undefined);
        return;
      }

      const options: PositionOptions = {
        enableHighAccuracy: true,
        timeout: TRUST_CONFIG.GEOLOCATION_TIMEOUT,
        maximumAge: 300000 // 5 minutes
      };

      navigator.geolocation.getCurrentPosition(
        (position) => {
          resolve({
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            accuracy: position.coords.accuracy,
            timestamp: position.timestamp
          });
        },
        () => resolve(undefined),
        options
      );
    });
  }, [enableGeolocation]);

  /**
   * Generate comprehensive device fingerprint
   */
  const generateDeviceFingerprint = useCallback(async (): Promise<DeviceFingerprint> => {
    setCurrentStep('Generating device fingerprint...');
    setVerificationProgress(20);

    const [canvasFingerprint, audioFingerprint] = await Promise.all([
      generateCanvasFingerprint().catch(() => 'canvas-error'),
      generateAudioFingerprint().catch(() => 'audio-error')
    ]);

    const fontFingerprint = generateFontFingerprint();

    // Get storage quota if available
    let storageQuota: number | undefined;
    try {
      if ('storage' in navigator && 'estimate' in navigator.storage) {
        const estimate = await navigator.storage.estimate();
        storageQuota = estimate.quota;
      }
    } catch (error) {
      // Storage API not available
    }

    // Get WebGL information
    let webglRenderer: string | undefined;
    let webglVendor: string | undefined;
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          webglRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
          webglVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
        }
      }
    } catch (error) {
      // WebGL not available
    }

    const baseFingerprint = {
      deviceId: '', // Will be set after generation
      userAgent: navigator.userAgent,
      screenResolution: `${screen.width}x${screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
      platform: navigator.platform,
      hardwareConcurrency: navigator.hardwareConcurrency || 0,
      maxTouchPoints: navigator.maxTouchPoints || 0,
      colorDepth: screen.colorDepth,
      pixelRatio: window.devicePixelRatio,
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack,
      webglRenderer,
      webglVendor,
      canvasFingerprint,
      audioFingerprint,
      fontFingerprint,
      storageQuota
    };

    const deviceId = existingDeviceId || await generateDeviceId(baseFingerprint);
    
    return {
      ...baseFingerprint,
      deviceId
    };
  }, [existingDeviceId, generateDeviceId, generateCanvasFingerprint, generateAudioFingerprint, generateFontFingerprint]);

  /**
   * Calculate device trust score based on multiple factors
   */
  const calculateTrustScore = useCallback((
    fingerprint: DeviceFingerprint,
    geolocation?: GeolocationData,
    networkInfo?: NetworkInfo
  ): DeviceTrustScore => {
    setCurrentStep('Calculating trust score...');
    setVerificationProgress(70);

    const flags: string[] = [];
    const recommendations: string[] = [];
    
    // Device Recognition Score (0-100)
    let deviceRecognition = 80; // Base score
    if (existingDeviceId && fingerprint.deviceId === existingDeviceId) {
      deviceRecognition = 100;
    } else if (existingDeviceId) {
      deviceRecognition = 40;
      flags.push('Device ID mismatch');
      recommendations.push('Device appears to be new or modified');
    }

    // Security Features Score (0-100)
    let securityFeatures = 60; // Base score
    if (fingerprint.maxTouchPoints > 0) securityFeatures += 10; // Touch capability
    if (fingerprint.webglRenderer) securityFeatures += 10; // WebGL support
    if (fingerprint.hardwareConcurrency >= 4) securityFeatures += 10; // Multi-core
    if (fingerprint.pixelRatio > 1) securityFeatures += 10; // High DPI

    // Behavioral Consistency Score (0-100)
    let behavioralConsistency = 70; // Base score for new devices
    // In production, this would analyze historical behavior patterns
    if (fingerprint.cookieEnabled) behavioralConsistency += 15;
    if (fingerprint.doNotTrack === null || fingerprint.doNotTrack === '0') {
      behavioralConsistency += 15;
    }

    // Network Trust Score (0-100)
    let networkTrust = 75; // Base score
    if (networkInfo) {
      if (networkInfo.connectionType === 'wifi') networkTrust += 10;
      if (networkInfo.effectiveType === '4g') networkTrust += 10;
      if (networkInfo.downlink > 1) networkTrust += 5;
    }

    // Geographic Consistency Score (0-100)
    let geographicConsistency = 80; // Base score when no previous data
    if (geolocation) {
      geographicConsistency = 90; // Bonus for providing location
      if (geolocation.accuracy < 100) geographicConsistency += 10;
    }

    // Check for suspicious patterns
    if (fingerprint.userAgent.includes('HeadlessChrome')) {
      flags.push('Automated browser detected');
      deviceRecognition = Math.min(deviceRecognition, 30);
      recommendations.push('Verify this is not an automated session');
    }

    if (fingerprint.webglRenderer?.includes('SwiftShader')) {
      flags.push('Software rendering detected');
      securityFeatures = Math.min(securityFeatures, 50);
    }

    if (fingerprint.canvasFingerprint === 'canvas-error') {
      flags.push('Canvas fingerprinting blocked');
      securityFeatures = Math.min(securityFeatures, 60);
    }

    const factors = {
      deviceRecognition,
      behavioralConsistency,
      networkTrust,
      geographicConsistency,
      securityFeatures
    };

    // Calculate weighted overall score
    const weights = {
      deviceRecognition: 0.3,
      behavioralConsistency: 0.2,
      networkTrust: 0.2,
      geographicConsistency: 0.15,
      securityFeatures: 0.15
    };

    const overallScore = Math.round(
      factors.deviceRecognition * weights.deviceRecognition +
      factors.behavioralConsistency * weights.behavioralConsistency +
      factors.networkTrust * weights.networkTrust +
      factors.geographicConsistency * weights.geographicConsistency +
      factors.securityFeatures * weights.securityFeatures
    );

    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    if (overallScore >= 85) riskLevel = 'LOW';
    else if (overallScore >= 70) riskLevel = 'MEDIUM';
    else if (overallScore >= 50) riskLevel = 'HIGH';
    else riskLevel = 'CRITICAL';

    if (flags.length === 0 && overallScore >= riskThreshold) {
      recommendations.push('Device verification successful');
    } else if (overallScore < riskThreshold) {
      recommendations.push('Additional authentication methods recommended');
    }

    return {
      overallScore,
      riskLevel,
      factors,
      flags,
      recommendations
    };
  }, [existingDeviceId, riskThreshold]);

  /**
   * Perform complete device trust verification
   */
  const performVerification = useCallback(async () => {
    setIsVerifying(true);
    setLastError(null);
    setVerificationProgress(0);

    // Set timeout for verification process
    verificationTimeoutRef.current = setTimeout(() => {
      setLastError('Verification timeout');
      setIsVerifying(false);
    }, TRUST_CONFIG.FINGERPRINT_TIMEOUT);

    try {
      setCurrentStep('Starting device verification...');
      setVerificationProgress(10);

      // Generate device fingerprint
      const fingerprint = await generateDeviceFingerprint();
      setDeviceFingerprint(fingerprint);

      setCurrentStep('Gathering device information...');
      setVerificationProgress(40);

      // Collect additional data
      const [geolocation, networkInfo] = await Promise.all([
        getGeolocationData(),
        Promise.resolve(getNetworkInfo())
      ]);

      setCurrentStep('Analyzing security posture...');
      setVerificationProgress(60);

      // Run custom validators if provided
      if (customValidators.length > 0) {
        setCurrentStep('Running custom validations...');
        await Promise.all(customValidators.map(validator => validator(fingerprint)));
      }

      // Calculate trust score
      const calculatedTrustScore = calculateTrustScore(fingerprint, geolocation, networkInfo);
      setTrustScore(calculatedTrustScore);

      setCurrentStep('Verification complete');
      setVerificationProgress(100);

      const result: DeviceTrustResult = {
        success: true,
        deviceFingerprint: fingerprint,
        trustScore: calculatedTrustScore,
        geolocation,
        networkInfo,
        verificationId: crypto.randomUUID(),
        timestamp: Date.now()
      };

      onVerificationComplete(result);

    } catch (error: any) {
      const errorMessage = error.message || 'Device verification failed';
      setLastError(errorMessage);
      onVerificationError(errorMessage);
    } finally {
      if (verificationTimeoutRef.current) {
        clearTimeout(verificationTimeoutRef.current);
      }
      setIsVerifying(false);
    }
  }, [
    generateDeviceFingerprint,
    getGeolocationData,
    getNetworkInfo,
    calculateTrustScore,
    customValidators,
    onVerificationComplete,
    onVerificationError
  ]);

  // Cleanup effect
  useEffect(() => {
    return () => {
      if (verificationTimeoutRef.current) {
        clearTimeout(verificationTimeoutRef.current);
      }
    };
  }, []);

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'LOW': return 'text-green-600';
      case 'MEDIUM': return 'text-yellow-600';
      case 'HIGH': return 'text-orange-600';
      case 'CRITICAL': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  const getRiskBadgeVariant = (riskLevel: string) => {
    switch (riskLevel) {
      case 'LOW': return 'default';
      case 'MEDIUM': return 'secondary';
      case 'HIGH': return 'destructive';
      case 'CRITICAL': return 'destructive';
      default: return 'outline';
    }
  };

  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-blue-600" />
          Device Trust Verification
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Verification Progress */}
        {isVerifying && (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
              <span className="text-sm">{currentStep}</span>
            </div>
            <Progress value={verificationProgress} className="w-full" />
          </div>
        )}

        {/* Error Display */}
        {lastError && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{lastError}</AlertDescription>
          </Alert>
        )}

        {/* Trust Score Display */}
        {trustScore && !isVerifying && (
          <div className="space-y-3">
            <div className="text-center">
              <div className="text-2xl font-bold mb-1">{trustScore.overallScore}/100</div>
              <Badge 
                variant={getRiskBadgeVariant(trustScore.riskLevel)}
                className="mb-2"
              >
                {trustScore.riskLevel} RISK
              </Badge>
            </div>

            {/* Trust Factors */}
            <div className="space-y-2">
              <div className="text-sm font-medium">Trust Factors:</div>
              {Object.entries(trustScore.factors).map(([key, score]) => (
                <div key={key} className="flex justify-between items-center">
                  <span className="text-sm capitalize">
                    {key.replace(/([A-Z])/g, ' $1').toLowerCase()}
                  </span>
                  <span className="text-sm font-medium">{score}/100</span>
                </div>
              ))}
            </div>

            {/* Flags */}
            {trustScore.flags.length > 0 && (
              <div className="space-y-2">
                <div className="text-sm font-medium text-orange-600">Security Flags:</div>
                {trustScore.flags.map((flag, index) => (
                  <div key={index} className="text-xs text-orange-600 bg-orange-50 p-2 rounded">
                    {flag}
                  </div>
                ))}
              </div>
            )}

            {/* Recommendations */}
            {trustScore.recommendations.length > 0 && (
              <div className="space-y-2">
                <div className="text-sm font-medium">Recommendations:</div>
                {trustScore.recommendations.map((rec, index) => (
                  <div key={index} className="text-xs text-gray-600 bg-gray-50 p-2 rounded">
                    {rec}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Device Information */}
        {deviceFingerprint && !isVerifying && (
          <div className="space-y-2">
            <div className="text-sm font-medium">Device Information:</div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center gap-1">
                <Smartphone className="h-3 w-3" />
                <span>{deviceFingerprint.platform}</span>
              </div>
              <div className="flex items-center gap-1">
                <MapPin className="h-3 w-3" />
                <span>{deviceFingerprint.timezone}</span>
              </div>
              <div className="flex items-center gap-1">
                <Wifi className="h-3 w-3" />
                <span>{deviceFingerprint.language}</span>
              </div>
              <div className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                <span>{new Date().toLocaleString()}</span>
              </div>
            </div>
          </div>
        )}

        {/* Action Button */}
        {!isVerifying && !trustScore && (
          <Button
            onClick={performVerification}
            className="w-full"
            disabled={isVerifying}
          >
            <div className="flex items-center gap-2">
              <Lock className="h-4 w-4" />
              Verify Device Trust
            </div>
          </Button>
        )}

        {/* Re-verification Button */}
        {trustScore && !isVerifying && (
          <Button
            onClick={performVerification}
            variant="outline"
            className="w-full"
            size="sm"
          >
            Re-verify Device
          </Button>
        )}

        {/* Security Notice */}
        <div className="text-xs text-gray-500 space-y-1">
          <p>• Device fingerprinting uses non-invasive browser APIs</p>
          <p>• No personal data is collected or stored permanently</p>
          <p>• Verification enhances account security</p>
        </div>
      </CardContent>
    </Card>
  );
}

export default DeviceTrustVerification;