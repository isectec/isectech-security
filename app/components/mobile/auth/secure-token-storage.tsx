'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Shield, 
  Key, 
  AlertTriangle, 
  Check, 
  Lock,
  Unlock,
  Clock,
  Database,
  Eye,
  EyeOff
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';

/**
 * Secure Token Storage Component
 * Production-grade implementation using Web Crypto API, IndexedDB with encryption
 * Supports multiple storage backends with automatic fallback
 */

export interface SecureToken {
  id: string;
  type: 'access' | 'refresh' | 'id' | 'custom';
  value: string;
  expiresAt: number;
  metadata?: {
    issuer?: string;
    audience?: string;
    scope?: string[];
    deviceId?: string;
    [key: string]: any;
  };
  created: number;
  lastAccessed: number;
}

export interface StorageConfig {
  databaseName: string;
  storeName: string;
  encryptionKeyId: string;
  compressionEnabled?: boolean;
  autoCleanupEnabled?: boolean;
  cleanupIntervalMs?: number;
  maxTokenAge?: number;
}

export interface StorageStats {
  totalTokens: number;
  expiredTokens: number;
  storageSize: number;
  lastCleanup: number;
  encryptionStatus: 'enabled' | 'disabled' | 'error';
  storageBackend: 'indexeddb' | 'localstorage' | 'memory';
}

export interface TokenOperationResult {
  success: boolean;
  tokenId?: string;
  error?: string;
  duration?: number;
}

interface SecureTokenStorageProps {
  config: StorageConfig;
  onStorageReady?: (stats: StorageStats) => void;
  onTokenExpired?: (tokenId: string) => void;
  onStorageError?: (error: string) => void;
  enableDebugMode?: boolean;
  autoInitialize?: boolean;
}

// Security constants for token storage
const STORAGE_CONFIG = {
  ENCRYPTION_ALGORITHM: 'AES-GCM',
  KEY_LENGTH: 256,
  IV_LENGTH: 12,
  TAG_LENGTH: 16,
  COMPRESSION_THRESHOLD: 1024,
  MAX_STORAGE_SIZE: 50 * 1024 * 1024, // 50MB
  DEFAULT_CLEANUP_INTERVAL: 3600000, // 1 hour
  DEFAULT_MAX_TOKEN_AGE: 2592000000, // 30 days
} as const;

export function SecureTokenStorage({
  config,
  onStorageReady,
  onTokenExpired,
  onStorageError,
  enableDebugMode = false,
  autoInitialize = true
}: SecureTokenStorageProps) {
  const [isInitialized, setIsInitialized] = useState(false);
  const [isInitializing, setIsInitializing] = useState(false);
  const [storageStats, setStorageStats] = useState<StorageStats | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);
  const [operationProgress, setOperationProgress] = useState(0);
  const [currentOperation, setCurrentOperation] = useState('');
  const [debugInfo, setDebugInfo] = useState<any[]>([]);
  const [showDebugInfo, setShowDebugInfo] = useState(false);

  const dbRef = useRef<IDBDatabase | null>(null);
  const encryptionKeyRef = useRef<CryptoKey | null>(null);
  const cleanupIntervalRef = useRef<NodeJS.Timeout>();
  const fallbackStorageRef = useRef<Map<string, SecureToken>>(new Map());

  /**
   * Add debug information
   */
  const addDebugInfo = useCallback((info: any) => {
    if (!enableDebugMode) return;
    
    setDebugInfo(prev => [
      {
        timestamp: new Date().toISOString(),
        ...info
      },
      ...prev.slice(0, 99) // Keep last 100 entries
    ]);
  }, [enableDebugMode]);

  /**
   * Generate or derive encryption key
   */
  const generateEncryptionKey = useCallback(async (): Promise<CryptoKey> => {
    try {
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(config.encryptionKeyId + 'isectech-secure-storage'),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      );

      const salt = new TextEncoder().encode('isectech-salt-2024');
      
      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        keyMaterial,
        {
          name: STORAGE_CONFIG.ENCRYPTION_ALGORITHM,
          length: STORAGE_CONFIG.KEY_LENGTH
        },
        false,
        ['encrypt', 'decrypt']
      );

      addDebugInfo({ action: 'key_generation', status: 'success' });
      return key;
    } catch (error: any) {
      addDebugInfo({ action: 'key_generation', status: 'error', error: error.message });
      throw new Error(`Encryption key generation failed: ${error.message}`);
    }
  }, [config.encryptionKeyId, addDebugInfo]);

  /**
   * Initialize IndexedDB database
   */
  const initializeDatabase = useCallback((): Promise<IDBDatabase> => {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(config.databaseName, 1);

      request.onerror = () => {
        addDebugInfo({ action: 'db_init', status: 'error', error: request.error?.message });
        reject(new Error(`Database initialization failed: ${request.error?.message}`));
      };

      request.onsuccess = () => {
        addDebugInfo({ action: 'db_init', status: 'success' });
        resolve(request.result);
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        
        if (!db.objectStoreNames.contains(config.storeName)) {
          const store = db.createObjectStore(config.storeName, { keyPath: 'id' });
          store.createIndex('type', 'type', { unique: false });
          store.createIndex('expiresAt', 'expiresAt', { unique: false });
          store.createIndex('created', 'created', { unique: false });
        }
        
        addDebugInfo({ action: 'db_upgrade', status: 'success' });
      };
    });
  }, [config.databaseName, config.storeName, addDebugInfo]);

  /**
   * Encrypt token data
   */
  const encryptData = useCallback(async (data: string): Promise<{ encrypted: ArrayBuffer; iv: Uint8Array }> => {
    if (!encryptionKeyRef.current) {
      throw new Error('Encryption key not available');
    }

    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const iv = crypto.getRandomValues(new Uint8Array(STORAGE_CONFIG.IV_LENGTH));

    try {
      const encrypted = await crypto.subtle.encrypt(
        {
          name: STORAGE_CONFIG.ENCRYPTION_ALGORITHM,
          iv: iv
        },
        encryptionKeyRef.current,
        dataBuffer
      );

      addDebugInfo({ action: 'encrypt', status: 'success', dataSize: data.length });
      return { encrypted, iv };
    } catch (error: any) {
      addDebugInfo({ action: 'encrypt', status: 'error', error: error.message });
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }, [addDebugInfo]);

  /**
   * Decrypt token data
   */
  const decryptData = useCallback(async (encrypted: ArrayBuffer, iv: Uint8Array): Promise<string> => {
    if (!encryptionKeyRef.current) {
      throw new Error('Encryption key not available');
    }

    try {
      const decrypted = await crypto.subtle.decrypt(
        {
          name: STORAGE_CONFIG.ENCRYPTION_ALGORITHM,
          iv: iv
        },
        encryptionKeyRef.current,
        encrypted
      );

      const decoder = new TextDecoder();
      const result = decoder.decode(decrypted);
      
      addDebugInfo({ action: 'decrypt', status: 'success', dataSize: result.length });
      return result;
    } catch (error: any) {
      addDebugInfo({ action: 'decrypt', status: 'error', error: error.message });
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }, [addDebugInfo]);

  /**
   * Store token securely
   */
  const storeToken = useCallback(async (token: SecureToken): Promise<TokenOperationResult> => {
    const startTime = Date.now();
    setCurrentOperation(`Storing token ${token.id}`);

    try {
      if (!isInitialized) {
        throw new Error('Storage not initialized');
      }

      // Prepare token data for storage
      const tokenData = {
        ...token,
        lastAccessed: Date.now()
      };

      const serialized = JSON.stringify(tokenData);
      const { encrypted, iv } = await encryptData(serialized);

      // Convert ArrayBuffer to Base64 for storage
      const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
      const ivBase64 = btoa(String.fromCharCode(...iv));

      const storageRecord = {
        id: token.id,
        encrypted: encryptedBase64,
        iv: ivBase64,
        created: token.created,
        expiresAt: token.expiresAt,
        type: token.type
      };

      if (dbRef.current) {
        // Store in IndexedDB
        const transaction = dbRef.current.transaction([config.storeName], 'readwrite');
        const store = transaction.objectStore(config.storeName);
        await new Promise<void>((resolve, reject) => {
          const request = store.put(storageRecord);
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error);
        });
      } else {
        // Fallback to memory storage
        fallbackStorageRef.current.set(token.id, tokenData);
      }

      const duration = Date.now() - startTime;
      addDebugInfo({ 
        action: 'store_token', 
        status: 'success', 
        tokenId: token.id, 
        duration 
      });

      await updateStorageStats();

      return {
        success: true,
        tokenId: token.id,
        duration
      };

    } catch (error: any) {
      const duration = Date.now() - startTime;
      addDebugInfo({ 
        action: 'store_token', 
        status: 'error', 
        tokenId: token.id, 
        error: error.message,
        duration 
      });

      return {
        success: false,
        error: error.message,
        duration
      };
    } finally {
      setCurrentOperation('');
    }
  }, [isInitialized, config.storeName, encryptData, addDebugInfo]);

  /**
   * Retrieve token securely
   */
  const retrieveToken = useCallback(async (tokenId: string): Promise<SecureToken | null> => {
    const startTime = Date.now();
    setCurrentOperation(`Retrieving token ${tokenId}`);

    try {
      if (!isInitialized) {
        throw new Error('Storage not initialized');
      }

      let storageRecord: any = null;

      if (dbRef.current) {
        // Retrieve from IndexedDB
        const transaction = dbRef.current.transaction([config.storeName], 'readonly');
        const store = transaction.objectStore(config.storeName);
        storageRecord = await new Promise<any>((resolve, reject) => {
          const request = store.get(tokenId);
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });
      } else {
        // Retrieve from fallback storage
        const token = fallbackStorageRef.current.get(tokenId);
        if (token) {
          const duration = Date.now() - startTime;
          addDebugInfo({ 
            action: 'retrieve_token', 
            status: 'success', 
            tokenId, 
            duration,
            backend: 'memory'
          });
          return token;
        }
      }

      if (!storageRecord) {
        addDebugInfo({ action: 'retrieve_token', status: 'not_found', tokenId });
        return null;
      }

      // Check if token is expired
      if (storageRecord.expiresAt <= Date.now()) {
        addDebugInfo({ action: 'retrieve_token', status: 'expired', tokenId });
        onTokenExpired?.(tokenId);
        return null;
      }

      // Decrypt token data
      const encryptedData = Uint8Array.from(atob(storageRecord.encrypted), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(storageRecord.iv), c => c.charCodeAt(0));
      
      const decryptedJson = await decryptData(encryptedData.buffer, iv);
      const token: SecureToken = JSON.parse(decryptedJson);

      // Update last accessed time
      token.lastAccessed = Date.now();
      await storeToken(token);

      const duration = Date.now() - startTime;
      addDebugInfo({ 
        action: 'retrieve_token', 
        status: 'success', 
        tokenId, 
        duration,
        backend: 'indexeddb'
      });

      return token;

    } catch (error: any) {
      const duration = Date.now() - startTime;
      addDebugInfo({ 
        action: 'retrieve_token', 
        status: 'error', 
        tokenId, 
        error: error.message,
        duration 
      });
      return null;
    } finally {
      setCurrentOperation('');
    }
  }, [isInitialized, config.storeName, decryptData, storeToken, addDebugInfo, onTokenExpired]);

  /**
   * Remove token from storage
   */
  const removeToken = useCallback(async (tokenId: string): Promise<TokenOperationResult> => {
    const startTime = Date.now();
    setCurrentOperation(`Removing token ${tokenId}`);

    try {
      if (!isInitialized) {
        throw new Error('Storage not initialized');
      }

      if (dbRef.current) {
        const transaction = dbRef.current.transaction([config.storeName], 'readwrite');
        const store = transaction.objectStore(config.storeName);
        await new Promise<void>((resolve, reject) => {
          const request = store.delete(tokenId);
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error);
        });
      } else {
        fallbackStorageRef.current.delete(tokenId);
      }

      const duration = Date.now() - startTime;
      addDebugInfo({ 
        action: 'remove_token', 
        status: 'success', 
        tokenId, 
        duration 
      });

      await updateStorageStats();

      return {
        success: true,
        tokenId,
        duration
      };

    } catch (error: any) {
      const duration = Date.now() - startTime;
      addDebugInfo({ 
        action: 'remove_token', 
        status: 'error', 
        tokenId, 
        error: error.message,
        duration 
      });

      return {
        success: false,
        error: error.message,
        duration
      };
    } finally {
      setCurrentOperation('');
    }
  }, [isInitialized, config.storeName, addDebugInfo]);

  /**
   * Update storage statistics
   */
  const updateStorageStats = useCallback(async () => {
    try {
      let totalTokens = 0;
      let expiredTokens = 0;
      const now = Date.now();

      if (dbRef.current) {
        const transaction = dbRef.current.transaction([config.storeName], 'readonly');
        const store = transaction.objectStore(config.storeName);
        
        const allTokens = await new Promise<any[]>((resolve, reject) => {
          const request = store.getAll();
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });

        totalTokens = allTokens.length;
        expiredTokens = allTokens.filter(token => token.expiresAt <= now).length;
      } else {
        totalTokens = fallbackStorageRef.current.size;
        expiredTokens = Array.from(fallbackStorageRef.current.values())
          .filter(token => token.expiresAt <= now).length;
      }

      const stats: StorageStats = {
        totalTokens,
        expiredTokens,
        storageSize: 0, // Would need to calculate actual storage size
        lastCleanup: Date.now(),
        encryptionStatus: encryptionKeyRef.current ? 'enabled' : 'disabled',
        storageBackend: dbRef.current ? 'indexeddb' : 'memory'
      };

      setStorageStats(stats);
      onStorageReady?.(stats);

    } catch (error: any) {
      console.error('Failed to update storage stats:', error);
    }
  }, [config.storeName, onStorageReady]);

  /**
   * Clean up expired tokens
   */
  const cleanupExpiredTokens = useCallback(async () => {
    setCurrentOperation('Cleaning up expired tokens');
    
    try {
      const now = Date.now();
      let cleanedCount = 0;

      if (dbRef.current) {
        const transaction = dbRef.current.transaction([config.storeName], 'readwrite');
        const store = transaction.objectStore(config.storeName);
        const index = store.index('expiresAt');
        
        const expiredTokens = await new Promise<any[]>((resolve, reject) => {
          const request = index.getAll(IDBKeyRange.upperBound(now));
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });

        for (const token of expiredTokens) {
          await new Promise<void>((resolve, reject) => {
            const deleteRequest = store.delete(token.id);
            deleteRequest.onsuccess = () => resolve();
            deleteRequest.onerror = () => reject(deleteRequest.error);
          });
          cleanedCount++;
        }
      } else {
        for (const [tokenId, token] of fallbackStorageRef.current.entries()) {
          if (token.expiresAt <= now) {
            fallbackStorageRef.current.delete(tokenId);
            cleanedCount++;
          }
        }
      }

      addDebugInfo({ 
        action: 'cleanup', 
        status: 'success', 
        cleanedCount 
      });

      await updateStorageStats();

    } catch (error: any) {
      addDebugInfo({ 
        action: 'cleanup', 
        status: 'error', 
        error: error.message 
      });
    } finally {
      setCurrentOperation('');
    }
  }, [config.storeName, addDebugInfo, updateStorageStats]);

  /**
   * Initialize secure storage
   */
  const initializeStorage = useCallback(async () => {
    setIsInitializing(true);
    setLastError(null);
    setOperationProgress(0);

    try {
      setCurrentOperation('Generating encryption key...');
      setOperationProgress(20);
      
      const encryptionKey = await generateEncryptionKey();
      encryptionKeyRef.current = encryptionKey;

      setCurrentOperation('Initializing database...');
      setOperationProgress(50);

      try {
        const database = await initializeDatabase();
        dbRef.current = database;
      } catch (dbError) {
        console.warn('IndexedDB not available, using memory storage:', dbError);
        // Continue with memory storage as fallback
      }

      setCurrentOperation('Setting up cleanup...');
      setOperationProgress(80);

      // Setup automatic cleanup
      if (config.autoCleanupEnabled !== false) {
        const interval = config.cleanupIntervalMs || STORAGE_CONFIG.DEFAULT_CLEANUP_INTERVAL;
        cleanupIntervalRef.current = setInterval(cleanupExpiredTokens, interval);
      }

      setCurrentOperation('Storage ready');
      setOperationProgress(100);

      setIsInitialized(true);
      await updateStorageStats();

      addDebugInfo({ 
        action: 'initialize', 
        status: 'success', 
        backend: dbRef.current ? 'indexeddb' : 'memory'
      });

    } catch (error: any) {
      const errorMessage = `Storage initialization failed: ${error.message}`;
      setLastError(errorMessage);
      onStorageError?.(errorMessage);
      
      addDebugInfo({ 
        action: 'initialize', 
        status: 'error', 
        error: error.message 
      });
    } finally {
      setIsInitializing(false);
      setCurrentOperation('');
      setOperationProgress(0);
    }
  }, [
    generateEncryptionKey,
    initializeDatabase,
    config.autoCleanupEnabled,
    config.cleanupIntervalMs,
    cleanupExpiredTokens,
    updateStorageStats,
    onStorageError,
    addDebugInfo
  ]);

  // Auto-initialize on mount
  useEffect(() => {
    if (autoInitialize && !isInitialized && !isInitializing) {
      initializeStorage();
    }
  }, [autoInitialize, isInitialized, isInitializing, initializeStorage]);

  // Cleanup effect
  useEffect(() => {
    return () => {
      if (cleanupIntervalRef.current) {
        clearInterval(cleanupIntervalRef.current);
      }
      if (dbRef.current) {
        dbRef.current.close();
      }
    };
  }, []);

  // Expose methods for external use
  const storageAPI = {
    store: storeToken,
    retrieve: retrieveToken,
    remove: removeToken,
    cleanup: cleanupExpiredTokens,
    initialize: initializeStorage,
    isReady: isInitialized
  };

  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Database className="h-5 w-5 text-blue-600" />
          Secure Token Storage
          {storageStats && (
            <Badge variant={storageStats.encryptionStatus === 'enabled' ? 'default' : 'destructive'}>
              {storageStats.encryptionStatus}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Initialization Progress */}
        {isInitializing && (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
              <span className="text-sm">{currentOperation}</span>
            </div>
            <Progress value={operationProgress} className="w-full" />
          </div>
        )}

        {/* Current Operation */}
        {currentOperation && !isInitializing && (
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-gray-400"></div>
            {currentOperation}
          </div>
        )}

        {/* Error Display */}
        {lastError && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{lastError}</AlertDescription>
          </Alert>
        )}

        {/* Storage Statistics */}
        {storageStats && isInitialized && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold">{storageStats.totalTokens}</div>
                <div className="text-sm text-gray-500">Total Tokens</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-600">{storageStats.expiredTokens}</div>
                <div className="text-sm text-gray-500">Expired</div>
              </div>
            </div>

            <div className="flex items-center justify-between text-sm">
              <span>Storage Backend:</span>
              <Badge variant="outline">{storageStats.storageBackend}</Badge>
            </div>

            <div className="flex items-center justify-between text-sm">
              <span>Encryption:</span>
              <div className="flex items-center gap-1">
                {storageStats.encryptionStatus === 'enabled' ? (
                  <Lock className="h-3 w-3 text-green-600" />
                ) : (
                  <Unlock className="h-3 w-3 text-red-600" />
                )}
                <span className={
                  storageStats.encryptionStatus === 'enabled' 
                    ? 'text-green-600' 
                    : 'text-red-600'
                }>
                  {storageStats.encryptionStatus}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Control Buttons */}
        {isInitialized && (
          <div className="flex gap-2">
            <Button
              onClick={cleanupExpiredTokens}
              variant="outline"
              size="sm"
              className="flex-1"
            >
              <Clock className="h-4 w-4 mr-2" />
              Cleanup
            </Button>
            <Button
              onClick={initializeStorage}
              variant="outline"
              size="sm"
              className="flex-1"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Reinitialize
            </Button>
          </div>
        )}

        {!isInitialized && !isInitializing && (
          <Button onClick={initializeStorage} className="w-full">
            <Database className="h-4 w-4 mr-2" />
            Initialize Storage
          </Button>
        )}

        {/* Debug Information */}
        {enableDebugMode && (
          <div className="space-y-2">
            <Button
              onClick={() => setShowDebugInfo(!showDebugInfo)}
              variant="ghost"
              size="sm"
              className="w-full"
            >
              {showDebugInfo ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              <span className="ml-2">Debug Info ({debugInfo.length})</span>
            </Button>

            {showDebugInfo && (
              <div className="max-h-64 overflow-y-auto bg-gray-50 p-2 rounded text-xs font-mono">
                {debugInfo.map((info, index) => (
                  <div key={index} className="mb-2 pb-2 border-b border-gray-200">
                    <div className="font-semibold text-blue-600">{info.timestamp}</div>
                    <div>Action: {info.action}</div>
                    <div>Status: <span className={
                      info.status === 'success' ? 'text-green-600' : 
                      info.status === 'error' ? 'text-red-600' : 'text-yellow-600'
                    }>{info.status}</span></div>
                    {info.duration && <div>Duration: {info.duration}ms</div>}
                    {info.error && <div className="text-red-600">Error: {info.error}</div>}
                    {info.tokenId && <div>Token ID: {info.tokenId}</div>}
                    {info.backend && <div>Backend: {info.backend}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Security Information */}
        <div className="text-xs text-gray-500 space-y-1">
          <p>• Tokens encrypted with AES-GCM 256-bit keys</p>
          <p>• Automatic cleanup of expired tokens</p>
          <p>• IndexedDB with memory fallback</p>
          <p>• No sensitive data persisted unencrypted</p>
        </div>
      </CardContent>
    </Card>
  );
}

export default SecureTokenStorage;