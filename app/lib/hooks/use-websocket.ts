import { useState, useEffect, useRef, useCallback } from 'react';

interface WebSocketMessage {
  data: string;
  timestamp: Date;
  type?: string;
}

interface UseWebSocketOptions {
  url: string;
  enabled: boolean;
  reconnectAttempts: number;
  reconnectInterval: number;
  heartbeatInterval?: number;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
  protocols?: string | string[];
}

interface UseWebSocketReturn {
  lastMessage: WebSocketMessage | null;
  sendMessage: (message: string) => void;
  isConnected: boolean;
  connectionState: 'connecting' | 'connected' | 'disconnected' | 'error';
  reconnectCount: number;
  closeConnection: () => void;
  openConnection: () => void;
}

export const useWebSocket = (options: UseWebSocketOptions): UseWebSocketReturn => {
  const {
    url,
    enabled,
    reconnectAttempts,
    reconnectInterval,
    heartbeatInterval = 30000, // 30 seconds
    onConnect,
    onDisconnect,
    onError,
    protocols
  } = options;

  // State management
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionState, setConnectionState] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('disconnected');
  const [reconnectCount, setReconnectCount] = useState(0);

  // Refs for stable references
  const websocketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const heartbeatTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const shouldReconnectRef = useRef(true);
  const reconnectAttemptsRef = useRef(0);

  // Clear timeouts helper
  const clearTimeouts = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (heartbeatTimeoutRef.current) {
      clearTimeout(heartbeatTimeoutRef.current);
      heartbeatTimeoutRef.current = null;
    }
  }, []);

  // Start heartbeat
  const startHeartbeat = useCallback(() => {
    if (heartbeatInterval > 0 && websocketRef.current?.readyState === WebSocket.OPEN) {
      heartbeatTimeoutRef.current = setTimeout(() => {
        if (websocketRef.current?.readyState === WebSocket.OPEN) {
          websocketRef.current.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
          startHeartbeat(); // Schedule next heartbeat
        }
      }, heartbeatInterval);
    }
  }, [heartbeatInterval]);

  // Stop heartbeat
  const stopHeartbeat = useCallback(() => {
    if (heartbeatTimeoutRef.current) {
      clearTimeout(heartbeatTimeoutRef.current);
      heartbeatTimeoutRef.current = null;
    }
  }, []);

  // Connect to WebSocket
  const connect = useCallback(() => {
    if (!enabled || websocketRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    try {
      setConnectionState('connecting');
      
      // Create WebSocket connection
      websocketRef.current = new WebSocket(url, protocols);

      // Connection opened
      websocketRef.current.onopen = () => {
        setIsConnected(true);
        setConnectionState('connected');
        setReconnectCount(0);
        reconnectAttemptsRef.current = 0;
        startHeartbeat();
        onConnect?.();
      };

      // Message received
      websocketRef.current.onmessage = (event) => {
        const messageData: WebSocketMessage = {
          data: event.data,
          timestamp: new Date()
        };

        // Handle heartbeat pong
        try {
          const parsed = JSON.parse(event.data);
          if (parsed.type === 'pong') {
            return; // Don't update lastMessage for pong responses
          }
          messageData.type = parsed.type;
        } catch {
          // Not JSON, treat as regular message
        }

        setLastMessage(messageData);
      };

      // Connection closed
      websocketRef.current.onclose = (event) => {
        setIsConnected(false);
        setConnectionState('disconnected');
        stopHeartbeat();
        
        if (shouldReconnectRef.current && enabled && reconnectAttemptsRef.current < reconnectAttempts) {
          // Schedule reconnection
          reconnectAttemptsRef.current += 1;
          setReconnectCount(reconnectAttemptsRef.current);
          
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        }
        
        onDisconnect?.();
      };

      // Connection error
      websocketRef.current.onerror = (error) => {
        setConnectionState('error');
        onError?.(error);
      };

    } catch (error) {
      setConnectionState('error');
      console.error('WebSocket connection error:', error);
      
      if (shouldReconnectRef.current && enabled && reconnectAttemptsRef.current < reconnectAttempts) {
        reconnectAttemptsRef.current += 1;
        setReconnectCount(reconnectAttemptsRef.current);
        
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, reconnectInterval);
      }
    }
  }, [enabled, url, protocols, reconnectAttempts, reconnectInterval, startHeartbeat, stopHeartbeat, onConnect, onDisconnect, onError]);

  // Disconnect from WebSocket
  const disconnect = useCallback(() => {
    shouldReconnectRef.current = false;
    clearTimeouts();
    stopHeartbeat();
    
    if (websocketRef.current) {
      if (websocketRef.current.readyState === WebSocket.OPEN || websocketRef.current.readyState === WebSocket.CONNECTING) {
        websocketRef.current.close(1000, 'Manual disconnect');
      }
      websocketRef.current = null;
    }
    
    setIsConnected(false);
    setConnectionState('disconnected');
    setReconnectCount(0);
    reconnectAttemptsRef.current = 0;
  }, [clearTimeouts, stopHeartbeat]);

  // Send message
  const sendMessage = useCallback((message: string) => {
    if (websocketRef.current?.readyState === WebSocket.OPEN) {
      try {
        websocketRef.current.send(message);
      } catch (error) {
        console.error('Failed to send WebSocket message:', error);
      }
    } else {
      console.warn('WebSocket is not connected. Message not sent:', message);
    }
  }, []);

  // Open connection manually
  const openConnection = useCallback(() => {
    shouldReconnectRef.current = true;
    reconnectAttemptsRef.current = 0;
    setReconnectCount(0);
    connect();
  }, [connect]);

  // Close connection manually
  const closeConnection = useCallback(() => {
    disconnect();
  }, [disconnect]);

  // Effect to handle connection when enabled changes
  useEffect(() => {
    if (enabled) {
      shouldReconnectRef.current = true;
      connect();
    } else {
      disconnect();
    }

    // Cleanup on unmount
    return () => {
      disconnect();
    };
  }, [enabled, connect, disconnect]);

  // Effect to handle URL changes
  useEffect(() => {
    if (enabled && websocketRef.current) {
      // Reconnect with new URL
      disconnect();
      setTimeout(() => {
        if (enabled) {
          connect();
        }
      }, 100);
    }
  }, [url, enabled, connect, disconnect]);

  // Effect to handle page visibility changes
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.hidden) {
        // Page is hidden, reduce heartbeat frequency or pause
        stopHeartbeat();
      } else {
        // Page is visible, resume normal heartbeat
        if (isConnected) {
          startHeartbeat();
        }
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [isConnected, startHeartbeat, stopHeartbeat]);

  // Effect to handle online/offline events
  useEffect(() => {
    const handleOnline = () => {
      if (enabled && !isConnected) {
        shouldReconnectRef.current = true;
        reconnectAttemptsRef.current = 0;
        setReconnectCount(0);
        connect();
      }
    };

    const handleOffline = () => {
      disconnect();
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [enabled, isConnected, connect, disconnect]);

  return {
    lastMessage,
    sendMessage,
    isConnected,
    connectionState,
    reconnectCount,
    closeConnection,
    openConnection
  };
};

export default useWebSocket;