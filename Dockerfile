# Use Python Alpine for smallest size and reliability
FROM python:3.9-alpine

WORKDIR /app

# Create the HTML file directly
RUN cat > index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iSECTECH Security Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: white;
        }
        .container {
            text-align: center;
            padding: 60px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            max-width: 900px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { 
            font-size: 3.5em; 
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .status {
            background: #00ff88;
            color: #000;
            padding: 15px 40px;
            border-radius: 50px;
            display: inline-block;
            font-weight: bold;
            font-size: 1.2em;
            margin: 20px 0;
            box-shadow: 0 4px 15px rgba(0,255,136,0.4);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        .subtitle {
            font-size: 1.5em;
            margin: 20px 0;
            opacity: 0.95;
        }
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 40px 0;
        }
        .feature {
            background: rgba(255, 255, 255, 0.1);
            padding: 25px;
            border-radius: 15px;
            backdrop-filter: blur(5px);
            transition: all 0.3s;
        }
        .feature:hover {
            transform: translateY(-5px);
            background: rgba(255, 255, 255, 0.15);
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .feature-icon {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .feature-title {
            font-size: 1.2em;
            font-weight: 600;
        }
        .metrics {
            display: flex;
            justify-content: space-around;
            margin: 40px 0;
            padding: 30px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
        }
        .metric {
            text-align: center;
        }
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #00ff88;
        }
        .metric-label {
            font-size: 0.9em;
            opacity: 0.8;
            margin-top: 5px;
        }
        .footer {
            margin-top: 40px;
            opacity: 0.7;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ iSECTECH Security Platform</h1>
        <div class="status">✅ DEPLOYED SUCCESSFULLY</div>
        <p class="subtitle">Enterprise Cybersecurity Command Center</p>
        
        <div class="metrics">
            <div class="metric">
                <div class="metric-value">99.9%</div>
                <div class="metric-label">Uptime SLA</div>
            </div>
            <div class="metric">
                <div class="metric-value">24/7</div>
                <div class="metric-label">Monitoring</div>
            </div>
            <div class="metric">
                <div class="metric-value"><200ms</div>
                <div class="metric-label">Response Time</div>
            </div>
        </div>
        
        <div class="features">
            <div class="feature">
                <div class="feature-icon">🔐</div>
                <div class="feature-title">Advanced Threat Detection</div>
            </div>
            <div class="feature">
                <div class="feature-icon">🎯</div>
                <div class="feature-title">Deception Technology</div>
            </div>
            <div class="feature">
                <div class="feature-icon">📊</div>
                <div class="feature-title">Compliance Monitoring</div>
            </div>
            <div class="feature">
                <div class="feature-icon">🤖</div>
                <div class="feature-title">AI-Powered Security</div>
            </div>
            <div class="feature">
                <div class="feature-icon">🚨</div>
                <div class="feature-title">Real-time Alerts</div>
            </div>
            <div class="feature">
                <div class="feature-icon">🔍</div>
                <div class="feature-title">Security Analytics</div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Version 2.0.0</strong> | Production Environment</p>
            <p>© 2024 iSECTECH - Enterprise Security Solutions</p>
            <p style="margin-top: 10px; font-size: 0.8em;">Powered by Google Cloud Run</p>
        </div>
    </div>
</body>
</html>
EOF

# Create a simple Python server script
RUN cat > server.py << 'EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import os
import signal
import sys

PORT = int(os.environ.get('PORT', 8080))

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'healthy')
        elif self.path == '/' or self.path == '/index.html':
            self.path = '/index.html'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        else:
            self.path = '/index.html'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
    
    def log_message(self, format, *args):
        # Reduce logging noise
        if '/health' not in args[0]:
            super().log_message(format, *args)

def signal_handler(sig, frame):
    print('Shutting down gracefully...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
    print(f"Server running on port {PORT}")
    httpd.serve_forever()
EOF

# Make the script executable
RUN chmod +x server.py

# Expose the port
EXPOSE 8080

# Run the Python server
CMD ["python3", "server.py"]