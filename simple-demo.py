#!/usr/bin/env python3
"""
iSECTECH Security Platform - Simple Local Demo
Demonstrates the key security features without external dependencies
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import datetime
import random

class SecurityDashboardHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        if self.path == '/' or self.path == '/dashboard':
            self.send_dashboard()
        elif self.path == '/api/alerts':
            self.send_alerts()
        elif self.path.startswith('/api/'):
            self.send_api_data()
        else:
            self.send_response(404)
            self.end_headers()
    
    def send_dashboard(self):
        """Send the main security dashboard HTML"""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iSECTECH Security Platform - Local Demo</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #0a0a0a; color: #fff; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .logo {{ color: #00ff88; font-size: 3em; font-weight: bold; text-shadow: 0 0 10px #00ff88; }}
        .subtitle {{ color: #888; margin-top: 10px; font-size: 1.2em; }}
        .version {{ color: #555; font-size: 0.9em; margin-top: 5px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 25px; }}
        .card {{ 
            background: linear-gradient(135deg, #1a1a1a, #2a2a2a);
            border-radius: 12px; 
            padding: 25px; 
            border: 1px solid #333;
            box-shadow: 0 4px 15px rgba(0,255,136,0.1);
            transition: transform 0.2s;
        }}
        .card:hover {{ transform: translateY(-5px); }}
        .card h3 {{ 
            margin-top: 0; 
            color: #00ff88; 
            display: flex; 
            align-items: center; 
            font-size: 1.3em;
        }}
        .card-icon {{ margin-right: 10px; font-size: 1.5em; }}
        .metric {{ font-size: 2.8em; font-weight: bold; color: #00ff88; text-shadow: 0 0 5px #00ff88; }}
        .sub-metric {{ color: #ccc; font-size: 0.9em; margin-top: 5px; }}
        .status {{ 
            display: inline-block; 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 0.75em; 
            font-weight: bold;
            text-transform: uppercase;
        }}
        .status.critical {{ background: linear-gradient(45deg, #ff4444, #cc0000); }}
        .status.high {{ background: linear-gradient(45deg, #ff6644, #ff4400); }}
        .status.medium {{ background: linear-gradient(45deg, #ffaa44, #ff8800); }}
        .status.low {{ background: linear-gradient(45deg, #44ff44, #00cc00); }}
        .status.online {{ background: linear-gradient(45deg, #44ff88, #00cc44); }}
        .alert-item {{ 
            background: rgba(255,68,68,0.1); 
            margin: 10px 0; 
            padding: 15px; 
            border-radius: 8px; 
            border-left: 4px solid #ff4444;
        }}
        .alert-item.medium {{ 
            background: rgba(255,170,68,0.1); 
            border-left-color: #ffaa44;
        }}
        .alert-item.low {{ 
            background: rgba(68,255,68,0.1); 
            border-left-color: #44ff44;
        }}
        .timestamp {{ color: #888; font-size: 0.8em; }}
        .service-list {{ list-style: none; padding: 0; }}
        .service-list li {{ 
            padding: 12px; 
            margin: 8px 0; 
            background: rgba(255,255,255,0.05); 
            border-radius: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .refresh-btn {{ 
            background: linear-gradient(45deg, #00ff88, #00cc44);
            color: #000; 
            border: none; 
            padding: 12px 25px; 
            border-radius: 25px; 
            cursor: pointer; 
            font-weight: bold;
            margin: 10px;
            transition: all 0.2s;
        }}
        .refresh-btn:hover {{ transform: scale(1.05); }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 15px; margin-top: 15px; }}
        .stat-item {{ text-align: center; background: rgba(0,255,136,0.1); padding: 10px; border-radius: 6px; }}
        .stat-value {{ font-size: 1.4em; font-weight: bold; color: #00ff88; }}
        .stat-label {{ font-size: 0.8em; color: #ccc; margin-top: 3px; }}
        .progress-bar {{ 
            width: 100%; 
            height: 8px; 
            background: #333; 
            border-radius: 4px; 
            overflow: hidden; 
            margin-top: 10px;
        }}
        .progress-fill {{ 
            height: 100%; 
            background: linear-gradient(45deg, #00ff88, #00cc44); 
            transition: width 0.3s;
        }}
        .feature-list {{ 
            display: grid; 
            grid-template-columns: repeat(2, 1fr); 
            gap: 10px; 
            margin-top: 20px;
        }}
        .feature-item {{ 
            background: rgba(0,255,136,0.05); 
            padding: 8px 12px; 
            border-radius: 4px; 
            font-size: 0.9em;
        }}
        .footer {{ 
            text-align: center; 
            margin-top: 50px; 
            padding: 30px; 
            background: linear-gradient(135deg, #1a1a1a, #2a2a2a);
            border-radius: 12px;
        }}
        .tech-stack {{ 
            display: flex; 
            justify-content: center; 
            gap: 30px; 
            margin-top: 20px; 
            flex-wrap: wrap;
        }}
        .tech-item {{ 
            background: rgba(0,255,136,0.1); 
            padding: 8px 16px; 
            border-radius: 20px; 
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">iSECTECH</div>
        <div class="subtitle">Enterprise Security Command Center</div>
        <div class="version">Local Demo v2.0.0 | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        <button class="refresh-btn" onclick="location.reload()">🔄 Refresh Dashboard</button>
    </div>
    
    <div class="grid">
        <div class="card">
            <h3><span class="card-icon">🚨</span>Security Alerts</h3>
            <div class="metric">{random.randint(3,8)}</div>
            <div class="sub-metric">Active incidents requiring attention</div>
            <div id="recent-alerts">
                <div class="alert-item">
                    <div>
                        <strong>Canary Token Triggered</strong> <span class="status critical">CRITICAL</span>
                        <div class="timestamp">2 minutes ago • IP: 192.168.1.100</div>
                    </div>
                </div>
                <div class="alert-item medium">
                    <div>
                        <strong>Decoy Service Access</strong> <span class="status high">HIGH</span>
                        <div class="timestamp">15 minutes ago • Database Console</div>
                    </div>
                </div>
                <div class="alert-item low">
                    <div>
                        <strong>ML Anomaly Detected</strong> <span class="status medium">MEDIUM</span>
                        <div class="timestamp">1 hour ago • User behavior pattern</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3><span class="card-icon">🎯</span>Canary Tokens</h3>
            <div class="metric">12</div>
            <div class="sub-metric">Deployed across 20 strategic locations</div>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value">4</div>
                    <div class="stat-label">Triggered</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">8</div>
                    <div class="stat-label">Active</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">96%</div>
                    <div class="stat-label">Coverage</div>
                </div>
            </div>
            <ul class="service-list">
                <li>AWS Access Key <span class="status online">ACTIVE</span></li>
                <li>SSH Private Key <span class="status critical">TRIGGERED</span></li>
                <li>API Token <span class="status online">ACTIVE</span></li>
                <li>Database Credential <span class="status online">ACTIVE</span></li>
            </ul>
        </div>
        
        <div class="card">
            <h3><span class="card-icon">🕵️</span>Deception Services</h3>
            <div class="metric">7</div>
            <div class="sub-metric">Realistic decoy services with authentic data</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: 94%;"></div>
            </div>
            <div style="text-align: center; margin-top: 5px; color: #00ff88;">94% Uptime</div>
            <ul class="service-list">
                <li>Customer Portal <span class="status online">ONLINE</span></li>
                <li>Internal API Gateway <span class="status online">ONLINE</span></li>
                <li>Admin Dashboard <span class="status online">ONLINE</span></li>
                <li>Database Console <span class="status high">ACCESSED</span></li>
            </ul>
        </div>
        
        <div class="card">
            <h3><span class="card-icon">🧠</span>ML Threat Detection</h3>
            <div class="metric">98.7%</div>
            <div class="sub-metric">Model accuracy with continuous learning</div>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value">3</div>
                    <div class="stat-label">Anomalies</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">1.2%</div>
                    <div class="stat-label">False +</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">15K</div>
                    <div class="stat-label">Events/hr</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">2hrs</div>
                    <div class="stat-label">Last Update</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3><span class="card-icon">📋</span>Compliance Status</h3>
            <div class="metric">94%</div>
            <div class="sub-metric">Multi-framework compliance automation</div>
            <ul class="service-list">
                <li>NIST CSF <span class="status online">96%</span></li>
                <li>ISO 27001 <span class="status online">92%</span></li>
                <li>PCI-DSS <span class="status online">95%</span></li>
                <li>HIPAA <span class="status medium">91%</span></li>
                <li>SOC 2 Type II <span class="status online">97%</span></li>
            </ul>
        </div>
        
        <div class="card">
            <h3><span class="card-icon">🔒</span>Security Validation</h3>
            <div class="metric">{random.randint(12,18)}</div>
            <div class="sub-metric">Automated tests completed today</div>
            <div class="feature-list">
                <div class="feature-item">✅ Penetration Testing</div>
                <div class="feature-item">✅ Vulnerability Scanning</div>
                <div class="feature-item">✅ Control Validation</div>
                <div class="feature-item">✅ Purple Team Exercises</div>
                <div class="feature-item">✅ BAS Simulations</div>
                <div class="feature-item">✅ CI/CD Security</div>
            </div>
        </div>
    </div>
    
    <div class="footer">
        <h2>🌟 iSECTECH Security Platform Features</h2>
        <div class="feature-list" style="grid-template-columns: repeat(3, 1fr); max-width: 800px; margin: 0 auto;">
            <div class="feature-item">🤖 ML-Powered Threat Detection</div>
            <div class="feature-item">🎯 Advanced Deception Technology</div>
            <div class="feature-item">📊 Real-time Security Analytics</div>
            <div class="feature-item">🔄 Automated Compliance Validation</div>
            <div class="feature-item">🔍 Continuous Security Testing</div>
            <div class="feature-item">⚡ Automated Incident Response</div>
        </div>
        
        <div style="margin-top: 30px;">
            <h3>Technology Stack</h3>
            <div class="tech-stack">
                <div class="tech-item">Next.js 15</div>
                <div class="tech-item">PostgreSQL</div>
                <div class="tech-item">Redis</div>
                <div class="tech-item">Docker</div>
                <div class="tech-item">Kubernetes</div>
                <div class="tech-item">Prometheus</div>
                <div class="tech-item">Python ML</div>
                <div class="tech-item">Go Services</div>
                <div class="tech-item">TypeScript</div>
            </div>
        </div>
        
        <div style="margin-top: 30px; color: #888;">
            <p>This is a local demonstration of the iSECTECH Security Platform</p>
            <p>All components are production-ready and enterprise-grade</p>
        </div>
    </div>
    
    <script>
        // Auto-refresh every 45 seconds
        setTimeout(() => location.reload(), 45000);
        
        // Add some dynamic elements
        const alerts = document.querySelectorAll('.alert-item');
        alerts.forEach((alert, index) => {{
            setTimeout(() => {{
                alert.style.animation = 'fadeInUp 0.5s ease-out';
            }}, index * 200);
        }});
        
        // Simulate real-time updates
        setInterval(() => {{
            const metrics = document.querySelectorAll('.metric');
            metrics.forEach(metric => {{
                if (Math.random() > 0.8) {{
                    metric.style.transform = 'scale(1.05)';
                    setTimeout(() => {{
                        metric.style.transform = 'scale(1)';
                    }}, 200);
                }}
            }});
        }}, 5000);
    </script>
    
    <style>
        @keyframes fadeInUp {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
    </style>
</body>
</html>
        """
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())
    
    def send_alerts(self):
        """Send security alerts data"""
        alert_data = [
            {'id': 1, 'type': 'Canary Token Triggered', 'severity': 'CRITICAL', 'description': 'AWS access key accessed from suspicious location', 'timestamp': '2025-01-09T08:42:00Z'},
            {'id': 2, 'type': 'Decoy Service Access', 'severity': 'HIGH', 'description': 'Unauthorized access to decoy database console', 'timestamp': '2025-01-09T08:25:00Z'},
            {'id': 3, 'type': 'ML Anomaly Detection', 'severity': 'MEDIUM', 'description': 'Unusual user behavior pattern detected', 'timestamp': '2025-01-09T07:15:00Z'},
            {'id': 4, 'type': 'Compliance Violation', 'severity': 'LOW', 'description': 'Missing encryption on data transfer', 'timestamp': '2025-01-09T06:30:00Z'},
            {'id': 5, 'type': 'Failed Login Attempts', 'severity': 'MEDIUM', 'description': 'Multiple failed login attempts from IP 192.168.1.50', 'timestamp': '2025-01-09T05:45:00Z'}
        ]
        self.send_json_response(alert_data)
    
    def send_api_data(self):
        """Send general API data for demonstration"""
        demo_data = {
            'status': 'operational',
            'timestamp': datetime.datetime.now().isoformat(),
            'platform': 'iSECTECH Security Platform',
            'version': '2.0.0',
            'demo': True
        }
        self.send_json_response(demo_data)
    
    def send_json_response(self, data):
        """Send JSON response"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

if __name__ == '__main__':
    try:
        server = HTTPServer(('localhost', 8080), SecurityDashboardHandler)
        print("🚀 iSECTECH Security Platform Demo Server Starting...")
        print("🌐 Dashboard URL: http://localhost:8080")
        print("📊 Features: ML Detection | Deception Tech | Compliance Automation")
        print("⚡ Press Ctrl+C to stop the server")
        print("─" * 70)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")