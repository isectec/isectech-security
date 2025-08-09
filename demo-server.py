#!/usr/bin/env python3
"""
iSECTECH Security Platform - Local Demo Server
Demonstrates the key security features and components
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse
import psycopg2
import redis
import datetime

class SecurityDashboardHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        if self.path == '/' or self.path == '/dashboard':
            self.send_dashboard()
        elif self.path == '/api/alerts':
            self.send_alerts()
        elif self.path == '/api/canary-tokens':
            self.send_canary_tokens()
        elif self.path == '/api/deception-services':
            self.send_deception_services()
        elif self.path == '/api/ml-detections':
            self.send_ml_detections()
        elif self.path == '/api/compliance-status':
            self.send_compliance_status()
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
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .logo {{ color: #00ff88; font-size: 2.5em; font-weight: bold; }}
        .subtitle {{ color: #888; margin-top: 5px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        .card {{ background: #2a2a2a; border-radius: 8px; padding: 20px; border-left: 4px solid #00ff88; }}
        .card h3 {{ margin-top: 0; color: #00ff88; }}
        .metric {{ font-size: 2em; font-weight: bold; color: #fff; }}
        .status {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }}
        .status.high {{ background: #ff4444; }}
        .status.medium {{ background: #ffaa44; }}
        .status.low {{ background: #44ff44; }}
        .status.online {{ background: #44ff44; }}
        .alert-item {{ background: #333; margin: 10px 0; padding: 10px; border-radius: 4px; }}
        .timestamp {{ color: #888; font-size: 0.8em; }}
        .service-list {{ list-style: none; padding: 0; }}
        .service-list li {{ padding: 8px; margin: 5px 0; background: #333; border-radius: 4px; }}
        .refresh-btn {{ background: #00ff88; color: #000; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">iSECTECH</div>
        <div class="subtitle">Enterprise Security Command Center - Local Demo</div>
        <button class="refresh-btn" onclick="location.reload()">Refresh Dashboard</button>
    </div>
    
    <div class="grid">
        <div class="card">
            <h3>🚨 Security Alerts</h3>
            <div class="metric" id="alert-count">5</div>
            <div>Active security incidents</div>
            <div id="recent-alerts">
                <div class="alert-item">
                    <strong>Canary Token Triggered</strong> <span class="status high">HIGH</span>
                    <div class="timestamp">2 minutes ago</div>
                </div>
                <div class="alert-item">
                    <strong>Decoy Service Access</strong> <span class="status high">HIGH</span>
                    <div class="timestamp">15 minutes ago</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3>🎯 Canary Tokens</h3>
            <div class="metric">12</div>
            <div>Deployed tokens</div>
            <ul class="service-list">
                <li>AWS Access Key - Production Console</li>
                <li>SSH Key - Development Server</li>
                <li>API Token - Payment Gateway</li>
                <li>Database Credential - Customer DB</li>
            </ul>
        </div>
        
        <div class="card">
            <h3>🕵️ Deception Services</h3>
            <div class="metric">7</div>
            <div>Active decoy services</div>
            <ul class="service-list">
                <li>Customer Management Portal <span class="status online">ONLINE</span></li>
                <li>Internal API Gateway <span class="status online">ONLINE</span></li>
                <li>Admin Dashboard <span class="status online">ONLINE</span></li>
                <li>Database Console <span class="status online">ONLINE</span></li>
            </ul>
        </div>
        
        <div class="card">
            <h3>🧠 ML Threat Detection</h3>
            <div class="metric">98.7%</div>
            <div>Model accuracy</div>
            <div style="margin-top: 15px;">
                <div>Behavioral anomalies detected: <strong>3</strong></div>
                <div>False positive rate: <strong>1.2%</strong></div>
                <div>Last model update: <strong>2 hours ago</strong></div>
            </div>
        </div>
        
        <div class="card">
            <h3>📋 Compliance Status</h3>
            <div class="metric">94%</div>
            <div>Overall compliance score</div>
            <ul class="service-list">
                <li>NIST CSF: <span class="status online">96%</span></li>
                <li>ISO 27001: <span class="status online">92%</span></li>
                <li>PCI-DSS: <span class="status online">95%</span></li>
                <li>HIPAA: <span class="status online">91%</span></li>
            </ul>
        </div>
        
        <div class="card">
            <h3>🔒 Security Validation</h3>
            <div class="metric">15</div>
            <div>Tests completed today</div>
            <div style="margin-top: 15px;">
                <div>Penetration tests: <strong>5 passed</strong></div>
                <div>Vulnerability scans: <strong>3 passed</strong></div>
                <div>Control validation: <strong>7 passed</strong></div>
            </div>
        </div>
    </div>
    
    <div style="text-align: center; margin-top: 40px; color: #888;">
        <p>iSECTECH Security Platform - Demonstrating production-grade security automation</p>
        <p>🌟 Features: ML Threat Detection | Deception Technology | Automated Compliance | Security Validation</p>
    </div>
    
    <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>
        """
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())
    
    def send_alerts(self):
        """Send security alerts data"""
        try:
            conn = psycopg2.connect(
                host="localhost",
                database="isectech_demo", 
                user="demo_user",
                password="demo_pass",
                port=5432
            )
            
            cur = conn.cursor()
            cur.execute("SELECT * FROM demo_alerts ORDER BY created_at DESC LIMIT 10")
            alerts = cur.fetchall()
            
            alert_data = []
            for alert in alerts:
                alert_data.append({
                    'id': alert[0],
                    'type': alert[1],
                    'severity': alert[2], 
                    'description': alert[3],
                    'timestamp': alert[4].isoformat() if alert[4] else None
                })
            
            cur.close()
            conn.close()
            
        except Exception as e:
            alert_data = [{'error': str(e)}]
        
        self.send_json_response(alert_data)
    
    def send_canary_tokens(self):
        """Send canary token data"""
        token_data = [
            {'id': 'aws_key_001', 'type': 'AWS Access Key', 'location': 'Production Console', 'status': 'active'},
            {'id': 'ssh_key_002', 'type': 'SSH Private Key', 'location': 'Development Server', 'status': 'active'},
            {'id': 'api_token_003', 'type': 'API Key', 'location': 'Payment Gateway', 'status': 'triggered'},
            {'id': 'db_conn_004', 'type': 'Database Credential', 'location': 'Customer Database', 'status': 'active'}
        ]
        self.send_json_response(token_data)
    
    def send_deception_services(self):
        """Send deception services data"""
        service_data = [
            {'name': 'Customer Portal', 'port': 8080, 'status': 'online', 'interactions': 23},
            {'name': 'Internal API', 'port': 8081, 'status': 'online', 'interactions': 7},
            {'name': 'Admin Dashboard', 'port': 8082, 'status': 'online', 'interactions': 2},
            {'name': 'Database Console', 'port': 8083, 'status': 'online', 'interactions': 15}
        ]
        self.send_json_response(service_data)
    
    def send_ml_detections(self):
        """Send ML detection data"""
        ml_data = {
            'model_accuracy': 98.7,
            'anomalies_detected': 3,
            'false_positive_rate': 1.2,
            'last_update': datetime.datetime.now().isoformat(),
            'recent_detections': [
                {'type': 'Unusual login pattern', 'user': 'user123', 'risk_score': 0.85},
                {'type': 'Abnormal data access', 'user': 'user456', 'risk_score': 0.72}
            ]
        }
        self.send_json_response(ml_data)
    
    def send_compliance_status(self):
        """Send compliance status data"""
        compliance_data = {
            'overall_score': 94,
            'frameworks': {
                'NIST_CSF': 96,
                'ISO_27001': 92,
                'PCI_DSS': 95,
                'HIPAA': 91
            },
            'last_assessment': datetime.datetime.now().isoformat()
        }
        self.send_json_response(compliance_data)
    
    def send_json_response(self, data):
        """Send JSON response"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

if __name__ == '__main__':
    server = HTTPServer(('localhost', 8080), SecurityDashboardHandler)
    print("🚀 iSECTECH Security Dashboard running at http://localhost:8080")
    print("🌟 Demonstrating: ML Threat Detection | Deception Technology | Compliance Automation")
    server.serve_forever()
