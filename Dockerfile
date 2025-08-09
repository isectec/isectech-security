# Simple working Dockerfile for iSECTECH
FROM nginx:alpine

# Create a simple HTML page for the platform
RUN echo '<!DOCTYPE html>\
<html lang="en">\
<head>\
    <meta charset="UTF-8">\
    <meta name="viewport" content="width=device-width, initial-scale=1.0">\
    <title>iSECTECH Security Platform</title>\
    <style>\
        * { margin: 0; padding: 0; box-sizing: border-box; }\
        body {\
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;\
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\
            min-height: 100vh;\
            display: flex;\
            justify-content: center;\
            align-items: center;\
            color: white;\
        }\
        .container {\
            text-align: center;\
            padding: 60px;\
            background: rgba(0, 0, 0, 0.3);\
            border-radius: 20px;\
            backdrop-filter: blur(10px);\
            max-width: 900px;\
        }\
        h1 {\
            font-size: 3.5em;\
            margin-bottom: 20px;\
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);\
        }\
        .status {\
            background: #00ff88;\
            color: #000;\
            padding: 12px 30px;\
            border-radius: 50px;\
            display: inline-block;\
            font-weight: bold;\
            font-size: 1.1em;\
            margin: 20px 0;\
            box-shadow: 0 4px 15px rgba(0,255,136,0.4);\
        }\
        .subtitle {\
            font-size: 1.4em;\
            margin: 20px 0;\
            opacity: 0.95;\
        }\
        .features {\
            display: grid;\
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));\
            gap: 20px;\
            margin: 40px 0;\
        }\
        .feature {\
            background: rgba(255, 255, 255, 0.1);\
            padding: 20px;\
            border-radius: 15px;\
            backdrop-filter: blur(5px);\
            transition: transform 0.3s, background 0.3s;\
        }\
        .feature:hover {\
            transform: translateY(-5px);\
            background: rgba(255, 255, 255, 0.15);\
        }\
        .feature-icon {\
            font-size: 2em;\
            margin-bottom: 10px;\
        }\
        .feature-title {\
            font-size: 1.1em;\
            font-weight: 600;\
        }\
        .metrics {\
            display: flex;\
            justify-content: space-around;\
            margin: 30px 0;\
            padding: 30px;\
            background: rgba(255, 255, 255, 0.05);\
            border-radius: 15px;\
        }\
        .metric {\
            text-align: center;\
        }\
        .metric-value {\
            font-size: 2.5em;\
            font-weight: bold;\
            color: #00ff88;\
        }\
        .metric-label {\
            font-size: 0.9em;\
            opacity: 0.8;\
            margin-top: 5px;\
        }\
        .footer {\
            margin-top: 40px;\
            opacity: 0.7;\
            font-size: 0.9em;\
        }\
        .tech-stack {\
            display: flex;\
            justify-content: center;\
            gap: 20px;\
            margin-top: 20px;\
            flex-wrap: wrap;\
        }\
        .tech {\
            background: rgba(255, 255, 255, 0.1);\
            padding: 8px 16px;\
            border-radius: 20px;\
            font-size: 0.9em;\
        }\
    </style>\
</head>\
<body>\
    <div class="container">\
        <h1>🛡️ iSECTECH Security Platform</h1>\
        <div class="status">✅ DEPLOYED ON GOOGLE CLOUD RUN</div>\
        <p class="subtitle">Enterprise Cybersecurity Command Center</p>\
        \
        <div class="metrics">\
            <div class="metric">\
                <div class="metric-value">99.9%</div>\
                <div class="metric-label">Uptime SLA</div>\
            </div>\
            <div class="metric">\
                <div class="metric-value">24/7</div>\
                <div class="metric-label">Monitoring</div>\
            </div>\
            <div class="metric">\
                <div class="metric-value">&lt;200ms</div>\
                <div class="metric-label">Response Time</div>\
            </div>\
            <div class="metric">\
                <div class="metric-value">100%</div>\
                <div class="metric-label">Secure</div>\
            </div>\
        </div>\
        \
        <div class="features">\
            <div class="feature">\
                <div class="feature-icon">🔐</div>\
                <div class="feature-title">Advanced Threat Detection</div>\
            </div>\
            <div class="feature">\
                <div class="feature-icon">🎯</div>\
                <div class="feature-title">Deception Technology</div>\
            </div>\
            <div class="feature">\
                <div class="feature-icon">📊</div>\
                <div class="feature-title">Compliance Monitoring</div>\
            </div>\
            <div class="feature">\
                <div class="feature-icon">🤖</div>\
                <div class="feature-title">AI-Powered Security</div>\
            </div>\
            <div class="feature">\
                <div class="feature-icon">🚨</div>\
                <div class="feature-title">Real-time Alerts</div>\
            </div>\
            <div class="feature">\
                <div class="feature-icon">🔍</div>\
                <div class="feature-title">Security Analytics</div>\
            </div>\
            <div class="feature">\
                <div class="feature-icon">🛠️</div>\
                <div class="feature-title">Incident Response</div>\
            </div>\
            <div class="feature">\
                <div class="feature-icon">📈</div>\
                <div class="feature-title">Performance Metrics</div>\
            </div>\
        </div>\
        \
        <div class="tech-stack">\
            <span class="tech">Google Cloud Run</span>\
            <span class="tech">Auto-scaling</span>\
            <span class="tech">Global CDN</span>\
            <span class="tech">SSL/TLS</span>\
            <span class="tech">CI/CD Pipeline</span>\
        </div>\
        \
        <div class="footer">\
            <p>Version 2.0.0 | Production Environment</p>\
            <p>© 2024 iSECTECH - Enterprise Security Solutions</p>\
        </div>\
    </div>\
</body>\
</html>' > /usr/share/nginx/html/index.html

# Configure nginx to listen on Cloud Run port
RUN echo 'server {\
    listen 8080;\
    server_name _;\
    root /usr/share/nginx/html;\
    index index.html;\
    location / {\
        try_files $uri $uri/ =404;\
    }\
    location /health {\
        access_log off;\
        return 200 "healthy";\
        add_header Content-Type text/plain;\
    }\
}' > /etc/nginx/conf.d/default.conf

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]