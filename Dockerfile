FROM nginx:alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Create custom nginx config that listens on port 8080
RUN echo 'server { \
    listen 8080; \
    server_name _; \
    root /usr/share/nginx/html; \
    index index.html; \
    location / { \
        try_files $uri $uri/ /index.html; \
    } \
    location /health { \
        access_log off; \
        return 200 "healthy"; \
        add_header Content-Type text/plain; \
    } \
}' > /etc/nginx/conf.d/default.conf

# Create the HTML page
RUN echo '<!DOCTYPE html> \
<html lang="en"> \
<head> \
    <meta charset="UTF-8"> \
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> \
    <title>iSECTECH Security Platform</title> \
    <style> \
        * { margin: 0; padding: 0; box-sizing: border-box; } \
        body { \
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; \
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); \
            min-height: 100vh; \
            display: flex; \
            justify-content: center; \
            align-items: center; \
            color: white; \
        } \
        .container { \
            text-align: center; \
            padding: 60px; \
            background: rgba(0, 0, 0, 0.3); \
            border-radius: 20px; \
            max-width: 900px; \
        } \
        h1 { font-size: 3em; margin-bottom: 20px; } \
        .status { \
            background: #00ff88; \
            color: #000; \
            padding: 12px 30px; \
            border-radius: 50px; \
            display: inline-block; \
            font-weight: bold; \
            margin: 20px 0; \
        } \
        .features { \
            display: grid; \
            grid-template-columns: repeat(2, 1fr); \
            gap: 20px; \
            margin: 40px 0; \
        } \
        .feature { \
            background: rgba(255, 255, 255, 0.1); \
            padding: 20px; \
            border-radius: 10px; \
        } \
    </style> \
</head> \
<body> \
    <div class="container"> \
        <h1>🛡️ iSECTECH Security Platform</h1> \
        <div class="status">✅ LIVE ON CLOUD RUN</div> \
        <p style="font-size: 1.2em; margin: 20px 0;">Enterprise Cybersecurity Command Center</p> \
        <div class="features"> \
            <div class="feature">🔐 Advanced Threat Detection</div> \
            <div class="feature">🎯 Deception Technology</div> \
            <div class="feature">📊 Compliance Monitoring</div> \
            <div class="feature">🤖 AI-Powered Security</div> \
        </div> \
        <p style="margin-top: 30px; opacity: 0.8;">Version 2.0.0 | Production Ready</p> \
    </div> \
</body> \
</html>' > /usr/share/nginx/html/index.html

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]