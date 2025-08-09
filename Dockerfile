# Production Dockerfile for iSECTECH Security Platform
FROM node:18-alpine

WORKDIR /app

# Copy and install dependencies
COPY package*.json ./
RUN npm install --legacy-peer-deps

# Copy application code
COPY . .

# Build the application
RUN npm run build

# Set production environment
ENV NODE_ENV=production
ENV PORT=8080
ENV HOSTNAME=0.0.0.0

EXPOSE 8080

# Start the application
CMD ["npm", "start"]# Trigger rebuild Sat Aug  9 17:43:28 EDT 2025
