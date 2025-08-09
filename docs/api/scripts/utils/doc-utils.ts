/**
 * Documentation Generation Utilities
 * 
 * Utility functions for validating OpenAPI specifications, generating code examples,
 * and creating versioned documentation.
 */

import { promises as fs } from 'fs';
import { execSync } from 'child_process';
import path from 'path';

// OpenAPI validation
export async function validateOpenAPISpec(specPath: string): Promise<boolean> {
  try {
    const specContent = JSON.parse(await fs.readFile(specPath, 'utf8'));
    
    // Basic OpenAPI 3.x validation
    if (!specContent.openapi || !specContent.openapi.startsWith('3.')) {
      console.error(`Invalid OpenAPI version: ${specContent.openapi}`);
      return false;
    }
    
    if (!specContent.info || !specContent.info.title || !specContent.info.version) {
      console.error('Missing required info fields (title, version)');
      return false;
    }
    
    if (!specContent.paths || Object.keys(specContent.paths).length === 0) {
      console.error('No paths defined in specification');
      return false;
    }
    
    // Validate security schemes if present
    if (specContent.components && specContent.components.securitySchemes) {
      for (const [name, scheme] of Object.entries(specContent.components.securitySchemes)) {
        if (!validateSecurityScheme(scheme as any)) {
          console.error(`Invalid security scheme: ${name}`);
          return false;
        }
      }
    }
    
    // Validate paths
    for (const [path, pathItem] of Object.entries(specContent.paths)) {
      if (!validatePathItem(pathItem as any)) {
        console.error(`Invalid path item: ${path}`);
        return false;
      }
    }
    
    return true;
  } catch (error) {
    console.error(`Validation error: ${error.message}`);
    return false;
  }
}

function validateSecurityScheme(scheme: any): boolean {
  if (!scheme.type) return false;
  
  switch (scheme.type) {
    case 'http':
      return scheme.scheme !== undefined;
    case 'apiKey':
      return scheme.name !== undefined && scheme.in !== undefined;
    case 'oauth2':
      return scheme.flows !== undefined;
    case 'openIdConnect':
      return scheme.openIdConnectUrl !== undefined;
    default:
      return false;
  }
}

function validatePathItem(pathItem: any): boolean {
  const validMethods = ['get', 'post', 'put', 'delete', 'options', 'head', 'patch', 'trace'];
  
  for (const method of validMethods) {
    if (pathItem[method] && !validateOperation(pathItem[method])) {
      return false;
    }
  }
  
  return true;
}

function validateOperation(operation: any): boolean {
  // Basic operation validation
  return operation.responses && Object.keys(operation.responses).length > 0;
}

// Code examples generation
export async function generateCodeExamples(
  spec: any,
  languages: string[],
  includeAuth: boolean = true,
  includeErrorHandling: boolean = true
): Promise<Record<string, string>> {
  const examples: Record<string, string> = {};
  
  for (const language of languages) {
    try {
      examples[language] = await generateCodeExampleForLanguage(spec, language, includeAuth, includeErrorHandling);
    } catch (error) {
      console.warn(`Failed to generate ${language} examples:`, error.message);
      examples[language] = `// Error generating ${language} examples: ${error.message}`;
    }
  }
  
  return examples;
}

async function generateCodeExampleForLanguage(
  spec: any,
  language: string,
  includeAuth: boolean,
  includeErrorHandling: boolean
): Promise<string> {
  const baseUrl = spec.servers?.[0]?.url || 'https://api.isectech.com/v1';
  const title = spec.info?.title || 'API';
  
  switch (language) {
    case 'javascript':
      return generateJavaScriptExamples(spec, baseUrl, includeAuth, includeErrorHandling);
    case 'python':
      return generatePythonExamples(spec, baseUrl, includeAuth, includeErrorHandling);
    case 'go':
      return generateGoExamples(spec, baseUrl, includeAuth, includeErrorHandling);
    case 'curl':
      return generateCurlExamples(spec, baseUrl, includeAuth, includeErrorHandling);
    case 'php':
      return generatePHPExamples(spec, baseUrl, includeAuth, includeErrorHandling);
    default:
      throw new Error(`Unsupported language: ${language}`);
  }
}

function generateJavaScriptExamples(spec: any, baseUrl: string, includeAuth: boolean, includeErrorHandling: boolean): string {
  const paths = Object.keys(spec.paths || {}).slice(0, 5); // First 5 endpoints for examples
  
  let code = `/**
 * ${spec.info?.title || 'API'} - JavaScript Examples
 * Generated from OpenAPI specification
 */

const axios = require('axios');

// Configuration
const API_BASE_URL = '${baseUrl}';
${includeAuth ? "const API_TOKEN = process.env.API_TOKEN || 'your-jwt-token-here';" : ''}

// Create API client with default configuration
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
    ${includeAuth ? "'Authorization': `Bearer ${API_TOKEN}`," : ''}
    'User-Agent': 'iSECTECH-JS-Client/1.0.0'
  },
  timeout: 10000
});

${includeErrorHandling ? `
// Response interceptor for error handling
apiClient.interceptors.response.use(
  response => response,
  error => {
    if (error.response) {
      // API responded with error status
      console.error('API Error:', {
        status: error.response.status,
        data: error.response.data,
        requestId: error.response.headers['x-request-id']
      });
      
      // Handle specific error cases
      switch (error.response.status) {
        case 401:
          console.error('Authentication failed. Please check your token.');
          break;
        case 403:
          console.error('Access forbidden. Insufficient permissions.');
          break;
        case 429:
          console.error('Rate limit exceeded. Please retry after:', error.response.headers['retry-after']);
          break;
        case 500:
          console.error('Internal server error. Please try again later.');
          break;
      }
    } else if (error.request) {
      // Network error
      console.error('Network Error:', error.message);
    } else {
      console.error('Error:', error.message);
    }
    return Promise.reject(error);
  }
);

// Rate limiting helper
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function handleRateLimit(error) {
  if (error.response?.status === 429) {
    const retryAfter = parseInt(error.response.headers['retry-after']) || 60;
    console.log(\`Rate limited. Waiting \${retryAfter} seconds...\`);
    await delay(retryAfter * 1000);
  }
}
` : ''}

// Example API functions
${paths.map(path => generateJSFunctionForPath(spec, path)).join('\\n\\n')}

${includeAuth ? `
// Authentication helper
async function authenticate(username, password, mfaCode) {
  try {
    const response = await axios.post(\`\${API_BASE_URL}/auth/login\`, {
      username,
      password,
      mfaCode
    });
    
    const { token, expiresIn, refreshToken } = response.data.data;
    
    // Store token securely (example using environment variable)
    process.env.API_TOKEN = token;
    
    // Update client headers
    apiClient.defaults.headers['Authorization'] = \`Bearer \${token}\`;
    
    console.log('Authentication successful');
    return { token, expiresIn, refreshToken };
  } catch (error) {
    console.error('Authentication failed:', error.response?.data || error.message);
    throw error;
  }
}

// Token refresh helper
async function refreshToken(refreshToken) {
  try {
    const response = await axios.post(\`\${API_BASE_URL}/auth/refresh\`, {
      refreshToken
    });
    
    const { token } = response.data.data;
    apiClient.defaults.headers['Authorization'] = \`Bearer \${token}\`;
    
    return token;
  } catch (error) {
    console.error('Token refresh failed:', error.response?.data || error.message);
    throw error;
  }
}
` : ''}

// Usage examples
async function main() {
  try {
    ${includeAuth ? `
    // Authenticate first
    await authenticate('your-username', 'your-password', '123456');
    ` : ''}
    
    // Example API calls
    ${paths.slice(0, 2).map(path => `await ${getFunctionNameFromPath(path)}();`).join('\\n    ')}
    
  } catch (error) {
    console.error('Error in main:', error);
  }
}

// Run examples
if (require.main === module) {
  main();
}

module.exports = {
  apiClient,
  ${paths.map(path => getFunctionNameFromPath(path)).join(',\\n  ')},
  ${includeAuth ? 'authenticate, refreshToken' : ''}
};
`;

  return code;
}

function generatePythonExamples(spec: any, baseUrl: string, includeAuth: boolean, includeErrorHandling: boolean): string {
  const paths = Object.keys(spec.paths || {}).slice(0, 5);
  
  return `"""
${spec.info?.title || 'API'} - Python Examples
Generated from OpenAPI specification
"""

import requests
import os
import time
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ISECTECHAPIClient:
    """
    Python client for iSECTECH API
    """
    
    def __init__(self, base_url: str = "${baseUrl}", token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        ${includeAuth ? `
        self.token = token or os.getenv('API_TOKEN')
        self.refresh_token = None
        self.token_expires = None
        ` : ''}
        
        # Set default headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'iSECTECH-Python-Client/1.0.0',
            ${includeAuth ? "'Authorization': f'Bearer {self.token}' if self.token else None" : ''}
        })
    
    ${includeAuth ? `
    def authenticate(self, username: str, password: str, mfa_code: str) -> Dict[str, Any]:
        """Authenticate with the API"""
        response = self.session.post(f"{self.base_url}/auth/login", json={
            "username": username,
            "password": password,
            "mfaCode": mfa_code
        })
        
        if response.status_code == 200:
            data = response.json()['data']
            self.token = data['token']
            self.refresh_token = data['refreshToken']
            self.token_expires = datetime.now() + timedelta(seconds=data['expiresIn'])
            
            # Update session headers
            self.session.headers['Authorization'] = f'Bearer {self.token}'
            
            logger.info("Authentication successful")
            return data
        else:
            logger.error(f"Authentication failed: {response.status_code}")
            response.raise_for_status()
    
    def refresh_access_token(self) -> str:
        """Refresh the access token"""
        if not self.refresh_token:
            raise ValueError("No refresh token available")
        
        response = self.session.post(f"{self.base_url}/auth/refresh", json={
            "refreshToken": self.refresh_token
        })
        
        if response.status_code == 200:
            data = response.json()['data']
            self.token = data['token']
            self.token_expires = datetime.now() + timedelta(seconds=data['expiresIn'])
            self.session.headers['Authorization'] = f'Bearer {self.token}'
            return self.token
        else:
            response.raise_for_status()
    
    def ensure_valid_token(self):
        """Ensure the token is valid, refresh if necessary"""
        if self.token_expires and datetime.now() >= self.token_expires:
            logger.info("Token expired, refreshing...")
            self.refresh_access_token()
    ` : ''}
    
    ${includeErrorHandling ? `
    def handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Handle API response with proper error handling"""
        try:
            # Log rate limit information
            if 'X-Rate-Limit-Remaining' in response.headers:
                remaining = response.headers['X-Rate-Limit-Remaining']
                logger.debug(f"Rate limit remaining: {remaining}")
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 201:
                return response.json()
            elif response.status_code == 401:
                logger.error("Authentication failed")
                raise requests.exceptions.HTTPError("Authentication required")
            elif response.status_code == 403:
                logger.error("Access forbidden")
                raise requests.exceptions.HTTPError("Insufficient permissions")
            elif response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limited. Retry after {retry_after} seconds")
                time.sleep(retry_after)
                raise requests.exceptions.HTTPError("Rate limit exceeded")
            elif response.status_code >= 500:
                logger.error(f"Server error: {response.status_code}")
                raise requests.exceptions.HTTPError("Internal server error")
            else:
                logger.error(f"API error: {response.status_code}")
                response.raise_for_status()
        except ValueError as e:
            logger.error(f"Invalid JSON response: {e}")
            raise
    ` : ''}
    
    # API methods
${paths.map(path => generatePythonMethodForPath(spec, path, includeAuth)).join('\\n\\n')}

# Usage examples
def main():
    """Example usage of the API client"""
    client = ISECTECHAPIClient()
    
    try:
        ${includeAuth ? `
        # Authenticate
        client.authenticate(
            username=os.getenv('API_USERNAME', 'your-username'),
            password=os.getenv('API_PASSWORD', 'your-password'),
            mfa_code=input('Enter MFA code: ')
        )
        ` : ''}
        
        # Example API calls
        ${paths.slice(0, 2).map(path => `result = client.${getPythonMethodNameFromPath(path)}()
        print(f"${getPythonMethodNameFromPath(path)} result:", result)`).join('\\n        ')}
        
    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
`;
}

function generateGoExamples(spec: any, baseUrl: string, includeAuth: boolean, includeErrorHandling: boolean): string {
  const paths = Object.keys(spec.paths || {}).slice(0, 5);
  
  return `//
// ${spec.info?.title || 'API'} - Go Examples
// Generated from OpenAPI specification
//

package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "time"
    "strconv"
    "log"
)

const (
    APIBaseURL = "${baseUrl}"
    UserAgent  = "iSECTECH-Go-Client/1.0.0"
    Timeout    = 10 * time.Second
)

// Client represents the API client
type Client struct {
    BaseURL    string
    HTTPClient *http.Client
    ${includeAuth ? 'Token      string' : ''}
}

// NewClient creates a new API client
func NewClient(${includeAuth ? 'token string' : ''}) *Client {
    return &Client{
        BaseURL: APIBaseURL,
        HTTPClient: &http.Client{
            Timeout: Timeout,
        },
        ${includeAuth ? 'Token: token,' : ''}
    }
}

${includeAuth ? `
// AuthRequest represents an authentication request
type AuthRequest struct {
    Username string \`json:"username"\`
    Password string \`json:"password"\`
    MFACode  string \`json:"mfaCode"\`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
    Success bool \`json:"success"\`
    Data    struct {
        Token        string \`json:"token"\`
        ExpiresIn    int    \`json:"expiresIn"\`
        RefreshToken string \`json:"refreshToken"\`
    } \`json:"data"\`
}

// Authenticate performs authentication
func (c *Client) Authenticate(username, password, mfaCode string) (*AuthResponse, error) {
    authReq := AuthRequest{
        Username: username,
        Password: password,
        MFACode:  mfaCode,
    }
    
    var authResp AuthResponse
    if err := c.makeRequest("POST", "/auth/login", authReq, &authResp); err != nil {
        return nil, fmt.Errorf("authentication failed: %w", err)
    }
    
    // Store token for future requests
    c.Token = authResp.Data.Token
    
    log.Println("Authentication successful")
    return &authResp, nil
}
` : ''}

// makeRequest performs an HTTP request
func (c *Client) makeRequest(method, endpoint string, body interface{}, result interface{}) error {
    var reqBody io.Reader
    
    if body != nil {
        jsonBody, err := json.Marshal(body)
        if err != nil {
            return fmt.Errorf("failed to marshal request body: %w", err)
        }
        reqBody = bytes.NewBuffer(jsonBody)
    }
    
    req, err := http.NewRequest(method, c.BaseURL+endpoint, reqBody)
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }
    
    // Set headers
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("User-Agent", UserAgent)
    ${includeAuth ? `
    if c.Token != "" {
        req.Header.Set("Authorization", "Bearer "+c.Token)
    }
    ` : ''}
    
    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()
    
    ${includeErrorHandling ? `
    // Handle rate limiting
    if remaining := resp.Header.Get("X-Rate-Limit-Remaining"); remaining != "" {
        if count, err := strconv.Atoi(remaining); err == nil {
            log.Printf("Rate limit remaining: %d", count)
        }
    }
    
    // Handle errors
    switch resp.StatusCode {
    case http.StatusOK, http.StatusCreated:
        // Success - continue to parse response
    case http.StatusUnauthorized:
        return fmt.Errorf("authentication required")
    case http.StatusForbidden:
        return fmt.Errorf("insufficient permissions")
    case http.StatusTooManyRequests:
        retryAfter := resp.Header.Get("Retry-After")
        return fmt.Errorf("rate limit exceeded, retry after: %s seconds", retryAfter)
    case http.StatusInternalServerError:
        return fmt.Errorf("internal server error")
    default:
        return fmt.Errorf("API error: %d", resp.StatusCode)
    }
    ` : `
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return fmt.Errorf("API error: %d", resp.StatusCode)
    }
    `}
    
    if result != nil {
        if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
            return fmt.Errorf("failed to decode response: %w", err)
        }
    }
    
    return nil
}

${paths.map(path => generateGoMethodForPath(spec, path)).join('\\n\\n')}

func main() {
    ${includeAuth ? `
    // Get credentials from environment
    token := os.Getenv("API_TOKEN")
    client := NewClient(token)
    
    // Authenticate if no token provided
    if token == "" {
        username := os.Getenv("API_USERNAME")
        password := os.Getenv("API_PASSWORD")
        
        if username == "" || password == "" {
            log.Fatal("Please provide API_USERNAME and API_PASSWORD environment variables")
        }
        
        fmt.Print("Enter MFA code: ")
        var mfaCode string
        fmt.Scanln(&mfaCode)
        
        _, err := client.Authenticate(username, password, mfaCode)
        if err != nil {
            log.Fatalf("Authentication failed: %v", err)
        }
    }
    ` : 'client := NewClient()'}
    
    // Example API calls
    ${paths.slice(0, 2).map(path => {
      const methodName = getGoMethodNameFromPath(path);
      return `
    ${methodName.toLowerCase()}Result, err := client.${methodName}()
    if err != nil {
        log.Printf("${methodName} failed: %v", err)
    } else {
        log.Printf("${methodName} result: %+v", ${methodName.toLowerCase()}Result)
    }`;
    }).join('')}
}
`;
}

function generateCurlExamples(spec: any, baseUrl: string, includeAuth: boolean, includeErrorHandling: boolean): string {
  const paths = Object.keys(spec.paths || {}).slice(0, 5);
  
  return `#!/bin/bash

#
# ${spec.info?.title || 'API'} - cURL Examples
# Generated from OpenAPI specification
#

# Configuration
API_BASE_URL="${baseUrl}"
${includeAuth ? 'API_TOKEN="${API_TOKEN:-your-jwt-token-here}"' : ''}

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

# Helper function for colored output
log_info() {
    echo -e "\${GREEN}[INFO]\${NC} \$1"
}

log_error() {
    echo -e "\${RED}[ERROR]\${NC} \$1"
}

log_warning() {
    echo -e "\${YELLOW}[WARNING]\${NC} \$1"
}

${includeErrorHandling ? `
# Error handling function
handle_response() {
    local http_code=\$1
    local response=\$2
    
    case \$http_code in
        200|201)
            log_info "Request successful"
            echo "\$response" | jq '.' 2>/dev/null || echo "\$response"
            ;;
        400)
            log_error "Bad Request (400)"
            echo "\$response" | jq '.error // .' 2>/dev/null || echo "\$response"
            ;;
        401)
            log_error "Unauthorized (401) - Check your authentication token"
            echo "\$response" | jq '.error // .' 2>/dev/null || echo "\$response"
            ;;
        403)
            log_error "Forbidden (403) - Insufficient permissions"
            echo "\$response" | jq '.error // .' 2>/dev/null || echo "\$response"
            ;;
        429)
            log_warning "Rate Limited (429) - Please wait before retrying"
            echo "\$response" | jq '.error // .' 2>/dev/null || echo "\$response"
            ;;
        500)
            log_error "Internal Server Error (500)"
            echo "\$response" | jq '.error // .' 2>/dev/null || echo "\$response"
            ;;
        *)
            log_error "HTTP Error \$http_code"
            echo "\$response" | jq '.error // .' 2>/dev/null || echo "\$response"
            ;;
    esac
}

# Make API request with error handling
api_request() {
    local method=\$1
    local endpoint=\$2
    local data=\$3
    
    local curl_args=(
        -s
        -w "\\n%{http_code}"
        -X "\$method"
        -H "Content-Type: application/json"
        -H "User-Agent: iSECTECH-cURL-Client/1.0.0"
        ${includeAuth ? '-H "Authorization: Bearer $API_TOKEN"' : ''}
    )
    
    if [[ -n "\$data" ]]; then
        curl_args+=(-d "\$data")
    fi
    
    local response
    response=\$(curl "\${curl_args[@]}" "\$API_BASE_URL\$endpoint")
    
    local http_code=\${response##*$'\\n'}
    local body=\${response%$'\\n'*}
    
    handle_response "\$http_code" "\$body"
}
` : `
# Simple API request function
api_request() {
    local method=\$1
    local endpoint=\$2
    local data=\$3
    
    local curl_args=(
        -s
        -X "\$method"
        -H "Content-Type: application/json"
        -H "User-Agent: iSECTECH-cURL-Client/1.0.0"
        ${includeAuth ? '-H "Authorization: Bearer $API_TOKEN"' : ''}
    )
    
    if [[ -n "\$data" ]]; then
        curl_args+=(-d "\$data")
    fi
    
    curl "\${curl_args[@]}" "\$API_BASE_URL\$endpoint" | jq '.' 2>/dev/null || echo "Response received"
}
`}

${includeAuth ? `
# Authentication function
authenticate() {
    local username=\$1
    local password=\$2
    local mfa_code=\$3
    
    log_info "Authenticating with iSECTECH API..."
    
    local auth_data
    auth_data=\$(cat <<EOF
{
  "username": "\$username",
  "password": "\$password",
  "mfaCode": "\$mfa_code"
}
EOF
    )
    
    local response
    response=\$(curl -s -X POST \\
        -H "Content-Type: application/json" \\
        -d "\$auth_data" \\
        "\$API_BASE_URL/auth/login")
    
    local token
    token=\$(echo "\$response" | jq -r '.data.token // empty' 2>/dev/null)
    
    if [[ -n "\$token" && "\$token" != "null" ]]; then
        export API_TOKEN="\$token"
        log_info "Authentication successful"
        echo "Token: \$token"
        return 0
    else
        log_error "Authentication failed"
        echo "\$response" | jq '.error // .' 2>/dev/null || echo "\$response"
        return 1
    fi
}

# Check if authenticated
check_auth() {
    if [[ -z "\$API_TOKEN" || "\$API_TOKEN" == "your-jwt-token-here" ]]; then
        log_error "No valid API token found"
        echo "Please set API_TOKEN environment variable or run authenticate function"
        echo "Example: authenticate 'username' 'password' '123456'"
        return 1
    fi
}
` : ''}

# Example API calls
${paths.map(path => generateCurlExampleForPath(spec, path)).join('\\n\\n')}

# Main execution
main() {
    log_info "iSECTECH API Examples"
    echo "Base URL: \$API_BASE_URL"
    
    ${includeAuth ? `
    # Check authentication
    if ! check_auth; then
        echo
        echo "To authenticate, run:"
        echo "  authenticate 'your-username' 'your-password' 'mfa-code'"
        echo
        echo "Or set the API_TOKEN environment variable:"
        echo "  export API_TOKEN='your-jwt-token'"
        return 1
    fi
    ` : ''}
    
    echo
    log_info "Running example API calls..."
    
    ${paths.slice(0, 2).map(path => {
      const functionName = getCurlFunctionNameFromPath(path);
      return `
    echo
    log_info "Calling ${functionName}..."
    ${functionName}`;
    }).join('')}
    
    echo
    log_info "Examples completed"
}

# Check if script is being sourced or executed
if [[ "\${BASH_SOURCE[0]}" == "\${0}" ]]; then
    # Script is being executed directly
    main "\$@"
else
    # Script is being sourced
    echo "Functions loaded. Run 'main' to execute examples."
fi
`;
}

function generatePHPExamples(spec: any, baseUrl: string, includeAuth: boolean, includeErrorHandling: boolean): string {
  const paths = Object.keys(spec.paths || {}).slice(0, 5);
  
  return `<?php

/**
 * ${spec.info?.title || 'API'} - PHP Examples
 * Generated from OpenAPI specification
 */

class ISECTECHAPIClient
{
    private \$baseUrl;
    private \$token;
    private \$httpClient;
    
    const USER_AGENT = 'iSECTECH-PHP-Client/1.0.0';
    const TIMEOUT = 10;
    
    public function __construct(\$baseUrl = '${baseUrl}', \$token = null)
    {
        \$this->baseUrl = rtrim(\$baseUrl, '/');
        \$this->token = \$token ?: (\$_ENV['API_TOKEN'] ?? null);
        
        // Initialize cURL
        \$this->httpClient = curl_init();
        curl_setopt_array(\$this->httpClient, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => self::TIMEOUT,
            CURLOPT_USERAGENT => self::USER_AGENT,
            CURLOPT_HTTPHEADER => \$this->getDefaultHeaders(),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_FOLLOWLOCATION => false
        ]);
    }
    
    public function __destruct()
    {
        if (\$this->httpClient) {
            curl_close(\$this->httpClient);
        }
    }
    
    private function getDefaultHeaders(): array
    {
        \$headers = [
            'Content-Type: application/json',
            'User-Agent: ' . self::USER_AGENT
        ];
        
        ${includeAuth ? `
        if (\$this->token) {
            \$headers[] = 'Authorization: Bearer ' . \$this->token;
        }
        ` : ''}
        
        return \$headers;
    }
    
    ${includeAuth ? `
    /**
     * Authenticate with the API
     */
    public function authenticate(\$username, \$password, \$mfaCode): array
    {
        \$response = \$this->makeRequest('POST', '/auth/login', [
            'username' => \$username,
            'password' => \$password,
            'mfaCode' => \$mfaCode
        ]);
        
        if (isset(\$response['data']['token'])) {
            \$this->token = \$response['data']['token'];
            error_log('Authentication successful');
            return \$response['data'];
        }
        
        throw new Exception('Authentication failed: ' . json_encode(\$response));
    }
    ` : ''}
    
    /**
     * Make HTTP request to API
     */
    private function makeRequest(\$method, \$endpoint, \$data = null): array
    {
        \$url = \$this->baseUrl . \$endpoint;
        
        curl_setopt(\$this->httpClient, CURLOPT_URL, \$url);
        curl_setopt(\$this->httpClient, CURLOPT_CUSTOMREQUEST, \$method);
        curl_setopt(\$this->httpClient, CURLOPT_HTTPHEADER, \$this->getDefaultHeaders());
        
        if (\$data !== null) {
            curl_setopt(\$this->httpClient, CURLOPT_POSTFIELDS, json_encode(\$data));
        } else {
            curl_setopt(\$this->httpClient, CURLOPT_POSTFIELDS, null);
        }
        
        \$response = curl_exec(\$this->httpClient);
        \$httpCode = curl_getinfo(\$this->httpClient, CURLINFO_HTTP_CODE);
        \$error = curl_error(\$this->httpClient);
        
        if (\$error) {
            throw new Exception("cURL error: " . \$error);
        }
        
        ${includeErrorHandling ? `
        // Handle HTTP errors
        switch (\$httpCode) {
            case 200:
            case 201:
                break; // Success
            case 401:
                throw new Exception("Authentication required");
            case 403:
                throw new Exception("Insufficient permissions");
            case 429:
                \$retryAfter = curl_getinfo(\$this->httpClient, CURLINFO_HEADER_OUT);
                throw new Exception("Rate limit exceeded");
            case 500:
                throw new Exception("Internal server error");
            default:
                throw new Exception("API error: HTTP " . \$httpCode);
        }
        ` : `
        if (\$httpCode < 200 || \$httpCode >= 300) {
            throw new Exception("API error: HTTP " . \$httpCode);
        }
        `}
        
        \$decodedResponse = json_decode(\$response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Invalid JSON response: " . json_last_error_msg());
        }
        
        return \$decodedResponse;
    }
    
    // API Methods
${paths.map(path => generatePHPMethodForPath(spec, path)).join('\\n\\n')}
}

// Usage examples
function main()
{
    try {
        \$client = new ISECTECHAPIClient();
        
        ${includeAuth ? `
        // Authenticate if needed
        if (!\$client->token) {
            \$username = \$_ENV['API_USERNAME'] ?? readline('Username: ');
            \$password = \$_ENV['API_PASSWORD'] ?? readline('Password: ');
            \$mfaCode = readline('MFA Code: ');
            
            \$client->authenticate(\$username, \$password, \$mfaCode);
        }
        ` : ''}
        
        // Example API calls
        ${paths.slice(0, 2).map(path => {
          const methodName = getPHPMethodNameFromPath(path);
          return `
        echo "Calling ${methodName}...\\n";
        \$result = \$client->${methodName}();
        echo "Result: " . json_encode(\$result, JSON_PRETTY_PRINT) . "\\n\\n";`;
        }).join('')}
        
    } catch (Exception \$e) {
        echo "Error: " . \$e->getMessage() . "\\n";
        exit(1);
    }
}

// Run examples if executed directly
if (basename(__FILE__) === basename(\$_SERVER['SCRIPT_NAME'])) {
    main();
}

?>
`;
}

// Helper functions for generating method names and examples
function generateJSFunctionForPath(spec: any, path: string): string {
  const pathItem = spec.paths[path];
  const method = Object.keys(pathItem)[0]; // Get first method
  const operation = pathItem[method];
  const functionName = getFunctionNameFromPath(path);
  
  return `async function ${functionName}() {
  try {
    const response = await apiClient.${method}('${path}');
    console.log('${functionName} result:', response.data);
    return response.data;
  } catch (error) {
    console.error('${functionName} failed:', error.message);
    throw error;
  }
}`;
}

function generatePythonMethodForPath(spec: any, path: string, includeAuth: boolean): string {
  const pathItem = spec.paths[path];
  const method = Object.keys(pathItem)[0];
  const operation = pathItem[method];
  const methodName = getPythonMethodNameFromPath(path);
  
  return `    def ${methodName}(self) -> Dict[str, Any]:
        """${operation.summary || `Call ${method.toUpperCase()} ${path}`}"""
        ${includeAuth ? 'self.ensure_valid_token()' : ''}
        
        response = self.session.${method}(f"{self.base_url}${path}")
        return self.handle_response(response)`;
}

function generateGoMethodForPath(spec: any, path: string): string {
  const pathItem = spec.paths[path];
  const method = Object.keys(pathItem)[0];
  const operation = pathItem[method];
  const methodName = getGoMethodNameFromPath(path);
  
  return `// ${methodName} ${operation.summary || `calls ${method.toUpperCase()} ${path}`}
func (c *Client) ${methodName}() (interface{}, error) {
    var result interface{}
    if err := c.makeRequest("${method.toUpperCase()}", "${path}", nil, &result); err != nil {
        return nil, fmt.Errorf("${methodName} failed: %w", err)
    }
    return result, nil
}`;
}

function generateCurlExampleForPath(spec: any, path: string): string {
  const pathItem = spec.paths[path];
  const method = Object.keys(pathItem)[0];
  const operation = pathItem[method];
  const functionName = getCurlFunctionNameFromPath(path);
  
  return `# ${operation.summary || `Call ${method.toUpperCase()} ${path}`}
${functionName}() {
    log_info "Calling ${method.toUpperCase()} ${path}"
    api_request "${method.toUpperCase()}" "${path}"
}`;
}

function generatePHPMethodForPath(spec: any, path: string): string {
  const pathItem = spec.paths[path];
  const method = Object.keys(pathItem)[0];
  const operation = pathItem[method];
  const methodName = getPHPMethodNameFromPath(path);
  
  return `    /**
     * ${operation.summary || `Call ${method.toUpperCase()} ${path}`}
     */
    public function ${methodName}(): array
    {
        return \$this->makeRequest('${method.toUpperCase()}', '${path}');
    }`;
}

// Helper functions for generating method names
function getFunctionNameFromPath(path: string): string {
  return path.split('/').filter(Boolean).map((part, index) => 
    index === 0 ? part : part.charAt(0).toUpperCase() + part.slice(1)
  ).join('').replace(/-/g, '');
}

function getPythonMethodNameFromPath(path: string): string {
  return path.split('/').filter(Boolean).join('_').replace(/-/g, '_');
}

function getGoMethodNameFromPath(path: string): string {
  return path.split('/').filter(Boolean).map(part => 
    part.charAt(0).toUpperCase() + part.slice(1)
  ).join('').replace(/-/g, '');
}

function getCurlFunctionNameFromPath(path: string): string {
  return path.split('/').filter(Boolean).join('_').replace(/-/g, '_');
}

function getPHPMethodNameFromPath(path: string): string {
  return path.split('/').filter(Boolean).map((part, index) => 
    index === 0 ? part : part.charAt(0).toUpperCase() + part.slice(1)
  ).join('').replace(/-/g, '');
}

// Version management
export async function createVersionedDocs(spec: any, version: string, outputDir: string): Promise<void> {
  const versionDir = path.join(outputDir, 'versions', version);
  await fs.mkdir(versionDir, { recursive: true });
  
  // Create version-specific documentation
  const versionInfo = {
    version,
    createdAt: new Date().toISOString(),
    spec: {
      title: spec.info?.title,
      version: spec.info?.version,
      description: spec.info?.description
    },
    endpoints: Object.keys(spec.paths || {}),
    schemas: Object.keys(spec.components?.schemas || {})
  };
  
  await fs.writeFile(
    path.join(versionDir, 'version-info.json'),
    JSON.stringify(versionInfo, null, 2)
  );
  
  // Copy specification
  await fs.writeFile(
    path.join(versionDir, 'openapi.json'),
    JSON.stringify(spec, null, 2)
  );
}