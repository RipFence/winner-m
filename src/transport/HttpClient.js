const https = require('https');
const http = require('http');
const { WinRMConnectionError, WinRMTimeoutError, WinRMProtocolError } = require('../utils/ErrorTypes.js');
const { logger } = require('../utils/Logging.js');

/**
 * HTTP client for WinRM connections with connection pooling and persistent connections
 */
class HttpClient {
  constructor(options) {
    this.options = options;
    this.baseURL = `${options.protocol}://${options.host}:${options.port}`;
    this.path = options.path || '/wsman';
    this.timeout = options.timeouts?.connectTimeout || 30000;
    this.keepAlive = true;

    // Configure SSL/TLS options
    this.sslOptions = this.buildSSLOptions(options.ssl || {});

    // Create HTTP agent for connection pooling
    this.agent = this.createAgent();

    // Connection tracking
    this.activeConnections = 0;
    this.maxConnections = options.maxConnections || 10;
  }

  /**
   * Build SSL/TLS configuration
   */
  buildSSLOptions(sslConfig) {
    return {
      rejectUnauthorized: sslConfig.rejectUnauthorized !== false,
      ca: sslConfig.ca,
      cert: sslConfig.cert,
      key: sslConfig.key,
      passphrase: sslConfig.passphrase,
      servername: this.options.host,
    };
  }

  /**
   * Create HTTP agent with connection pooling
   */
  createAgent() {
    if (this.options.protocol === 'https') {
      return new https.Agent({
        keepAlive: this.keepAlive,
        keepAliveMsecs: 60000,
        maxFreeSockets: 5,
        maxSockets: this.maxConnections,
        timeout: this.timeout,
        ...this.sslOptions,
      });
    }
    return new http.Agent({
      keepAlive: this.keepAlive,
      keepAliveMsecs: 60000,
      maxFreeSockets: 5,
      maxSockets: this.maxConnections,
      timeout: this.timeout,
    });
  }

  /**
   * Perform HTTP request with retry logic
   */
  async request(method, data = null, headers = {}, retryCount = 0) {
    const requestOptions = {
      method,
      path: this.path,
      headers: {
        'Content-Type': 'application/soap+xml; charset=UTF-8',
        'User-Agent': 'JS-WinRM/1.0',
        Connection: this.keepAlive ? 'keep-alive' : 'close',
        ...headers,
      },
      timeout: this.options.timeouts?.readTimeout || 60000,
      agent: this.agent,
    };

    const requestStart = Date.now();

    try {
      logger.logHttpRequest(method, `${this.baseURL}${this.path}`, requestOptions.headers, data);

      const response = await this.performRequest(requestOptions, data);
      const responseData = await HttpClient.readResponse(response);

      const responseTime = Date.now() - requestStart;
      logger.logPerformance('HTTP Request', responseTime, {
        method,
        statusCode: response.statusCode,
      });

      // Check for authentication challenges
      if (response.statusCode === 401) {
        const authHeader = response.headers['www-authenticate'];
        if (authHeader && authHeader.includes('NTLM')) {
          throw new WinRMProtocolError('NTLM authentication required', 'AUTHENTICATION_CHALLENGE', {
            authHeader,
          });
        }
      }

      // Check for other error status codes
      if (response.statusCode >= 400) {
        throw new WinRMConnectionError(
          `HTTP ${response.statusCode}: ${response.statusMessage}`,
          null,
          { statusCode: response.statusCode, statusMessage: response.statusMessage, body: responseData },
        );
      }

      logger.logHttpResponse(response.statusCode, response.headers, responseData);
      return responseData;
    } catch (error) {
      // Handle timeout errors
      if (error.code === 'ETIMEDOUT' || error.code === 'ESOCKETTIMEDOUT') {
        throw new WinRMTimeoutError('Connection timeout', 'CONNECT_TIMEOUT', {
          timeout: this.timeout,
          method,
          url: `${this.baseURL}${this.path}`,
        });
      }

      // Handle connection errors
      if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
        throw new WinRMConnectionError(
          `Connection failed: ${error.message}`,
          error.code,
          {
            host: this.options.host,
            port: this.options.port,
            protocol: this.options.protocol,
          },
        );
      }

      // Re-throw WinRM-specific errors
      if (error instanceof WinRMTimeoutError
          || error instanceof WinRMConnectionError
          || error instanceof WinRMProtocolError) {
        throw error;
      }

      // Handle other errors with retry logic
      if (retryCount < (this.options.retries?.maxRetries || 3) && this.isRetryableError(error)) {
        const delay = this.options.retries?.retryDelay || 1000 * 2 ** retryCount;
        logger.warn(`Retrying request in ${delay}ms (attempt ${retryCount + 1})`, { error: error.message });
        await HttpClient.delay(delay);
        return this.request(method, data, headers, retryCount + 1);
      }

      // Create generic connection error
      throw new WinRMConnectionError(
        `HTTP request failed: ${error.message}`,
        error.code,
        { method, url: `${this.baseURL}${this.path}` },
      );
    }
  }

  /**
   * Perform the actual HTTP request
   */
  performRequest(options, data = null) {
    return new Promise((resolve, reject) => {
      const client = this.options.protocol === 'https' ? https : http;

      this.activeConnections += 1;

      const req = client.request(options, (res) => {
        this.activeConnections -= 1;
        resolve(res);
      });

      req.on('error', (error) => {
        this.activeConnections -= 1;
        reject(error);
      });

      req.on('timeout', () => {
        this.activeConnections -= 1;
        req.destroy();
        const timeoutError = new Error('Request timeout');
        timeoutError.code = 'ETIMEDOUT';
        reject(timeoutError);
      });

      if (data) {
        req.write(data);
      }

      req.end();
    });
  }

  /**
   * Read and buffer response data
   */
  static readResponse(response) {
    return new Promise((resolve, reject) => {
      let data = '';

      response.on('data', (chunk) => {
        data += chunk;
      });

      response.on('end', () => {
        resolve(data);
      });

      response.on('error', (error) => {
        reject(error);
      });
    });
  }

  /**
   * Check if error is retryable
   */
  isRetryableError(error) {
    // Retry on connection errors and temporary HTTP errors
    const maxRetries = this.options.retries?.maxRetries || 3;
    return (error.code === 'ECONNRESET'
           || error.code === 'ECONNABORTED'
           || (error.statusCode >= 500 && error.statusCode < 600))
           && maxRetries > 0;
  }

  /**
   * Delay utility
   */
  static delay(ms) {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  }

  /**
   * Get connection statistics
   */
  getConnectionStats() {
    return {
      activeConnections: this.activeConnections,
      maxConnections: this.maxConnections,
      keepAlive: this.keepAlive,
    };
  }

  /**
   * Close all connections
   */
  async close() {
    if (this.agent) {
      await this.agent.destroy();
      this.agent = null;
    }
  }

  /**
   * Check if connected and responsive
   */
  async ping() {
    try {
      await this.request('GET');
      return true;
    } catch (error) {
      return false;
    }
  }
}

module.exports = HttpClient;
