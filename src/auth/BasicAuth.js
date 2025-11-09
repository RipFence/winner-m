const { WinRMAuthenticationError } = require('../utils/ErrorTypes');
const { logger } = require('../utils/Logging');

/**
 * Basic authentication for WinRM (only for HTTPS connections)
 * Should only be used when NTLM is not available
 */
class BasicAuth {
  constructor(options) {
    this.username = options.username;
    this.password = options.password;
    this.logger = options.logger || logger;
    
    if (!this.username || !this.password) {
      throw new WinRMAuthenticationError('Username and password are required for Basic authentication', 'basic', {
        parameter: 'credentials'
      });
    }
  }

  /**
   * Perform basic authentication
   */
  async authenticate(httpClient) {
    try {
      logger.logAuthEvent('Starting Basic authentication', {
        username: this.username
      });

      const authHeader = this.buildBasicAuthHeader();
      const headers = { 'Authorization': authHeader };

      // Test authentication with a simple request
      await httpClient.request('POST', null, headers);
      
      logger.logAuthEvent('Basic authentication completed successfully');
      return true;

    } catch (error) {
      logger.logAuthEvent('Basic authentication failed', { error: error.message });
      
      throw new WinRMAuthenticationError(
        `Basic authentication failed: ${error.message}`,
        'basic',
        { originalError: error.message }
      );
    }
  }

  /**
   * Build Basic authentication header
   */
  buildBasicAuthHeader() {
    const credentials = Buffer.from(`${this.username}:${this.password}`).toString('base64');
    return `Basic ${credentials}`;
  }
}

module.exports = BasicAuth;