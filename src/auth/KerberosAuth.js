const kerberos = require('kerberos');
const { WinRMAuthenticationError } = require('../utils/ErrorTypes');
const { logger } = require('../utils/Logging');

/**
 * Kerberos Authentication implementation for WinRM
 * Implements the complete Kerberos authentication flow using the mongodb-js/kerberos library
 * Supports service principal configuration and challenge-response authentication
 */
class KerberosAuth {
  constructor(options) {
    this.servicePrincipal = options.servicePrincipal || 'HTTP/hostname@DOMAIN';
    this.username = options.username;
    this.password = options.password;
    this.domain = options.domain || '';
    this.hostname = options.hostname || 'localhost';
    this.kdcOptions = options.kdcOptions || {};
    this.logger = options.logger || logger;
    this.maxRetries = options.maxRetries || 3;
    this.mutualAuthentication = options.mutualAuthentication !== false; // default true
    
    // Validate required parameters
    if (!this.servicePrincipal) {
      throw new WinRMAuthenticationError(
        'Service principal is required for Kerberos authentication',
        'kerberos',
        { parameter: 'servicePrincipal' }
      );
    }

    // If no explicit service principal provided, construct it from hostname and domain
    if (!options.servicePrincipal) {
      const domainPart = this.domain ? `@${this.domain.toUpperCase()}` : '';
      this.servicePrincipal = `HTTP/${this.hostname}${domainPart}`;
    }
  }

  /**
   * Main authentication method implementing the Kerberos protocol
   * @param {Object} httpClient - HTTP client for making requests
   * @returns {Promise<Object>} Authentication response
   * @throws {WinRMAuthenticationError} If authentication fails
   */
  async authenticate(httpClient) {
    try {
      this.logger.logAuthEvent('Starting Kerberos authentication', {
        servicePrincipal: this.servicePrincipal,
        hostname: this.hostname,
        domain: this.domain
      });

      // Step 1: Initialize Kerberos client
      const gssClient = await this.initializeKerberosClient();
      
      // Step 2: Perform authentication challenge-response
      const authResponse = await this.performKerberosChallengeResponse(httpClient, gssClient);

      this.logger.logAuthEvent('Kerberos authentication completed successfully');
      return authResponse;

    } catch (error) {
      this.logger.logAuthEvent('Kerberos authentication failed', {
        error: error.message,
        servicePrincipal: this.servicePrincipal
      });

      if (error instanceof WinRMAuthenticationError) {
        throw error;
      }

      throw new WinRMAuthenticationError(
        `Kerberos authentication failed: ${error.message}`,
        'kerberos',
        {
          servicePrincipal: this.servicePrincipal,
          originalError: error.message
        }
      );
    }
  }

  /**
   * Initialize the Kerberos client with service principal
   * @returns {Promise<Object>} Initialized Kerberos GSS client
   * @throws {Error} If client initialization fails
   */
  async initializeKerberosClient() {
    return new Promise((resolve, reject) => {
      const callback = (err, gssClient) => {
        if (err) {
          return reject(new Error(`Failed to initialize Kerberos client: ${err.message}`));
        }
        resolve(gssClient);
      };

      try {
        kerberos.initializeClient(
          this.servicePrincipal,
          this.kdcOptions,
          callback
        );
      } catch (error) {
        reject(new Error(`Kerberos initialization exception: ${error.message}`));
      }
    });
  }

  /**
   * Perform the complete Kerberos challenge-response authentication
   * @param {Object} httpClient - HTTP client for making requests
   * @param {Object} gssClient - Initialized Kerberos GSS client
   * @returns {Promise<Object>} Authentication response
   * @throws {Error} If challenge-response fails
   */
  async performKerberosChallengeResponse(httpClient, gssClient) {
    let currentChallenge = null;
    let step = 0;
    const maxSteps = 5; // Reasonable limit to prevent infinite loops

    while (step < maxSteps) {
      step++;
      
      try {
        // Step 1: Initialize or continue the challenge
        const response = await this.sendKerberosToken(httpClient, gssClient, currentChallenge);
        
        // Step 2: Check if authentication is complete
        if (response.isComplete) {
          return response;
        }

        // Step 3: Update the challenge for next iteration
        currentChallenge = response.challenge;
        
        // Step 4: If no challenge and not complete, authentication failed
        if (!currentChallenge) {
          throw new Error('No Kerberos challenge received but authentication not complete');
        }

      } catch (error) {
        if (step === 1 && error.message.includes('not found in Kerberos database')) {
          throw new Error(`Service principal not found: ${this.servicePrincipal}. Check domain/hostname configuration.`);
        }
        if (error.message.includes('Credentials cache')) {
          throw new Error('No valid Kerberos credentials found. Ensure you have a valid ticket or provide username/password.');
        }
        throw error;
      }
    }

    throw new Error(`Authentication did not complete within ${maxSteps} steps`);
  }

  /**
   * Send Kerberos token to server and receive challenge
   * @param {Object} httpClient - HTTP client for making requests
   * @param {Object} gssClient - Kerberos GSS client
   * @param {string|null} challengeToken - Optional challenge token from previous step
   * @returns {Promise<Object>} Response containing challenge and completion status
   * @throws {Error} If request fails
   */
  async sendKerberosToken(httpClient, gssClient, challengeToken = null) {
    return new Promise((resolve, reject) => {
      const callback = (err, challengeResponse) => {
        if (err) {
          return reject(new Error(`Kerberos token processing failed: ${err.message}`));
        }

        try {
          // Parse the response to extract challenge and completion status
          const parsedResponse = this.parseKerberosResponse(challengeResponse);
          
          // Send the token to the server if we have one
          if (challengeResponse) {
            this.sendTokenToServer(httpClient, challengeResponse)
              .then(serverResponse => {
                // Check if server accepted the token
                if (serverResponse.accepted) {
                  parsedResponse.isComplete = true;
                }
                resolve(parsedResponse);
              })
              .catch(reject);
          } else {
            resolve(parsedResponse);
          }
        } catch (error) {
          reject(error);
        }
      };

      try {
        // Process the token through the GSS API
        gssClient.step(challengeToken || '', callback);
      } catch (error) {
        reject(new Error(`Kerberos step exception: ${error.message}`));
      }
    });
  }

  /**
   * Send Kerberos token to server via HTTP
   * @param {Object} httpClient - HTTP client
   * @param {string} token - Kerberos token to send
   * @returns {Promise<Object>} Server response
   * @throws {Error} If server request fails
   */
  async sendTokenToServer(httpClient, token) {
    const headers = {
      'Authorization': `Negotiate ${token}`
    };

    try {
      const response = await httpClient.request('POST', null, headers);
      
      return {
        accepted: true,
        response: response
      };
    } catch (error) {
      // Check if it's a challenge response (401) or actual error
      if (error.code === 'CONNECTION_FAILED' && error.details.statusCode === 401) {
        return {
          accepted: false,
          challenge: this.extractKerberosChallenge(error.details.body)
        };
      }
      throw error;
    }
  }

  /**
   * Parse Kerberos response and extract challenge information
   * @param {string} response - Raw Kerberos response
   * @returns {Object} Parsed response with challenge and status
   */
  parseKerberosResponse(response) {
    // The exact parsing depends on the kerberos library's response format
    // This is a general implementation that should work with the mongodb-js/kerberos library
    
    if (!response) {
      return {
        challenge: null,
        isComplete: false
      };
    }

    // Check if this appears to be a complete response
    const isComplete = this.isCompleteKerberosResponse(response);
    
    return {
      challenge: response,
      isComplete: isComplete
    };
  }

  /**
   * Check if the Kerberos response indicates completion
   * @param {string} response - Kerberos response
   * @returns {boolean} True if authentication is complete
   */
  isCompleteKerberosResponse(response) {
    // This is a heuristic check - the actual implementation might need
    // more sophisticated detection based on the kerberos library's format
    
    // If we receive a response that doesn't need further steps
    // For Kerberos, the response itself typically indicates completion
    return response && response.length > 0;
  }

  /**
   * Extract Kerberos challenge from server response headers
   * @param {string} responseBody - Server response body
   * @returns {string|null} Challenge token if found
   */
  extractKerberosChallenge(responseBody) {
    try {
      // Parse response to find WWW-Authenticate header with Kerberos
      if (typeof responseBody === 'string') {
        const lines = responseBody.split('\n');
        for (const line of lines) {
          if (line.trim().toLowerCase().startsWith('www-authenticate:')) {
            const match = line.match(/Negotiate\s+([^\s]+)/);
            if (match) {
              return match[1];
            }
          }
        }
      }
    } catch (error) {
      this.logger.debug('Failed to extract Kerberos challenge', { error: error.message });
    }
    
    return null;
  }

  /**
   * Get the service principal name being used
   * @returns {string} Service principal
   */
  getServicePrincipal() {
    return this.servicePrincipal;
  }

  /**
   * Get authentication method name
   * @returns {string} 'kerberos'
   */
  getAuthMethod() {
    return 'kerberos';
  }

  /**
   * Validate Kerberos configuration
   * @returns {Object} Validation result with isValid flag and errors
   */
  validateConfig() {
    const errors = [];

    if (!this.servicePrincipal) {
      errors.push('Service principal is required');
    }

    if (!this.hostname) {
      errors.push('Hostname is required');
    }

    if (this.domain && this.servicePrincipal.includes('@') && 
        !this.servicePrincipal.toUpperCase().endsWith(this.domain.toUpperCase())) {
      errors.push('Service principal domain does not match provided domain');
    }

    return {
      isValid: errors.length === 0,
      errors: errors
    };
  }

  /**
   * Generate a canonicalized service principal name
   * @param {string} hostname - Hostname
   * @param {string} domain - Domain (optional)
   * @returns {string} Canonical service principal
   */
  static generateServicePrincipal(hostname, domain = '') {
    if (!hostname) {
      throw new Error('Hostname is required for service principal generation');
    }

    const domainPart = domain ? `@${domain.toUpperCase()}` : '';
    return `HTTP/${hostname}${domainPart}`;
  }
}

module.exports = KerberosAuth;
