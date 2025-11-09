const { WinRMConfigurationError } = require('../utils/ErrorTypes');
const { logger } = require('../utils/Logging');
const KerberosAuth = require('./KerberosAuth');
const CredSSPAuth = require('./CredSSPAuth');

/**
 * Authentication manager for WinRM
 * Handles different authentication methods and orchestrates the authentication process
 */
class AuthManager {
  constructor(options) {
    this.options = options;
    this.authMethods = new Map();
    this.defaultMethod = this.validateAndGetDefaultMethod();
    this.initializeAuthMethods();
  }

  /**
   * Validate configuration and determine default authentication method
   */
  validateAndGetDefaultMethod() {
    if (!this.options.auth) {
      throw new WinRMConfigurationError('Authentication configuration is required', 'auth');
    }

    const { type, username, password } = this.options.auth;
    
    if (!type) {
      throw new WinRMConfigurationError('Authentication type is required', 'auth.type');
    }

    if (!username || !password) {
      throw new WinRMConfigurationError('Username and password are required for authentication', 'auth.credentials');
    }

    return type;
  }

  /**
   * Initialize available authentication methods
   */
  initializeAuthMethods() {
    // Initialize NTLM authentication
    this.authMethods.set('ntlm', this.createNTLMAuth());
    
    // Initialize Basic authentication (optional)
    if (this.options.protocol === 'https') {
      this.authMethods.set('basic', this.createBasicAuth());
    } else {
      logger.warn('Basic authentication is only available over HTTPS. Skipping Basic auth initialization.');
    }
    
    // Initialize Kerberos authentication
    this.authMethods.set('kerberos', this.createKerberosAuth());
    
    // Initialize CredSSP authentication
    this.authMethods.set('credssp', this.createCredSSPAuth());
  }

  /**
   * Create NTLM authentication instance
   */
  createNTLMAuth() {
    const NTLMAuth = require('./NTLMAuth');
    
    return new NTLMAuth({
      domain: this.options.auth.domain || '',
      username: this.options.auth.username,
      password: this.options.auth.password,
      workstation: this.options.auth.workstation || 'JS-WinRM-CLIENT',
      logger: logger
    });
  }

  /**
   * Create Basic authentication instance
   */
  createBasicAuth() {
    const BasicAuth = require('./BasicAuth');
    
    return new BasicAuth({
      username: this.options.auth.username,
      password: this.options.auth.password,
      logger: logger
    });
  }

  /**
   * Create Kerberos authentication instance
   */
  createKerberosAuth() {
    return new KerberosAuth({
      username: this.options.auth.username,
      password: this.options.auth.password,
      domain: this.options.auth.domain || '',
      kdc: this.options.auth.kdc || '',
      logger: logger
    });
  }

  /**
   * Create CredSSP authentication instance
   */
  createCredSSPAuth() {
    return new CredSSPAuth({
      username: this.options.auth.username,
      password: this.options.auth.password,
      domain: this.options.auth.domain || '',
      logger: logger
    });
  }

  /**
   * Perform authentication using the specified or default method
   */
  async authenticate(httpClient, method = this.defaultMethod) {
    logger.info(`Starting authentication with method: ${method}`);

    const authMethod = this.authMethods.get(method);
    if (!authMethod) {
      throw new WinRMConfigurationError(
        `Unsupported authentication method: ${method}. Available methods: ${Array.from(this.authMethods.keys()).join(', ')}`,
        'auth.method'
      );
    }

    try {
      const result = await authMethod.authenticate(httpClient);
      logger.info(`Authentication completed successfully using ${method}`);
      return result;
    } catch (error) {
      logger.error(`Authentication failed with method ${method}`, { error: error.message });
      throw error;
    }
  }

  /**
   * Get available authentication methods
   */
  getAvailableMethods() {
    return Array.from(this.authMethods.keys());
  }

  /**
   * Check if a specific authentication method is available
   */
  isMethodAvailable(method) {
    return this.authMethods.has(method);
  }

  /**
   * Get the default authentication method
   */
  getDefaultMethod() {
    return this.defaultMethod;
  }

  /**
   * Validate authentication configuration
   */
  validateConfiguration() {
    const errors = [];

    // Check basic configuration
    if (!this.options.auth) {
      errors.push('Authentication configuration is required');
      return errors;
    }

    const { type, username, password } = this.options.auth;

    if (!type) {
      errors.push('Authentication type is required');
    }

    if (!username) {
      errors.push('Username is required');
    }

    if (!password) {
      errors.push('Password is required');
    }

    // Check method-specific requirements
    if (type === 'basic' && this.options.protocol !== 'https') {
      errors.push('Basic authentication requires HTTPS');
    }

    if (type === 'ntlm') {
      // Additional NTLM-specific validation
      if (this.options.auth.domain && this.options.auth.domain.length === 0) {
        logger.warn('Empty domain specified for NTLM authentication. Using local account authentication.');
      }
    }

    if (type === 'kerberos') {
      // Additional Kerberos-specific validation
      if (this.options.auth.domain && this.options.auth.domain.length === 0) {
        logger.warn('Empty domain specified for Kerberos authentication. This may cause authentication issues.');
      }
      
      if (this.options.auth.kdc) {
        logger.info(`Using custom KDC: ${this.options.auth.kdc}`);
      }
    }

    if (type === 'credssp') {
      // Additional CredSSP-specific validation
      if (this.options.auth.domain && this.options.auth.domain.length === 0) {
        logger.warn('Empty domain specified for CredSSP authentication. Using local account authentication.');
      }
    }

    return errors;
  }

  /**
   * Get authentication info for logging (without sensitive data)
   */
  getAuthInfo() {
    return {
      method: this.defaultMethod,
      availableMethods: this.getAvailableMethods(),
      username: this.options.auth.username,
      domain: this.options.auth.domain || '',
      workstation: this.options.auth.workstation || ''
    };
  }

  /**
   * Test authentication with different methods
   */
  async testAuthentication(httpClient) {
    const results = {};
    
    for (const [method, authInstance] of this.authMethods) {
      try {
        logger.info(`Testing authentication with method: ${method}`);
        const startTime = Date.now();
        await authInstance.authenticate(httpClient);
        const duration = Date.now() - startTime;
        
        results[method] = {
          success: true,
          duration: duration
        };
        
        logger.info(`Authentication test successful for method: ${method} (${duration}ms)`);
      } catch (error) {
        results[method] = {
          success: false,
          error: error.message
        };
        
        logger.error(`Authentication test failed for method: ${method}`, { error: error.message });
      }
    }
    
    return results;
  }
}

module.exports = AuthManager;