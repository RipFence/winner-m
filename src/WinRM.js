/**
 * Main library entry point for winner-m (Windows Remote Management for JavaScript)
 * Provides easy access to Session, Protocol, and authentication classes
 */

const Session = require('./Session');
const Protocol = require('./Protocol');
const AuthManager = require('./auth/AuthManager');

// Version information
const VERSION = '1.1.0';

// Error classes
const {
  WinRMError,
  WinRMAuthenticationError,
  WinRMConnectionError,
  WinRMCommandError,
  WinRMConfigurationError,
  WinRMProtocolError,
  WinRMTimeoutError,
  WinRMSslError
} = require('./utils/ErrorTypes');

/**
 * winner-m main class factory
 * Provides comprehensive Windows Remote Management capabilities
 */
class WinRM {
  /**
   * Create a new Session instance
   */
  static createSession(options) {
    return new Session(options);
  }

  /**
   * Create a new Protocol instance
   */
  static createProtocol(options) {
    return new Protocol(options);
  }

  /**
   * Create a new Authentication Manager
   */
  static createAuthManager(options) {
    return new AuthManager(options);
  }

  /**
   * Create NTLM authentication instance
   * @param {Object} credentials - NTLM authentication credentials
   * @param {string} credentials.username - Username
   * @param {string} credentials.password - Password
   * @param {string} credentials.domain - Domain (optional)
   * @param {string} credentials.workstation - Workstation name (optional)
   */
  static createNTLMAuth(credentials) {
    const NTLMAuth = require('./auth/NTLMAuth');
    return new NTLMAuth(credentials);
  }

  /**
   * Create Basic authentication instance
   * @param {Object} credentials - Basic authentication credentials
   * @param {string} credentials.username - Username
   * @param {string} credentials.password - Password
   */
  static createBasicAuth(credentials) {
    const BasicAuth = require('./auth/BasicAuth');
    return new BasicAuth(credentials);
  }

  /**
   * Create Kerberos authentication instance (TBD - to be implemented)
   * @param {Object} credentials - Kerberos authentication credentials
   * @param {string} credentials.username - Username
   * @param {string} credentials.password - Password
   * @param {string} credentials.realm - Kerberos realm
   * @param {string} credentials.kdc - Key Distribution Center
   */
  static createKerberosAuth(credentials) {
    throw new WinRMError('Kerberos authentication is not yet implemented. This is a placeholder for future development.', 'NOT_IMPLEMENTED');
  }

  /**
   * Create Certificate authentication instance (TBD - to be implemented)
   * @param {Object} credentials - Certificate authentication credentials
   * @param {string} credentials.certPath - Path to client certificate
   * @param {string} credentials.keyPath - Path to private key
   * @param {string} credentials.passphrase - Certificate passphrase (optional)
   */
  static createCertificateAuth(credentials) {
    throw new WinRMError('Certificate authentication is not yet implemented. This is a placeholder for future development.', 'NOT_IMPLEMENTED');
  }

  /**
   * Create OAuth authentication instance (TBD - to be implemented)
   * @param {Object} credentials - OAuth authentication credentials
   * @param {string} credentials.token - OAuth access token
   * @param {string} credentials.provider - OAuth provider
   */
  static createOAuthAuth(credentials) {
    throw new WinRMError('OAuth authentication is not yet implemented. This is a placeholder for future development.', 'NOT_IMPLEMENTED');
  }

  /**
   * Quick connect to a Windows host
   */
  static async connect(options) {
    const session = new Session(options);
    await session.test();
    return session;
  }

  /**
   * Execute a single command on a Windows host
   */
  static async runCommand(options, command) {
    const session = new Session(options);
    try {
      const result = await session.run(command);
      return result;
    } finally {
      await session.close();
    }
  }

  /**
   * Execute a PowerShell script on a Windows host
   */
  static async runPowerShell(options, script) {
    const session = new Session(options);
    try {
      const result = await session.runPS(script);
      return result;
    } finally {
      await session.close();
    }
  }
}

// Utility functions
/**
 * Validate WinRM configuration
 */
function validateConfig(options) {
  const errors = [];

  if (!options) {
    errors.push('Configuration object is required');
    return errors;
  }

  if (!options.host) {
    errors.push('Host is required');
  }

  if (!options.auth) {
    errors.push('Authentication configuration is required');
  } else {
    if (!options.auth.username) {
      errors.push('Username is required in auth configuration');
    }
    if (!options.auth.password) {
      errors.push('Password is required in auth configuration');
    }
  }

  return errors;
}

/**
 * Test connection to a Windows host
 */
async function testConnection(options) {
  try {
    const session = new Session(options);
    const result = await session.ping();
    await session.close();
    return result;
  } catch (error) {
    return false;
  }
}

// Export the main components
module.exports = {
  // Main library export as 'winner-m'
  'winner-m': WinRM,

  // Main classes
  WinRM,
  Session,
  Protocol,
  AuthManager,

  // Authentication method factories
  createNTLMAuth: WinRM.createNTLMAuth,
  createBasicAuth: WinRM.createBasicAuth,
  createKerberosAuth: WinRM.createKerberosAuth,
  createCertificateAuth: WinRM.createCertificateAuth,
  createOAuthAuth: WinRM.createOAuthAuth,

  // Utility functions
  validateConfig,
  testConnection,
  createAuthManager: WinRM.createAuthManager,

  // Version
  VERSION,

  // Error classes for easy import
  WinRMError,
  WinRMAuthenticationError,
  WinRMConnectionError,
  WinRMCommandError,
  WinRMConfigurationError,
  WinRMProtocolError,
  WinRMTimeoutError,
  WinRMSslError
};