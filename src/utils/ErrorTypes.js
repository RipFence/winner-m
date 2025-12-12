/* eslint-disable max-classes-per-file */
/**
 * Custom error classes for WinRM operations
 */

/**
 * Base WinRM error class
 */
class WinRMError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'WinRMError';
    this.code = code;
    this.details = details;
    this.timestamp = new Date().toISOString();

    // Maintains proper stack trace for where our error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, WinRMError);
    }
  }

  toString() {
    return `${this.name} [${this.code}]: ${this.message}`;
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      details: this.details,
      timestamp: this.timestamp,
      stack: this.stack,
    };
  }
}

/**
 * Authentication-related errors
 */
class WinRMAuthenticationError extends WinRMError {
  constructor(message, authMethod, details = {}) {
    super(message, 'AUTHENTICATION_FAILED', {
      authMethod,
      ...details,
    });
    this.name = 'WinRMAuthenticationError';
  }
}

/**
 * Connection-related errors
 */
class WinRMConnectionError extends WinRMError {
  constructor(message, cause, details = {}) {
    super(message, 'CONNECTION_FAILED', {
      cause,
      ...details,
    });
    this.name = 'WinRMConnectionError';
  }
}

/**
 * Command execution errors
 */
class WinRMCommandError extends WinRMError {
  constructor(message, command, exitCode, stdout = '', stderr = '', details = {}) {
    super(message, 'COMMAND_FAILED', {
      command,
      exitCode,
      stdout,
      stderr,
      ...details,
    });
    this.name = 'WinRMCommandError';
  }
}

/**
 * Configuration errors
 */
class WinRMConfigurationError extends WinRMError {
  constructor(message, parameter, details = {}) {
    super(message, 'CONFIGURATION_ERROR', {
      parameter,
      ...details,
    });
    this.name = 'WinRMConfigurationError';
  }
}

/**
 * Protocol errors (SOAP, XML parsing, etc.)
 */
class WinRMProtocolError extends WinRMError {
  constructor(message, operation, details = {}) {
    super(message, 'PROTOCOL_ERROR', {
      operation,
      ...details,
    });
    this.name = 'WinRMProtocolError';
  }
}

/**
 * Timeout errors
 */
class WinRMTimeoutError extends WinRMError {
  constructor(message, timeoutType, details = {}) {
    super(message, 'TIMEOUT', {
      timeoutType,
      ...details,
    });
    this.name = 'WinRMTimeoutError';
  }
}

/**
 * SSL/TLS certificate errors
 */
class WinRMSslError extends WinRMError {
  constructor(message, certificate, details = {}) {
    super(message, 'SSL_ERROR', {
      certificate,
      ...details,
    });
    this.name = 'WinRMSslError';
  }
}

module.exports = {
  WinRMError,
  WinRMAuthenticationError,
  WinRMConnectionError,
  WinRMCommandError,
  WinRMConfigurationError,
  WinRMProtocolError,
  WinRMTimeoutError,
  WinRMSslError,
};
