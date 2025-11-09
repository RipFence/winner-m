/**
 * Simple logging utility for WinRM operations
 */

class WinRMLogger {
  constructor(options = {}) {
    this.level = options.level || 'info';
    this.levels = {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
      trace: 4
    };
    this.enabled = {
      error: true,
      warn: true,
      info: true,
      debug: false,
      trace: false
    };
  }

  /**
   * Set logging level
   */
  setLevel(level) {
    this.level = level;
  }

  /**
   * Log error message
   */
  error(message, details = {}) {
    if (this.shouldLog('error')) {
      this.formatLog('ERROR', message, details);
    }
  }

  /**
   * Log warning message
   */
  warn(message, details = {}) {
    if (this.shouldLog('warn')) {
      this.formatLog('WARN', message, details);
    }
  }

  /**
   * Log info message
   */
  info(message, details = {}) {
    if (this.shouldLog('info')) {
      this.formatLog('INFO', message, details);
    }
  }

  /**
   * Log debug message
   */
  debug(message, details = {}) {
    if (this.shouldLog('debug')) {
      this.formatLog('DEBUG', message, details);
    }
  }

  /**
   * Log trace message
   */
  trace(message, details = {}) {
    if (this.shouldLog('trace')) {
      this.formatLog('TRACE', message, details);
    }
  }

  /**
   * Check if a log level should be logged
   */
  shouldLog(level) {
    return this.levels[level] <= this.levels[this.level] && this.enabled[level];
  }

  /**
   * Format and output log message
   */
  formatLog(level, message, details) {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [${level}] ${message}`;
    
    if (Object.keys(details).length > 0) {
      console.log(logMessage, details);
    } else {
      console.log(logMessage);
    }
  }

  /**
   * Log HTTP request/response for debugging
   */
  logHttpRequest(method, url, headers, data) {
    this.debug('HTTP Request', {
      method,
      url,
      headers: this.sanitizeHeaders(headers),
      data: data ? data.substring(0, 500) + (data.length > 500 ? '...' : '') : null
    });
  }

  /**
   * Log HTTP response for debugging
   */
  logHttpResponse(statusCode, headers, data) {
    this.debug('HTTP Response', {
      statusCode,
      headers: this.sanitizeHeaders(headers),
      data: data ? data.substring(0, 500) + (data.length > 500 ? '...' : '') : null
    });
  }

  /**
   * Sanitize headers to remove sensitive information
   */
  sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    if (sanitized.Authorization) {
      sanitized.Authorization = '[REDACTED]';
    }
    if (sanitized['WWW-Authenticate']) {
      sanitized['WWW-Authenticate'] = '[REDACTED]';
    }
    return sanitized;
  }

  /**
   * Log authentication events
   */
  logAuthEvent(event, details = {}) {
    this.info(`Authentication: ${event}`, details);
  }

  /**
   * Log command execution
   */
  logCommand(command, commandId, shellId) {
    this.debug('Command execution', {
      command,
      commandId,
      shellId
    });
  }

  /**
   * Log shell lifecycle events
   */
  logShellEvent(event, shellId) {
    this.debug('Shell lifecycle', {
      event,
      shellId
    });
  }

  /**
   * Log performance metrics
   */
  logPerformance(operation, duration, details = {}) {
    this.debug(`Performance: ${operation}`, {
      duration: `${duration}ms`,
      ...details
    });
  }
}

// Default logger instance
const logger = new WinRMLogger();

module.exports = {
  WinRMLogger,
  logger
};