const { WinRMProtocolError, WinRMConnectionError, WinRMAuthenticationError, WinRMTimeoutError } = require('./utils/ErrorTypes');
const { logger } = require('./utils/Logging');
const HttpClient = require('./transport/HttpClient');
const AuthManager = require('./auth/AuthManager');
const XMLUtils = require('./utils/XMLUtils');

/**
 * Low-level WinRM Protocol class
 * Provides direct access to WinRM operations (shell lifecycle, command execution)
 * Similar to pywinrm's Protocol class
 */
class Protocol {
  constructor(options) {
    this.options = this.validateOptions(options);
    this.httpClient = new HttpClient(this.options);
    this.authManager = new AuthManager(this.options);
    this.shellId = null;
    this.isConnected = false;
    this.authenticated = false;
    
    logger.info('WinRM Protocol initialized', {
      host: this.options.host,
      port: this.options.port,
      protocol: this.options.protocol,
      auth: this.authManager.getAuthInfo()
    });
  }

  /**
   * Validate and normalize options
   */
  validateOptions(options) {
    const requiredFields = ['host', 'auth'];
    for (const field of requiredFields) {
      if (!options[field]) {
        throw new WinRMProtocolError(`Required option missing: ${field}`, 'OPTIONS_VALIDATION', {
          field
        });
      }
    }

    return {
      host: options.host,
      port: options.port || (options.protocol === 'https' ? 5986 : 5985),
      protocol: options.protocol || 'https',
      path: options.path || '/wsman',
      auth: {
        type: options.auth.type || 'ntlm',
        username: options.auth.username,
        password: options.auth.password,
        domain: options.auth.domain || '',
        workstation: options.auth.workstation || 'JS-WINRM-CLIENT'
      },
      ssl: options.ssl || { rejectUnauthorized: true },
      timeouts: {
        connectTimeout: options.timeouts?.connectTimeout || 30000,
        readTimeout: options.timeouts?.readTimeout || 60000,
        operationTimeout: options.timeouts?.operationTimeout || 60000
      },
      retries: {
        maxRetries: options.retries?.maxRetries || 3,
        retryDelay: options.retries?.retryDelay || 1000
      },
      maxConnections: options.maxConnections || 10
    };
  }

  /**
   * Open a WinRM shell
   */
  async openShell() {
    if (this.isConnected) {
      logger.warn('Shell already open, ignoring openShell call');
      return;
    }

    const startTime = Date.now();
    logger.logShellEvent('Opening shell', null);

    try {
      // First, authenticate if not already done
      if (!this.authenticated) {
        await this.authenticate();
      }

      // Create the shell
      const shellRequest = XMLUtils.buildCreateShell();
      const response = await this.httpClient.request('POST', shellRequest);
      
      // Parse response to get shell ID
      const shellId = await XMLUtils.parseCreateShellResponse(response);
      
      this.shellId = shellId;
      this.isConnected = true;
      
      const duration = Date.now() - startTime;
      logger.logShellEvent('Shell opened successfully', shellId);
      logger.logPerformance('openShell', duration, { shellId });

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.logShellEvent('Shell opening failed', null, { error: error.message, duration });
      
      if (error instanceof WinRMAuthenticationError || 
          error instanceof WinRMConnectionError || 
          error instanceof WinRMTimeoutError) {
        throw error;
      }
      
      throw new WinRMProtocolError(
        `Failed to open shell: ${error.message}`,
        'OPEN_SHELL',
        { duration, originalError: error.message }
      );
    }
  }

  /**
   * Close the WinRM shell
   */
  async closeShell() {
    if (!this.isConnected) {
      logger.warn('No shell to close, ignoring closeShell call');
      return;
    }

    const startTime = Date.now();
    logger.logShellEvent('Closing shell', this.shellId);

    try {
      const closeRequest = XMLUtils.buildCloseShell(this.shellId);
      await this.httpClient.request('POST', closeRequest);
      
      const duration = Date.now() - startTime;
      logger.logShellEvent('Shell closed successfully', this.shellId);
      logger.logPerformance('closeShell', duration);

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.logShellEvent('Shell closing failed', this.shellId, { error: error.message, duration });
      
      // Don't throw on close failures, just log them
      logger.warn('Shell close operation failed, but continuing cleanup', {
        error: error.message,
        duration
      });
    } finally {
      this.isConnected = false;
      this.shellId = null;
    }
  }

  /**
   * Run a command in the current shell
   */
  async runCommand(command, args = '') {
    if (!this.isConnected) {
      throw new WinRMProtocolError('Shell must be opened before running commands', 'RUN_COMMAND');
    }

    const fullCommand = args ? `${command} ${args}` : command;
    const startTime = Date.now();
    
    logger.logCommand(fullCommand, null, this.shellId);

    try {
      const runRequest = XMLUtils.buildRunCommand(this.shellId, fullCommand);
      const response = await this.httpClient.request('POST', runRequest);
      
      const commandId = await XMLUtils.parseRunCommandResponse(response);
      
      const duration = Date.now() - startTime;
      logger.logCommand(fullCommand, commandId, this.shellId);
      logger.logPerformance('runCommand', duration, { commandId });

      return commandId;

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.logCommand(fullCommand, null, this.shellId, { error: error.message, duration });
      
      if (error instanceof WinRMConnectionError || 
          error instanceof WinRMTimeoutError) {
        throw error;
      }
      
      throw new WinRMProtocolError(
        `Failed to run command '${fullCommand}': ${error.message}`,
        'RUN_COMMAND',
        { command: fullCommand, duration, originalError: error.message }
      );
    }
  }

  /**
   * Get output from a running command
   */
  async getCommandOutput(commandId) {
    if (!this.isConnected) {
      throw new WinRMProtocolError('Shell must be opened to get command output', 'GET_OUTPUT');
    }

    const startTime = Date.now();

    try {
      const outputRequest = XMLUtils.buildGetCommandOutput(this.shellId, commandId);
      const response = await this.httpClient.request('POST', outputRequest);
      
      // Check for faults in the response
      await XMLUtils.checkForFault(response);
      
      const output = await XMLUtils.parseCommandOutputResponse(response);
      
      const duration = Date.now() - startTime;
      logger.logPerformance('getCommandOutput', duration, { commandId, hasOutput: !!output.stdout });

      return output;

    } catch (error) {
      const duration = Date.now() - startTime;
      
      if (error instanceof WinRMConnectionError || 
          error instanceof WinRMTimeoutError) {
        throw error;
      }
      
      throw new WinRMProtocolError(
        `Failed to get command output for command ${commandId}: ${error.message}`,
        'GET_OUTPUT',
        { commandId, duration, originalError: error.message }
      );
    }
  }

  /**
   * Clean up a command
   */
  async cleanupCommand(commandId) {
    if (!this.isConnected) {
      throw new WinRMProtocolError('Shell must be opened to cleanup commands', 'CLEANUP_COMMAND');
    }

    const startTime = Date.now();

    try {
      const cleanupRequest = XMLUtils.buildDeleteCommand(this.shellId, commandId);
      await this.httpClient.request('POST', cleanupRequest);
      
      const duration = Date.now() - startTime;
      logger.logPerformance('cleanupCommand', duration, { commandId });

    } catch (error) {
      const duration = Date.now() - startTime;
      
      // Don't throw on cleanup failures, just log them
      logger.warn(`Command cleanup failed for command ${commandId}`, {
        error: error.message,
        duration
      });
    }
  }

  /**
   * Wait for command to complete and return output
   */
  async waitForCommand(commandId, pollInterval = 1000) {
    const startTime = Date.now();
    let attempts = 0;

    while (attempts * pollInterval < this.options.timeouts.operationTimeout) {
      try {
        const output = await this.getCommandOutput(commandId);
        
        // Check if command has completed (exitCode !== null typically indicates completion)
        if (output.exitCode !== null && output.exitCode !== undefined) {
          return output;
        }
      } catch (error) {
        // Continue polling on transient errors
        if (!(error instanceof WinRMConnectionError)) {
          throw error;
        }
      }

      await this.delay(pollInterval);
      attempts++;
    }

    throw new WinRMTimeoutError(
      `Command ${commandId} did not complete within operation timeout`,
      'OPERATION_TIMEOUT',
      { commandId, timeout: this.options.timeouts.operationTimeout, attempts }
    );
  }

  /**
   * Execute command and wait for completion
   */
  async runCommandAndWait(command, args = '', pollInterval = 1000) {
    const commandId = await this.runCommand(command, args);
    return await this.waitForCommand(commandId, pollInterval);
  }

  /**
   * Perform authentication
   */
  async authenticate() {
    if (this.authenticated) {
      return;
    }

    const startTime = Date.now();
    logger.info('Starting WinRM authentication');

    try {
      await this.authManager.authenticate(this.httpClient);
      this.authenticated = true;
      
      const duration = Date.now() - startTime;
      logger.info('WinRM authentication completed', { duration });
      logger.logPerformance('authentication', duration);

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('WinRM authentication failed', { error: error.message, duration });
      
      if (error instanceof WinRMAuthenticationError) {
        throw error;
      }
      
      throw new WinRMAuthenticationError(
        `Authentication failed: ${error.message}`,
        this.options.auth.type,
        { duration, originalError: error.message }
      );
    }
  }

  /**
   * Check if connected
   */
  isShellOpen() {
    return this.isConnected && this.shellId !== null;
  }

  /**
   * Get connection status
   */
  getStatus() {
    return {
      connected: this.isConnected,
      authenticated: this.authenticated,
      shellId: this.shellId,
      options: {
        host: this.options.host,
        port: this.options.port,
        protocol: this.options.protocol
      },
      auth: this.authManager.getAuthInfo(),
      httpClient: this.httpClient.getConnectionStats()
    };
  }

  /**
   * Test connectivity to the WinRM endpoint
   */
  async ping() {
    try {
      // Try to authenticate and open a shell
      await this.authenticate();
      await this.openShell();
      await this.closeShell();
      return true;
    } catch (error) {
      logger.warn('WinRM connectivity test failed', { error: error.message });
      return false;
    }
  }

  /**
   * Clean up resources
   */
  async close() {
    try {
      if (this.isConnected) {
        await this.closeShell();
      }
      await this.httpClient.close();
    } catch (error) {
      logger.warn('Error during cleanup', { error: error.message });
    }
  }

  /**
   * Utility function for delays
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = Protocol;