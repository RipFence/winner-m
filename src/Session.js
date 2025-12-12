const { WinRMCommandError, WinRMProtocolError } = require('./utils/ErrorTypes.js');
const { logger } = require('./utils/Logging.js');
const Protocol = require('./protocol.js');

/**
 * High-level WinRM Session class
 * Provides a simplified interface for command execution and PowerShell remoting
 * Similar to pywinrm's Session class
 */
class Session {
  constructor(options) {
    this.options = Session.normalizeSessionOptions(options);
    this.protocol = new Protocol(this.options);
    this.defaultCommandOptions = {
      workingDirectory: this.options.workingDirectory,
      environmentVars: this.options.environmentVars,
      operationTimeout: this.options.timeouts?.operationTimeout,
      readTimeout: this.options.timeouts?.readTimeout,
    };

    logger.info('WinRM Session initialized', {
      host: this.options.host,
      port: this.options.port,
      protocol: this.options.protocol,
      auth: this.protocol.authManager.getAuthInfo(),
    });
  }

  /**
   * Normalize session options and set defaults
   */
  static normalizeSessionOptions(options) {
    const baseOptions = {
      host: options.host,
      port: options.port || (options.protocol === 'https' ? 5986 : 5985),
      protocol: options.protocol || 'https',
      path: '/wsman',
      auth: {
        type: options.auth.type || 'ntlm',
        username: options.auth.username,
        password: options.auth.password,
        domain: options.auth.domain || '',
        workstation: options.auth.workstation || 'JS-WINRM-SESSION',
      },
      ssl: {
        rejectUnauthorized: options.ssl?.rejectUnauthorized !== false,
        ca: options.ssl?.ca,
        cert: options.ssl?.cert,
        key: options.ssl?.key,
        passphrase: options.ssl?.passphrase,
      },
      timeouts: {
        connectTimeout: options.timeouts?.connectTimeout || 30000,
        readTimeout: options.timeouts?.readTimeout || 60000,
        operationTimeout: options.timeouts?.operationTimeout || 300000, // 5 minutes default for PowerShell
      },
      retries: {
        maxRetries: options.retries?.maxRetries || 3,
        retryDelay: options.retries?.retryDelay || 1000,
      },
      workingDirectory: options.workingDirectory || 'C:\\',
      environmentVars: options.environmentVars || {},
      maxShellTime: options.maxShellTime || 3600, // 1 hour default
      maxConnections: options.maxConnections || 10,
    };

    return baseOptions;
  }

  /**
   * Run a command on the remote Windows host
   */
  async run(command, options = {}) {
    const runOptions = { ...this.defaultCommandOptions, ...options };
    const startTime = Date.now();

    logger.info('Session.run command', {
      command,
      workingDirectory: runOptions.workingDirectory,
      envVars: Object.keys(runOptions.environmentVars || {}),
    });

    try {
      // Ensure we have a shell open
      if (!this.protocol.isShellOpen()) {
        await this.protocol.openShell();
      }

      // Build the complete command with working directory and environment
      const completeCommand = this.buildCompleteCommand(command, runOptions);

      // Execute command and wait for completion
      const result = await this.protocol.runCommandAndWait('cmd.exe', `/c ${completeCommand}`);

      const duration = Date.now() - startTime;
      logger.info('Session.run completed', {
        command,
        exitCode: result.exitCode,
        duration,
        stdoutLength: result.stdout.length,
        stderrLength: result.stderr.length,
      });
      logger.logPerformance('session.run', duration, { command, exitCode: result.exitCode });

      return Session.formatResult(result, startTime);
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Session.run failed', {
        command,
        error: error.message,
        duration,
      });

      if (error instanceof WinRMCommandError || error instanceof WinRMProtocolError) {
        throw error;
      }

      throw new WinRMCommandError(
        `Command execution failed: ${error.message}`,
        command,
        1, // Generic exit code for failures
        '',
        error.message,
        { duration, originalError: error.message },
      );
    }
  }

  /**
   * Run a PowerShell script on the remote Windows host
   */
  async runPS(powerShellScript, options = {}) {
    const psOptions = { ...this.defaultCommandOptions, ...options };
    const startTime = Date.now();

    logger.info('Session.runPS', {
      scriptLength: powerShellScript.length,
      workingDirectory: psOptions.workingDirectory,
    });

    try {
      // Ensure we have a shell open
      if (!this.protocol.isShellOpen()) {
        await this.protocol.openShell();
      }

      // Encode PowerShell script for safe transmission
      const encodedScript = Session.encodePowerShellScript(powerShellScript);

      // Build PowerShell command
      const psCommand = Session.buildPowerShellCommand(encodedScript, psOptions);

      // Execute PowerShell command
      const result = await this.protocol.runCommandAndWait('powershell.exe', `-EncodedCommand ${psCommand}`);

      // Decode PowerShell output if needed
      const decodedOutput = Session.decodePowerShellOutput(result.stdout);
      const decodedError = Session.decodePowerShellOutput(result.stderr);

      const duration = Date.now() - startTime;
      logger.info('Session.runPS completed', {
        exitCode: result.exitCode,
        duration,
        outputLength: decodedOutput.length,
        errorLength: decodedError.length,
      });
      logger.logPerformance('session.runPS', duration, { exitCode: result.exitCode });

      return Session.formatResult({
        ...result,
        stdout: decodedOutput,
        stderr: decodedError,
      }, startTime);
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Session.runPS failed', {
        error: error.message,
        duration,
      });

      if (error instanceof WinRMCommandError || error instanceof WinRMProtocolError) {
        throw error;
      }

      throw new WinRMCommandError(
        `PowerShell execution failed: ${error.message}`,
        powerShellScript,
        1,
        '',
        error.message,
        { duration, originalError: error.message },
      );
    }
  }

  /**
   * Build complete command with working directory and environment
   */
  buildCompleteCommand(command, options) {
    let fullCommand = command;

    // Add working directory if specified
    if (options.workingDirectory && options.workingDirectory !== this.options.workingDirectory) {
      fullCommand = `cd /d "${options.workingDirectory}" && ${fullCommand}`;
    }

    // Add environment variables if specified
    if (options.environmentVars && Object.keys(options.environmentVars).length > 0) {
      const envCommands = Object.entries(options.environmentVars)
        .map(([key, value]) => `set ${key}="${value}"`)
        .join(' && ');
      fullCommand = `${envCommands} && ${fullCommand}`;
    }

    return fullCommand;
  }

  /**
   * Encode PowerShell script for safe transmission
   */
  static encodePowerShellScript(script) {
    // Convert to UTF-16LE and base64 encode
    const unicodeScript = Buffer.from(script, 'utf8').toString('base64');
    return unicodeScript;
  }

  /**
   * Decode PowerShell output
   */
  static decodePowerShellOutput(output) {
    if (!output) return output;

    try {
      // If output appears to be base64 encoded, decode it
      const decoded = Buffer.from(output, 'base64').toString('utf8');
      return decoded;
    } catch (error) {
      // If decoding fails, return original output
      return output;
    }
  }

  /**
   * Build PowerShell command with encoded script
   */
  static buildPowerShellCommand(encodedScript, options) {
    let psCommand = encodedScript;

    // Add working directory if specified
    if (options.workingDirectory) {
      psCommand = `Set-Location "${options.workingDirectory}"; ${psCommand}`;
    }

    return Buffer.from(psCommand, 'utf8').toString('base64');
  }

  /**
   * Format execution result
   */
  static formatResult(result, startTime) {
    const endTime = Date.now();

    return {
      statusCode: result.exitCode || 0,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      exitCode: result.exitCode,
      startTime: new Date(startTime),
      endTime: new Date(endTime),
      duration: endTime - startTime,
      success: (result.exitCode || 0) === 0,
    };
  }

  /**
   * Run multiple commands sequentially
   */
  async runBatch(commands) {
    const results = [];

    for (const command of commands) {
      // eslint-disable-next-line no-await-in-loop
      const result = await this.run(command);
      results.push(result);

      // Stop on first failure if specified
      if (result.exitCode !== 0 && command.continueOnError !== true) {
        break;
      }
    }

    return results;
  }

  /**
   * Check if session is connected
   */
  isConnected() {
    return this.protocol.isShellOpen();
  }

  /**
   * Get session status
   */
  getStatus() {
    return this.protocol.getStatus();
  }

  /**
   * Test connectivity
   */
  async ping() {
    return this.protocol.ping();
  }

  /**
   * Close the session and clean up resources
   */
  async close() {
    try {
      await this.protocol.close();
      logger.info('Session closed successfully');
    } catch (error) {
      logger.warn('Error closing session', { error: error.message });
    }
  }

  /**
   * Execute a simple test command to verify connectivity
   */
  async test() {
    try {
      const result = await this.run('echo "WinRM test successful"');
      return result.exitCode === 0;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get system information
   */
  async getSystemInfo() {
    try {
      const hostname = await this.run('hostname');
      const osVersion = await this.run('ver');
      const currentUser = await this.run('whoami');

      return {
        hostname: hostname.stdout.trim(),
        osVersion: osVersion.stdout.trim(),
        currentUser: currentUser.stdout.trim(),
        connected: this.isConnected(),
      };
    } catch (error) {
      throw new WinRMProtocolError(
        `Failed to get system information: ${error.message}`,
        'GET_SYSTEM_INFO',
      );
    }
  }
}

module.exports = Session;
