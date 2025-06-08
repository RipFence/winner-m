// winrm-client.js
// This is the main client interface for interacting with WinRM.
// It orchestrates calls to the WinRmTransport and WinRmProtocol layers.

import { WinRmTransport } from './transport.js';
import { WinRmProtocol } from './protocol.js';

export class WinRmClient {
  /**
   * Initializes the WinRM client.
   * @param {string} host - The hostname or IP address of the Windows server.
   * @param {string} username - The username for authentication.
   * @param {string} password - The password for authentication.
   * @param {object} [options={}] - Configuration options for the client.
   * @param {number} [options.port=5986] - The WinRM port (5985 for HTTP, 5986 for HTTPS).
   * @param {boolean} [options.https=true] - Whether to use HTTPS. Defaults to true.
   * @param {number} [options.timeout=60000] - Request timeout in milliseconds.
   * @param {boolean} [options.rejectUnauthorized=true] - For HTTPS, whether to reject self-signed certs.
   * @param {string} [options.locale='en-US'] - Locale for WinRM messages.
   * @param {string} [options.dataLocale='en-US'] - Data locale for WinRM messages.
   * @param {number} [options.maxEnvelopeSize=153600] - Max envelope size for WinRM messages.
   * @param {string} [options.operationTimeout='PT60S'] - Operation timeout for WinRM messages.
   */
  constructor(host, username, password, options = {}) {
    this.host = host;
    this.username = username;
    this.password = password;
    this.options = {
      port: 5986, // Default to HTTPS port
      https: true,
      timeout: 60000,
      rejectUnauthorized: true,
      locale: 'en-US',
      dataLocale: 'en-US',
      maxEnvelopeSize: 153600,
      operationTimeout: 'PT60S',
      ...options
    };

    this.transport = new WinRmTransport(
      this.host,
      this.options.port,
      this.username,
      this.password,
      this.options
    );
    this.protocol = new WinRmProtocol(this.options);

    // WinRM operates on a target URI that depends on HTTPS/HTTP
    this.toUri = `${this.options.https ? 'https' : 'http'}://${this.host}:${this.options.port}/wsman`;

    this.shellId = null; // Store the active shell ID
  }

  /**
   * Opens a new WinRM shell on the remote server.
   * @returns {Promise<string>} A promise that resolves with the Shell ID.
   */
  async openShell() {
    console.log('Opening WinRM shell...');
    try {
      const xmlRequest = this.protocol.buildCreateShellRequest(this.toUri);
      const xmlResponse = await this.transport.sendRequest(xmlRequest);
      const { shellId } = this.protocol.parseCreateShellResponse(xmlResponse);
      this.shellId = shellId;
      console.log(`Shell opened with ID: ${shellId}`);
      return shellId;
    } catch (error) {
      console.error('Failed to open shell:', error.message);
      throw error;
    }
  }

  /**
   * Runs a command within the active WinRM shell.
   * PowerShell commands are automatically encoded to UTF-16LE and Base64.
   * @param {string} command - The command to execute (e.g., 'ipconfig', 'powershell -EncodedCommand ...').
   * @param {string[]} [args=[]] - Arguments for the command.
   * @returns {Promise<object>} A promise that resolves with an object containing { commandId }.
   */
  async runCommand(command, args = []) {
    if (!this.shellId) {
      throw new Error('No active shell. Call openShell() first.');
    }

    // Special handling for PowerShell -EncodedCommand
    if (command.toLowerCase().startsWith('powershell -encodedcommand')) {
      const rawCommand = args.join(' '); // Assuming the actual PowerShell script is in args
      // Convert to UTF-16LE bytes
      const utf16leBuffer = Buffer.from(rawCommand, 'utf16le');
      // Base64 encode the buffer
      const encodedCmd = utf16leBuffer.toString('base64');
      command = 'powershell -EncodedCommand';
      args = [encodedCmd];
      console.log('Executing PowerShell command with -EncodedCommand.');
    }

    console.log(`Running command: ${command} ${args.join(' ')} on shell ${this.shellId}`);
    try {
      const xmlRequest = this.protocol.buildRunCommandRequest(this.toUri, this.shellId, command, args);
      const xmlResponse = await this.transport.sendRequest(xmlRequest);
      const { commandId } = this.protocol.parseRunCommandResponse(xmlResponse);
      console.log(`Command started with ID: ${commandId}`);
      return { commandId };
    } catch (error) {
      console.error('Failed to run command:', error.message);
      throw error;
    }
  }

  /**
   * Receives output (stdout and stderr) from a running command.
   * This method might need to be called multiple times until `done` is true.
   * @param {string} commandId - The ID of the running command.
   * @returns {Promise<object>} A promise that resolves with { stdout, stderr, exitCode, done }.
   */
  async getCommandOutput(commandId) {
    if (!this.shellId) {
      throw new Error('No active shell. Call openShell() first.');
    }
    console.log(`Receiving output for command: ${commandId}`);
    try {
      const xmlRequest = this.protocol.buildReceiveRequest(this.toUri, this.shellId, commandId);
      const xmlResponse = await this.transport.sendRequest(xmlRequest);
      const result = this.protocol.parseReceiveResponse(xmlResponse);
      if (result.done) {
        console.log(`Command ${commandId} finished with exit code: ${result.exitCode}`);
      }
      return result;
    } catch (error) {
      console.error('Failed to get command output:', error.message);
      throw error;
    }
  }

  /**
   * Sends a signal to a running command (e.g., terminate).
   * @param {string} commandId - The ID of the running command.
   * @param {string} signalCode - The signal code (e.g., '[http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate](http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate)').
   * @returns {Promise<void>} A promise that resolves when the signal is sent.
   */
  async signalCommand(commandId, signalCode = '[http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate](http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate)') {
    if (!this.shellId) {
      throw new Error('No active shell. Call openShell() first.');
    }
    console.log(`Sending signal ${signalCode} to command ${commandId}`);
    try {
      const xmlRequest = this.protocol.buildSignalRequest(this.toUri, this.shellId, commandId, signalCode);
      await this.transport.sendRequest(xmlRequest);
      console.log('Signal sent successfully.');
    } catch (error) {
      console.error('Failed to send signal:', error.message);
      throw error;
    }
  }

  /**
   * Closes the active WinRM shell.
   * @returns {Promise<void>} A promise that resolves when the shell is closed.
   */
  async closeShell() {
    if (!this.shellId) {
      console.log('No active shell to close.');
      return;
    }
    console.log(`Closing shell: ${this.shellId}`);
    try {
      const xmlRequest = this.protocol.buildDeleteShellRequest(this.toUri, this.shellId);
      await this.transport.sendRequest(xmlRequest);
      console.log('Shell closed successfully.');
      this.shellId = null;
    } catch (error) {
      console.error('Failed to close shell:', error.message);
      throw error;
    }
  }

  /**
   * Executes a command end-to-end (opens shell, runs command, collects output, closes shell).
   * This is a convenience method for simple command execution.
   * @param {string} command - The command to execute.
   * @param {string[]} [args=[]] - Arguments for the command.
   * @param {number} [pollInterval=1000] - Interval in ms to poll for command output.
   * @param {number} [maxPollAttempts=60] - Max attempts to poll for output.
   * @returns {Promise<object>} A promise that resolves with { stdout, stderr, exitCode }.
   */
  async runPsCommand(command, args = [], pollInterval = 1000, maxPollAttempts = 60) {
    let shellId = null;
    let commandId = null;
    try {
      shellId = await this.openShell();
      const result = await this.runCommand(command, args);
      commandId = result.commandId;

      let output = { stdout: '', stderr: '', exitCode: null, done: false };
      let attempts = 0;

      while (!output.done && attempts < maxPollAttempts) {
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        output = await this.getCommandOutput(commandId);
        attempts++;
      }

      if (!output.done) {
        throw new Error(`Command ${commandId} timed out after ${maxPollAttempts} attempts.`);
      }

      return {
        stdout: output.stdout,
        stderr: output.stderr,
        exitCode: output.exitCode
      };

    } catch (error) {
      console.error('Error during end-to-end command execution:', error.message);
      throw error;
    } finally {
      if (shellId) {
        await this.closeShell(); // Ensure shell is closed even on error
      }
    }
  }
}
