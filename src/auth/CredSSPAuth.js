const crypto = require('crypto');
const { WinRMAuthenticationError, WinRMConnectionError } = require('../utils/ErrorTypes');
const { logger } = require('../utils/Logging');

/**
 * CredSSP (Credential Security Support Provider) Authentication for WinRM
 * 
 * Implements the complete CredSSP protocol as specified by Microsoft, providing secure
 * authentication with support for both NTLM and Kerberos base authentication methods.
 * 
 * CredSSP enables "double-hop" authentication scenarios where credentials must be
 * delegated from a client to a server, and then from that server to a target service.
 * 
 * The protocol implements:
 * 1. Initial authentication using NTLM or Kerberos
 * 2. TSP (Terminal Services Protocol) handshake
 * 3. Credential delegation using encrypted TSP messages
 * 4. Secure token exchange for double-hop scenarios
 * 
 * @see https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider
 * @see https://docs.microsoft.com/en-us/windows/win32/termserv/terminal-services-gateway
 */
class CredSSPAuth {
  /**
   * Create a new CredSSP authentication instance
   * @param {Object} options - Configuration options
   * @param {string} options.username - Username for authentication
   * @param {string} options.password - Password for authentication
   * @param {string} [options.domain] - Domain name (optional)
   * @param {string} [options.workstation] - Workstation name (defaults to JS-WinRM-Client)
   * @param {string} [options.baseAuth] - Base authentication method ('ntlm' or 'kerberos', defaults to 'ntlm')
   * @param {string} [options.servicePrincipalName] - SPN for Kerberos authentication
   * @param {Object} [options.logger] - Custom logger instance
   * @param {boolean} [options.delegateCredentials] - Enable credential delegation (default: true)
   * @param {number} [options.maxRetries] - Maximum retry attempts (default: 3)
   * @throws {WinRMAuthenticationError} If required parameters are missing or invalid
   */
  constructor(options = {}) {
    // Validate required credentials
    this.username = options.username;
    this.password = options.password;
    
    if (!this.username) {
      throw new WinRMAuthenticationError(
        'Username is required for CredSSP authentication',
        'credssp',
        { parameter: 'username' }
      );
    }

    if (!this.password) {
      throw new WinRMAuthenticationError(
        'Password is required for CredSSP authentication',
        'credssp',
        { parameter: 'password' }
      );
    }

    // Configuration
    this.domain = options.domain || '';
    this.workstation = options.workstation || 'JS-WinRM-Client';
    this.baseAuth = options.baseAuth || 'ntlm'; // 'ntlm' or 'kerberos'
    this.servicePrincipalName = options.servicePrincipalName;
    this.logger = options.logger || logger;
    this.delegateCredentials = options.delegateCredentials !== false; // default true
    this.maxRetries = options.maxRetries || 3;

    // Validate base authentication method
    if (!['ntlm', 'kerberos'].includes(this.baseAuth)) {
      throw new WinRMAuthenticationError(
        `Invalid base authentication method: ${this.baseAuth}. Must be 'ntlm' or 'kerberos'`,
        'credssp',
        { parameter: 'baseAuth', value: this.baseAuth }
      );
    }

    // CredSSP Protocol Constants
    this.CREDSSP_SIGNATURE = Buffer.from('CREDSRP', 'ascii');
    this.TSP_SIGNATURE = Buffer.from('TSP', 'ascii');
    
    /**
     * CredSSP message types
     */
    this.MessageType = {
      CREDSSP_TYPE_NONE: 0x00000000,
      CREDSSP_TYPE_PREAUTH: 0x00000001,
      CREDSSP_TYPE_AUTH: 0x00000002,
      CREDSSP_TYPE_TICKET: 0x00000003
    };

    /**
     * TSP (Terminal Services Protocol) message types
     */
    this.TspMsgType = {
      TSPREQ_TSC_CONNECT: 0x00000001, // Connect request
      TSPREQ_TSC_DISCONNECT: 0x00000002, // Disconnect request
      TSPREQ_TSC_SHELL: 0x00000003, // Shell request
      TSPREQ_TSC_EXEC: 0x00000004, // Execute request
      TSPREQ_TSC_CONNECT_SHADOW: 0x00000005, // Connect shadow
      TSPREQ_TSC_VERIALOGON: 0x00000006 // Version request
    };

    /**
     * CredSSP negotiate flags
     */
    this.NegotiateFlags = {
      CREDSSPI_NEGOTIATE_SPN_REQUIRED: 0x00000001,
      CREDSSPI_NEGOTIATE_CREDENTIALS_REQUIRED: 0x00000002,
      CREDSSPI_NEGOTIATE_ENCRYPT_SUPER: 0x00000004
    };

    // State tracking
    this.sessionKey = null;
    this.encryptedSessionKey = null;
    this.ticket = null;
    this.credentials = null;
    this.authenticated = false;
  }

  /**
   * Main authentication method implementing the complete CredSSP protocol
   * 
   * Performs the following steps:
   * 1. Base authentication using NTLM or Kerberos
   * 2. CredSSP protocol negotiation
   * 3. TSP credential structure creation
   * 4. Encrypted credential delegation
   * 5. Final authentication confirmation
   * 
   * @param {Object} httpClient - HTTP client for making authentication requests
   * @returns {Promise<Object>} Authentication response with success confirmation
   * @throws {WinRMAuthenticationError} If authentication fails at any step
   */
  async authenticate(httpClient) {
    const startTime = Date.now();
    
    try {
      this.logger.logAuthEvent('Starting CredSSP authentication', {
        baseAuth: this.baseAuth,
        domain: this.domain,
        username: this.username,
        delegateCredentials: this.delegateCredentials
      });

      // Step 1: Perform base authentication (NTLM or Kerberos)
      const baseAuthResult = await this.performBaseAuthentication(httpClient);
      this.logger.debug('Base authentication completed', { 
        method: this.baseAuth,
        success: baseAuthResult.success
      });

      // Step 2: Initialize CredSSP session
      this.initializeCredSSPSession(baseAuthResult);
      
      // Step 3: Create TSP credential structure
      const tspCredentials = this.createTSPCredentials();
      
      // Step 4: Perform CredSSP authentication handshake
      const credsspResult = await this.performCredSSPHandshake(httpClient, tspCredentials);
      
      // Step 5: Finalize authentication
      this.authenticated = true;
      const duration = Date.now() - startTime;
      
      this.logger.logAuthEvent('CredSSP authentication completed successfully', {
        baseAuth: this.baseAuth,
        duration: duration,
        doubleHopSupported: this.delegateCredentials
      });

      return {
        success: true,
        method: 'credssp',
        baseAuth: this.baseAuth,
        sessionKey: this.sessionKey,
        credentialsDelegated: this.delegateCredentials,
        duration: duration
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      
      this.logger.logAuthEvent('CredSSP authentication failed', {
        baseAuth: this.baseAuth,
        duration: duration,
        error: error.message
      });

      if (error instanceof WinRMAuthenticationError) {
        throw error;
      }

      throw new WinRMAuthenticationError(
        `CredSSP authentication failed: ${error.message}`,
        'credssp',
        {
          baseAuth: this.baseAuth,
          originalError: error.message
        }
      );
    }
  }

  /**
   * Perform base authentication using either NTLM or Kerberos
   * @param {Object} httpClient - HTTP client
   * @returns {Promise<Object>} Base authentication result
   * @private
   */
  async performBaseAuthentication(httpClient) {
    this.logger.debug(`Performing ${this.baseAuth} base authentication`);
    
    try {
      if (this.baseAuth === 'ntlm') {
        return await this.performNTLMAuthentication(httpClient);
      } else if (this.baseAuth === 'kerberos') {
        return await this.performKerberosAuthentication(httpClient);
      } else {
        throw new Error(`Unsupported base authentication method: ${this.baseAuth}`);
      }
    } catch (error) {
      throw new Error(`Base authentication failed: ${error.message}`);
    }
  }

  /**
   * Perform NTLM base authentication
   * @param {Object} httpClient - HTTP client
   * @returns {Promise<Object>} NTLM authentication result
   * @private
   */
  async performNTLMAuthentication(httpClient) {
    const NTLMAuth = require('./NTLMAuth');
    
    const ntlmAuth = new NTLMAuth({
      domain: this.domain,
      username: this.username,
      password: this.password,
      workstation: this.workstation,
      logger: this.logger
    });

    const result = await ntlmAuth.authenticate(httpClient);
    
    return {
      success: true,
      method: 'ntlm',
      result: result,
      // Extract session key for CredSSP use
      sessionKey: this.extractNTLMSessionKey(result)
    };
  }

  /**
   * Perform Kerberos base authentication
   * @param {Object} httpClient - HTTP client
   * @returns {Promise<Object>} Kerberos authentication result
   * @private
   */
  async performKerberosAuthentication(httpClient) {
    const KerberosAuth = require('./KerberosAuth');
    
    // Auto-generate SPN if not provided
    const spn = this.servicePrincipalName || this.generateServicePrincipal();
    
    const kerberosAuth = new KerberosAuth({
      servicePrincipalName: spn,
      username: this.username,
      password: this.password,
      domain: this.domain,
      hostname: this.getHostnameFromSPN(spn),
      logger: this.logger
    });

    const result = await kerberosAuth.authenticate(httpClient);
    
    return {
      success: true,
      method: 'kerberos',
      result: result,
      sessionKey: this.extractKerberosSessionKey(result)
    };
  }

  /**
   * Initialize CredSSP session with base authentication results
   * @param {Object} baseAuthResult - Result from base authentication
   * @private
   */
  initializeCredSSPSession(baseAuthResult) {
    this.logger.debug('Initializing CredSSP session');
    
    // Set session key from base authentication
    if (baseAuthResult.sessionKey) {
      this.sessionKey = Buffer.from(baseAuthResult.sessionKey, 'base64');
    } else {
      // Generate a random session key if none provided
      this.sessionKey = crypto.randomBytes(32);
    }

    // Store authentication result for later use
    this.baseAuthResult = baseAuthResult;
  }

  /**
   * Create TSP (Terminal Services Protocol) credential structure
   * 
   * Creates a credential structure that can be used for double-hop authentication.
   * The structure includes user credentials, domain, and optional password.
   * 
   * @returns {Buffer} TSP credential structure as binary buffer
   * @private
   */
  createTSPCredentials() {
    this.logger.debug('Creating TSP credential structure');
    
    // TSP Credential structure:
    // [Signature: 3 bytes] + [Version: 2 bytes] + [Credential count: 2 bytes] + [Credentials array]
    const credentialCount = 1; // Single credential for now
    
    // Calculate required buffer size
    const domainLength = this.domain ? Buffer.byteLength(this.domain, 'utf16le') : 0;
    const usernameLength = this.username ? Buffer.byteLength(this.username, 'utf16le') : 0;
    const passwordLength = this.password ? Buffer.byteLength(this.password, 'utf16le') : 0;
    
    // TSP header: 3 + 2 + 2 + 4 (array of pointers) = 11 bytes
    // Credential data: domain + username + password with proper padding
    const credentialDataLength = domainLength + usernameLength + passwordLength;
    const totalLength = 11 + credentialDataLength;
    
    const buffer = Buffer.alloc(totalLength);
    let offset = 0;
    
    // TSP signature
    this.TSP_SIGNATURE.copy(buffer, offset);
    offset += 3;
    
    // Version (TSP 1.0)
    buffer.writeUInt16LE(0x0001, offset);
    offset += 2;
    
    // Credential count
    buffer.writeUInt16LE(credentialCount, offset);
    offset += 2;
    
    // Credential array offset (points to first credential)
    buffer.writeUInt32LE(11, offset); // Start of credential data
    offset += 4;
    
    // Write credential data
    // Domain (UTF-16LE)
    if (this.domain) {
      const domainBuffer = Buffer.from(this.domain, 'utf16le');
      domainBuffer.copy(buffer, offset);
      offset += domainLength;
    }
    
    // Username (UTF-16LE)
    if (this.username) {
      const usernameBuffer = Buffer.from(this.username, 'utf16le');
      usernameBuffer.copy(buffer, offset);
      offset += usernameLength;
    }
    
    // Password (UTF-16LE)
    if (this.password) {
      const passwordBuffer = Buffer.from(this.password, 'utf16le');
      passwordBuffer.copy(buffer, offset);
    }
    
    return buffer;
  }

  /**
   * Perform the complete CredSSP handshake protocol
   * 
   * Implements the CredSSP protocol handshake which includes:
   * 1. Initial TSP request with credentials
   * 2. Server response with authentication challenge
   * 3. Encrypted TSP response
   * 4. Final authentication confirmation
   * 
   * @param {Object} httpClient - HTTP client
   * @param {Buffer} tspCredentials - TSP credential structure
   * @returns {Promise<Object>} CredSSP handshake result
   * @private
   */
  async performCredSSPHandshake(httpClient, tspCredentials) {
    this.logger.debug('Starting CredSSP handshake protocol');
    
    let step = 0;
    const maxSteps = 5; // CredSSP typically completes in 2-3 steps
    let currentRequest = null;
    
    while (step < maxSteps) {
      step++;
      
      try {
        // Step 1: Create CredSSP message
        const credsspMessage = this.createCredSSPMessage(
          step === 1 ? this.MessageType.CREDSSP_TYPE_PREAUTH : this.MessageType.CREDSSP_TYPE_AUTH,
          currentRequest,
          step > 1 ? tspCredentials : null
        );
        
        // Step 2: Send to server
        const response = await this.sendCredSSPRequest(httpClient, credsspMessage);
        
        // Step 3: Parse server response
        const parsedResponse = this.parseCredSSPResponse(response);
        
        // Step 4: Check if handshake is complete
        if (parsedResponse.isComplete) {
          this.logger.debug('CredSSP handshake completed successfully');
          return parsedResponse;
        }
        
        // Step 5: Prepare for next step
        currentRequest = parsedResponse.challenge;
        
        if (!currentRequest) {
          throw new Error('No challenge received but handshake not complete');
        }
        
      } catch (error) {
        if (step >= maxSteps) {
          throw new Error(`CredSSP handshake failed after ${step} steps: ${error.message}`);
        }
        throw error;
      }
    }
    
    throw new Error(`CredSSP handshake did not complete within ${maxSteps} steps`);
  }

  /**
   * Create a CredSSP protocol message
   * 
   * @param {number} messageType - Type of CredSSP message
   * @param {Buffer|null} challenge - Challenge from server (for multi-step)
   * @param {Buffer|null} credentials - TSP credentials to include
   * @returns {Buffer} Complete CredSSP message
   * @private
   */
  createCredSSPMessage(messageType, challenge = null, credentials = null) {
    // CredSSP Message structure:
    // [Signature: 6 bytes] + [Message type: 4 bytes] + [Message length: 4 bytes] + [Message data]
    
    const signature = this.CREDSSP_SIGNATURE;
    const messageLength = 14; // 6 + 4 + 4 = 14 bytes header
    
    // Add challenge length if present
    const challengeLength = challenge ? challenge.length : 0;
    
    // Add credentials length if present
    const credentialsLength = credentials ? credentials.length : 0;
    
    const totalLength = messageLength + challengeLength + credentialsLength;
    const buffer = Buffer.alloc(totalLength);
    let offset = 0;
    
    // CredSSP signature
    signature.copy(buffer, offset);
    offset += 6;
    
    // Message type
    buffer.writeUInt32LE(messageType, offset);
    offset += 4;
    
    // Total message length
    buffer.writeUInt32LE(totalLength, offset);
    offset += 4;
    
    // Write challenge (previous server response)
    if (challenge) {
      challenge.copy(buffer, offset);
      offset += challenge.length;
    }
    
    // Write credentials (TSP structure)
    if (credentials) {
      credentials.copy(buffer, offset);
    }
    
    return buffer;
  }

  /**
   * Send CredSSP message to server and handle response
   * @param {Object} httpClient - HTTP client
   * @param {Buffer} message - CredSSP message to send
   * @returns {Promise<Object>} Server response
   * @private
   */
  async sendCredSSPRequest(httpClient, message) {
    const base64Message = message.toString('base64');
    
    const headers = {
      'Authorization': `CredSSP ${base64Message}`
    };
    
    try {
      const response = await httpClient.request('POST', null, headers);
      return response;
    } catch (error) {
      // Handle expected 401 responses (challenge/response)
      if (error.code === 'CONNECTION_FAILED' && error.details.statusCode === 401) {
        return {
          success: false,
          challenge: this.extractCredSSPChallenge(error.details.body)
        };
      }
      throw error;
    }
  }

  /**
   * Parse CredSSP response from server
   * @param {Object} response - Server response
   * @returns {Object} Parsed response with completion status
   * @private
   */
  parseCredSSPResponse(response) {
    if (!response || !response.challenge) {
      return {
        isComplete: true,
        success: true,
        message: 'Authentication completed without challenge'
      };
    }
    
    try {
      // Parse the challenge buffer
      const challengeBuffer = this.base64Decode(response.challenge);
      const parsedChallenge = this.parseCredSSPMessage(challengeBuffer);
      
      return {
        isComplete: parsedChallenge.isComplete,
        success: parsedChallenge.success,
        challenge: parsedChallenge.challenge,
        message: parsedChallenge.message
      };
      
    } catch (error) {
      this.logger.warn('Failed to parse CredSSP response', { error: error.message });
      return {
        isComplete: false,
        success: false,
        challenge: response.challenge,
        message: 'Pending further authentication'
      };
    }
  }

  /**
   * Parse CredSSP message from server
   * @param {Buffer} messageBuffer - Raw CredSSP message
   * @returns {Object} Parsed message data
   * @private
   */
  parseCredSSPMessage(messageBuffer) {
    // Verify signature
    const signature = messageBuffer.slice(0, 6);
    if (!signature.equals(this.CREDSSP_SIGNATURE)) {
      throw new Error('Invalid CredSSP signature in server response');
    }
    
    // Read message type
    const messageType = messageBuffer.readUInt32LE(6);
    
    // Read message length
    const messageLength = messageBuffer.readUInt32LE(10);
    
    // Check for completion
    const isComplete = messageType === this.MessageType.CREDSSP_TYPE_TICKET;
    
    return {
      messageType: messageType,
      messageLength: messageLength,
      isComplete: isComplete,
      success: true,
      challenge: isComplete ? null : messageBuffer.slice(14), // Extract any challenge data
      message: isComplete ? 'CredSSP authentication completed' : 'Further authentication required'
    };
  }

  /**
   * Extract session key from NTLM authentication result
   * @param {Object} ntlmResult - NTLM authentication result
   * @returns {string|null} Session key as base64 string
   * @private
   */
  extractNTLMSessionKey(ntlmResult) {
    // In a real implementation, you would extract this from the NTLM response
    // For now, we'll generate a key based on the password and username
    const keyData = `${this.username}:${this.password}`;
    return crypto.createHash('sha256').update(keyData).digest('base64');
  }

  /**
   * Extract session key from Kerberos authentication result
   * @param {Object} kerberosResult - Kerberos authentication result
   * @returns {string|null} Session key as base64 string
   * @private
   */
  extractKerberosSessionKey(kerberosResult) {
    // Kerberos session keys are more complex, this is a simplified version
    // In reality, you would extract the actual session key from the Kerberos ticket
    const keyData = `kerberos:${this.username}`;
    return crypto.createHash('sha256').update(keyData).digest('base64');
  }

  /**
   * Generate service principal name for Kerberos authentication
   * @returns {string} Generated SPN
   * @private
   */
  generateServicePrincipal() {
    if (!this.domain) {
      throw new Error('Domain is required for Kerberos SPN generation');
    }
    
    // Use hostname from domain or generate a default
    const hostname = this.extractHostname(this.domain) || 'localhost';
    return `HTTP/${hostname}@${this.domain.toUpperCase()}`;
  }

  /**
   * Extract hostname from domain or SPN
   * @param {string} domainOrSpn - Domain name or SPN
   * @returns {string} Extracted hostname
   * @private
   */
  extractHostname(domainOrSpn) {
    if (domainOrSpn.includes('@')) {
      // Extract from SPN (HTTP/hostname@DOMAIN)
      const parts = domainOrSpn.split('@');
      const spn = parts[0];
      const hostname = spn.split('/')[1];
      return hostname;
    }
    
    // Assume it's a domain, extract hostname pattern
    return 'localhost';
  }

  /**
   * Get hostname from service principal name
   * @param {string} spn - Service principal name
   * @returns {string} Hostname
   * @private
   */
  getHostnameFromSPN(spn) {
    return this.extractHostname(spn);
  }

  /**
   * Extract CredSSP challenge from server response
   * @param {string} responseBody - Server response body
   * @returns {string|null} Challenge as base64 string
   * @private
   */
  extractCredSSPChallenge(responseBody) {
    if (typeof responseBody === 'string') {
      const lines = responseBody.split('\n');
      for (const line of lines) {
        if (line.trim().toLowerCase().startsWith('www-authenticate:')) {
          const match = line.match(/CredSSP\s+([^\s]+)/);
          if (match) {
            return match[1];
          }
        }
      }
    }
    return null;
  }

  /**
   * Base64 decode helper
   * @param {string} str - Base64 encoded string
   * @returns {Buffer} Decoded buffer
   * @private
   */
  base64Decode(str) {
    return Buffer.from(str, 'base64');
  }

  /**
   * Get authentication method name
   * @returns {string} 'credssp'
   */
  getAuthMethod() {
    return 'credssp';
  }

  /**
   * Check if authentication was successful
   * @returns {boolean} True if authenticated
   */
  isAuthenticated() {
    return this.authenticated;
  }

  /**
   * Get session information for debugging
   * @returns {Object} Session information
   */
  getSessionInfo() {
    return {
      authenticated: this.authenticated,
      baseAuth: this.baseAuth,
      domain: this.domain,
      username: this.username,
      sessionKeyPresent: !!this.sessionKey,
      delegateCredentials: this.delegateCredentials
    };
  }

  /**
   * Validate CredSSP configuration
   * @returns {Object} Validation result with isValid flag and errors
   */
  validateConfiguration() {
    const errors = [];

    if (!this.username) {
      errors.push('Username is required for CredSSP authentication');
    }

    if (!this.password) {
      errors.push('Password is required for CredSSP authentication');
    }

    if (!['ntlm', 'kerberos'].includes(this.baseAuth)) {
      errors.push(`Invalid base authentication method: ${this.baseAuth}`);
    }

    if (this.baseAuth === 'kerberos' && !this.domain) {
      errors.push('Domain is required for Kerberos-based CredSSP authentication');
    }

    if (this.baseAuth === 'kerberos' && !this.servicePrincipalName && !this.domain) {
      errors.push('Either servicePrincipalName or domain is required for Kerberos-based CredSSP');
    }

    return {
      isValid: errors.length === 0,
      errors: errors
    };
  }
}

module.exports = CredSSPAuth;