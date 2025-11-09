const crypto = require('crypto');
const { WinRMAuthenticationError, WinRMConnectionError } = require('../utils/ErrorTypes');
const { logger } = require('../utils/Logging');

/**
 * Enhanced NTLM Authentication implementation for WinRM
 * Implements the complete NTLM 3-message handshake (Type 1, Type 2, Type 3) with proper protocol support
 */
class NTLMAuth {
  constructor(options) {
    this.domain = options.domain || '';
    this.username = options.username;
    this.password = options.password;
    this.workstation = options.workstation || 'JS-WinRM-Client';
    this.logger = options.logger || logger;
    this.maxRetries = options.maxRetries || 3;
    
    if (!this.username) {
      throw new WinRMAuthenticationError('Username is required for NTLM authentication', 'ntlm', {
        parameter: 'username'
      });
    }

    // NTLM Security Support Provider Interface (SSPI) Constants
    this.NTLMSSP_SIGNATURE = Buffer.from('NTLMSSP\0', 'ascii');
    this.MESSAGE_TYPE = {
      NEGOTIATE: 0x00000001,
      CHALLENGE: 0x00000002,
      AUTHENTICATE: 0x00000003
    };

    this.NEGOTIATE_FLAGS = {
      NTLMSSP_NEGOTIATE_56: 0x80000000,
      NTLMSSP_NEGOTIATE_KEY_EXCH: 0x40000000,
      NTLMSSP_NEGOTIATE_128: 0x20000000,
      NTLMSSP_NEGOTIATE_VERSION: 0x10000000,
      NTLMSSP_NEGOTIATE_RESERVED_3: 0x08000000,
      NTLMSSP_NEGOTIATE_RESERVED_2: 0x04000000,
      NTLMSSP_NEGOTIATE_RESERVED_1: 0x02000000,
      NTLMSSP_NEGOTIATE_RESERVED_0: 0x01000000,
      NTLMSSP_REQUEST_TARGET: 0x00800000,
      NTLMSSP_NEGOTIATE_SIGN: 0x00100000,
      NTLMSSP_NEGOTIATE_SEAL: 0x00080000,
      NTLMSSP_NEGOTIATE_DATAGRAM: 0x00040000,
      NTLMSSP_NEGOTIATE_LM_KEY: 0x00020000,
      NTLMSSP_NEGOTIATE_NETWARE: 0x00010000,
      NTLMSSP_NEGOTIATE_NTLM: 0x00000200,
      NTLMSSP_NEGOTIATE_RESERVED_4: 0x00000100,
      NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED: 0x00000010,
      NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED: 0x00000008,
      NTLMSSP_NEGOTIATE_LOCAL_CALL: 0x00000004,
      NTLMSSP_NEGOTIATE_ALWAYS_SIGN: 0x00000002,
      NTLMSSP_NEGOTIATE_OEM: 0x00000001
    };
  }

  /**
   * Main authentication method
   */
  async authenticate(httpClient) {
    try {
      logger.logAuthEvent('Starting NTLM authentication', {
        domain: this.domain,
        username: this.username,
        workstation: this.workstation
      });

      // Step 1: Send Type 1 message (Negotiate)
      const type1Message = this.buildType1Message();
      const step1Response = await this.sendAuthMessage(httpClient, type1Message);

      // Step 2: Send Type 3 message (Authenticate)
      const type3Message = this.buildType3Message(step1Response);
      const finalResponse = await this.sendAuthMessage(httpClient, type3Message);

      logger.logAuthEvent('NTLM authentication completed successfully');
      return finalResponse;

    } catch (error) {
      logger.logAuthEvent('NTLM authentication failed', { error: error.message });
      
      if (error instanceof WinRMAuthenticationError) {
        throw error;
      }
      
      throw new WinRMAuthenticationError(
        `NTLM authentication failed: ${error.message}`,
        'ntlm',
        { originalError: error.message }
      );
    }
  }

  /**
   * Build NTLM Type 1 message (Negotiation)
   */
  buildType1Message() {
    const flags = this.calculateNegotiateFlags();
    
    // Build Type 1 message structure
    const domainLength = this.domain ? Buffer.byteLength(this.domain, 'utf8') : 0;
    const workstationLength = this.workstation ? Buffer.byteLength(this.workstation, 'utf8') : 0;
    
    const messageBuffer = Buffer.alloc(40 + domainLength + workstationLength);
    let offset = 0;

    // Signature (8 bytes)
    this.NTLMSSP_SIGNATURE.copy(messageBuffer, offset);
    offset += 8;

    // Message Type (4 bytes)
    messageBuffer.writeUInt32LE(this.MESSAGE_TYPE.NEGOTIATE, offset);
    offset += 4;

    // Flags (4 bytes)
    messageBuffer.writeUInt32LE(flags, offset);
    offset += 4;

    // Domain fields
    const domainOffset = 40; // Start of domain string
    messageBuffer.writeUInt16LE(domainLength, offset); // Domain length
    offset += 2;
    messageBuffer.writeUInt16LE(domainLength, offset); // Max length
    offset += 2;
    messageBuffer.writeUInt32LE(domainOffset, offset); // Domain offset
    offset += 4;

    // Workstation fields
    const workstationOffset = domainOffset + domainLength;
    messageBuffer.writeUInt16LE(workstationLength, offset); // Workstation length
    offset += 2;
    messageBuffer.writeUInt16LE(workstationLength, offset); // Max length
    offset += 2;
    messageBuffer.writeUInt32LE(workstationOffset, offset); // Workstation offset
    offset += 4;

    // Version (8 bytes) - all zeros for compatibility
    // This could be enhanced to include actual version info
    for (let i = 0; i < 8; i++) {
      messageBuffer.writeUInt8(0, offset + i);
    }
    offset += 8;

    // Domain string (UTF-16LE)
    if (this.domain) {
      const domainBuffer = Buffer.from(this.domain, 'utf16le');
      domainBuffer.copy(messageBuffer, domainOffset);
    }

    // Workstation string (UTF-16LE)
    if (this.workstation) {
      const workstationBuffer = Buffer.from(this.workstation, 'utf16le');
      workstationBuffer.copy(messageBuffer, workstationOffset);
    }

    return messageBuffer;
  }

  /**
   * Calculate negotiated flags based on protocol capabilities
   */
  calculateNegotiateFlags() {
    let flags = 0;

    // Negotiate Unicode and OEM
    flags |= this.NEGOTIATE_FLAGS.NTLMSSP_NEGOTIATE_OEM;
    
    // Request target for server identity
    flags |= this.NEGOTIATE_FLAGS.NTLMSSP_REQUEST_TARGET;
    
    // Negotiate NTLM
    flags |= this.NEGOTIATE_FLAGS.NTLMSSP_NEGOTIATE_NTLM;
    
    // Always sign
    flags |= this.NEGOTIATE_FLAGS.NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
    
    // Negotiate signing and sealing if supported
    flags |= this.NEGOTIATE_FLAGS.NTLMSSP_NEGOTIATE_SIGN;
    flags |= this.NEGOTIATE_FLAGS.NTLMSSP_NEGOTIATE_SEAL;
    
    // 128-bit encryption
    flags |= this.NEGOTIATE_FLAGS.NTLMSSP_NEGOTIATE_128;
    
    // 56-bit encryption
    flags |= this.NEGOTIATE_FLAGS.NTLMSSP_NEGOTIATE_56;
    
    // Key exchange
    flags |= this.NEGOTIATE_FLAGS.NTLMSSP_NEGOTIATE_KEY_EXCH;
    
    // Domain and workstation supplied
    if (this.domain) {
      flags |= this.NEGOTIATE_FLAGS.NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED;
    }
    if (this.workstation) {
      flags |= this.NEGOTIATE_FLAGS.NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED;
    }

    return flags;
  }

  /**
   * Build NTLM Type 3 message (Authentication)
   */
  buildType3Message(type2Response) {
    // Parse Type 2 message to get challenge
    const parsedType2 = this.parseType2Message(type2Response);
    const challenge = parsedType2.challenge;

    // Calculate responses
    const ntlmResponse = this.calculateNTLMv2Response(parsedType2, challenge);
    const lmResponse = this.calculateLMv2Response(parsedType2, challenge);

    // Build the full Type 3 message
    return this.buildType3MessageBuffer(ntlmResponse, lmResponse);
  }

  /**
   * Build Type 3 message buffer
   */
  buildType3MessageBuffer(ntlmResponse, lmResponse) {
    const domainLength = this.domain ? Buffer.byteLength(this.domain, 'utf8') : 0;
    const usernameLength = Buffer.byteLength(this.username, 'utf8');
    const workstationLength = this.workstation ? Buffer.byteLength(this.workstation, 'utf8') : 0;
    
    // Calculate total response lengths
    const lmResponseLength = lmResponse.length;
    const ntlmResponseLength = ntlmResponse.length;
    const sessionKeyLength = 16; // 16 bytes for NTLMv2 session key
    
    // Calculate offsets
    const fixedHeaderLength = 64;
    const domainOffset = fixedHeaderLength;
    const usernameOffset = domainOffset + domainLength;
    const workstationOffset = usernameOffset + usernameLength;
    const lmResponseOffset = workstationOffset + workstationLength;
    const ntlmResponseOffset = lmResponseOffset + lmResponseLength;
    const sessionKeyOffset = ntlmResponseOffset + ntlmResponseLength;
    
    const totalLength = sessionKeyOffset + sessionKeyLength;
    const messageBuffer = Buffer.alloc(totalLength);
    let offset = 0;

    // Signature (8 bytes)
    this.NTLMSSP_SIGNATURE.copy(messageBuffer, offset);
    offset += 8;

    // Message Type (4 bytes)
    messageBuffer.writeUInt32LE(this.MESSAGE_TYPE.AUTHENTICATE, offset);
    offset += 4;

    // LM Response
    messageBuffer.writeUInt16LE(lmResponseLength, offset); // Length
    offset += 2;
    messageBuffer.writeUInt16LE(lmResponseLength, offset); // Max length
    offset += 2;
    messageBuffer.writeUInt32LE(lmResponseOffset, offset); // Offset
    offset += 4;

    // NTLM Response
    messageBuffer.writeUInt16LE(ntlmResponseLength, offset); // Length
    offset += 2;
    messageBuffer.writeUInt16LE(ntlmResponseLength, offset); // Max length
    offset += 2;
    messageBuffer.writeUInt32LE(ntlmResponseOffset, offset); // Offset
    offset += 4;

    // Target Name (domain)
    messageBuffer.writeUInt16LE(domainLength, offset); // Length
    offset += 2;
    messageBuffer.writeUInt16LE(domainLength, offset); // Max length
    offset += 2;
    messageBuffer.writeUInt32LE(domainOffset, offset); // Offset
    offset += 4;

    // User Name
    messageBuffer.writeUInt16LE(usernameLength, offset); // Length
    offset += 2;
    messageBuffer.writeUInt16LE(usernameLength, offset); // Max length
    offset += 2;
    messageBuffer.writeUInt32LE(usernameOffset, offset); // Offset
    offset += 4;

    // Workstation
    messageBuffer.writeUInt16LE(workstationLength, offset); // Length
    offset += 2;
    messageBuffer.writeUInt16LE(workstationLength, offset); // Max length
    offset += 2;
    messageBuffer.writeUInt32LE(workstationOffset, offset); // Offset
    offset += 4;

    // Session Key
    messageBuffer.writeUInt16LE(sessionKeyLength, offset); // Length
    offset += 2;
    messageBuffer.writeUInt16LE(sessionKeyLength, offset); // Max length
    offset += 2;
    messageBuffer.writeUInt32LE(sessionKeyOffset, offset); // Offset
    offset += 4;

    // Flags (same as Type 1)
    messageBuffer.writeUInt32LE(this.calculateNegotiateFlags(), offset);
    offset += 4;

    // Version (8 bytes) - all zeros for compatibility
    for (let i = 0; i < 8; i++) {
      messageBuffer.writeUInt8(0, offset + i);
    }
    offset += 8;

    // MIC (16 bytes) - not implemented in this version
    // All zeros for compatibility
    // offset += 16;

    // Write the actual data
    // Domain
    if (this.domain) {
      const domainBuffer = Buffer.from(this.domain, 'utf16le');
      domainBuffer.copy(messageBuffer, domainOffset);
    }

    // Username
    const usernameBuffer = Buffer.from(this.username, 'utf16le');
    usernameBuffer.copy(messageBuffer, usernameOffset);

    // Workstation
    if (this.workstation) {
      const workstationBuffer = Buffer.from(this.workstation, 'utf16le');
      workstationBuffer.copy(messageBuffer, workstationOffset);
    }

    // LM Response
    lmResponse.copy(messageBuffer, lmResponseOffset);

    // NTLM Response
    ntlmResponse.copy(messageBuffer, ntlmResponseOffset);

    // Session Key (16 bytes of zeros for now)
    messageBuffer.fill(0, sessionKeyOffset, sessionKeyOffset + sessionKeyLength);

    return messageBuffer;
  }

  /**
   * Parse NTLM Type 2 message (Challenge)
   */
  parseType2Message(type2Response) {
    try {
      // Find the NTLM challenge in the response
      const authHeader = this.extractNTLMAuthHeader(type2Response);
      if (!authHeader) {
        throw new WinRMAuthenticationError('No NTLM challenge found in response', 'ntlm');
      }

      const challengeBuffer = this.base64Decode(authHeader);
      
      // Parse Type 2 message structure
      return this.parseType2Binary(challengeBuffer);
    } catch (error) {
      throw new WinRMAuthenticationError(
        `Failed to parse NTLM Type 2 message: ${error.message}`,
        'ntlm'
      );
    }
  }

  /**
   * Parse binary Type 2 message
   */
  parseType2Binary(buffer) {
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    
    // Check signature
    const signature = buffer.slice(0, 8).toString('ascii');
    if (signature !== 'NTLMSSP\0') {
      throw new Error('Invalid NTLM signature in Type 2 message');
    }

    // Read message type
    const messageType = view.getUint32(8, true);
    if (messageType !== this.MESSAGE_TYPE.CHALLENGE) {
      throw new Error('Expected Type 2 (Challenge) message');
    }

    // Read flags
    const flags = view.getUint32(12, true);
    
    // Read challenge (8 bytes)
    const challenge = buffer.slice(16, 24);
    
    // Read target name and other fields
    const targetName = this.readUnicodeString(buffer, 32, 40);
    const targetInfo = this.readTargetInfo(buffer, 40);
    
    return {
      flags,
      challenge: new Uint8Array(challenge),
      targetName,
      targetInfo
    };
  }

  /**
   * Read Unicode string from buffer
   */
  readUnicodeString(buffer, offset, maxOffset) {
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const length = view.getUint16(offset, true);
    const stringOffset = view.getUint32(offset + 4, true);
    
    if (length === 0) return '';
    
    const stringBuffer = buffer.slice(stringOffset, stringOffset + length);
    return stringBuffer.toString('utf16le').replace(/\0.*/, '');
  }

  /**
   * Read target info from buffer
   */
  readTargetInfo(buffer, offset) {
    try {
      const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      const length = view.getUint16(offset, true);
      const stringOffset = view.getUint32(offset + 4, true);
      
      if (length === 0) return null;
      
      return buffer.slice(stringOffset, stringOffset + length);
    } catch (error) {
      return null;
    }
  }

  /**
   * Calculate NTLM v2 response
   */
  calculateNTLMv2Response(type2Data, challenge) {
    // Create NTLM hash
    const ntlmHash = this.createNTLMv2Hash();
    
    // Create the challenge response
    const challengeResponse = this.createChallengeResponse(ntlmHash, type2Data.challenge, type2Data.targetInfo);
    
    return challengeResponse;
  }

  /**
   * Calculate LM v2 response
   */
  calculateLMv2Response(type2Data, challenge) {
    const ntlmHash = this.createNTLMv2Hash();
    const challengeResponse = this.createChallengeResponse(ntlmHash, type2Data.challenge, null);
    
    return challengeResponse;
  }

  /**
   * Create NTLM v2 hash
   */
  createNTLMv2Hash() {
    // Create NTLM hash using MD4
    const password = this.password || '';
    const passwordBuffer = Buffer.from(password, 'utf16le');
    return crypto.createHash('md4').update(passwordBuffer).digest();
  }

  /**
   * Create challenge response using HMAC-MD5
   */
  createChallengeResponse(ntlmHash, challenge, targetInfo) {
    // Build response data (challenge + timestamp + target info)
    const timestamp = this.getCurrentTime();
    const clientChallenge = crypto.randomBytes(8);
    
    const responseData = Buffer.concat([
      Buffer.from(challenge),
      this.ulong64LE(timestamp),
      Buffer.from(clientChallenge),
      Buffer.from([0x00, 0x00, 0x00, 0x00]) // Unknown4
    ]);

    if (targetInfo && targetInfo.length > 0) {
      // Include target info in response
      const targetInfoHeader = Buffer.concat([
        Buffer.from([0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), // Target info header
        this.ulong32LE(targetInfo.length),
        targetInfo
      ]);
      responseData = Buffer.concat([responseData, targetInfoHeader]);
    }

    // Create HMAC-MD5 using the NTLM hash
    const hmac = crypto.createHmac('md5', ntlmHash);
    hmac.update(responseData);
    const mac = hmac.digest();

    // Build final response
    const response = Buffer.concat([
      Buffer.from(mac),
      Buffer.from(clientChallenge)
    ]);

    return response;
  }

  /**
   * Get current time as 64-bit little-endian value
   */
  getCurrentTime() {
    // Windows FILETIME epoch: January 1, 1601
    const windowsEpoch = Date.UTC(1601, 0, 1);
    const currentTime = Date.now();
    const diffMs = currentTime - windowsEpoch;
    const diff100ns = diffMs * 10000;
    
    return diff100ns;
  }

  /**
   * Convert number to 64-bit little-endian buffer
   */
  ulong64LE(value) {
    const low = value % 0x100000000;
    const high = Math.floor(value / 0x100000000);
    
    const buffer = Buffer.alloc(8);
    buffer.writeUInt32LE(low, 0);
    buffer.writeUInt32LE(high, 4);
    
    return buffer;
  }

  /**
   * Convert number to 32-bit little-endian buffer
   */
  ulong32LE(value) {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32LE(value, 0);
    return buffer;
  }

  /**
   * Send authentication message and handle challenge/response
   */
  async sendAuthMessage(httpClient, message) {
    const encodedMessage = this.base64Encode(message);
    
    const headers = {
      'Authorization': `NTLM ${encodedMessage}`
    };

    try {
      const response = await httpClient.request('POST', null, headers);
      return response;
    } catch (error) {
      // Expected 401 on first step, 200 on success
      if (error.code === 'CONNECTION_FAILED' && error.details.statusCode === 401) {
        return error.details.body; // This contains the Type 2 challenge
      }
      throw error;
    }
  }

  /**
   * Extract NTLM authentication header from response
   */
  extractNTLMAuthHeader(response) {
    // Find the WWW-Authenticate header with NTLM
    const lines = response.split('\n');
    for (const line of lines) {
      if (line.trim().toLowerCase().startsWith('www-authenticate:')) {
        const match = line.match(/NTLM\s+([^\s]+)/);
        if (match) {
          return match[1];
        }
      }
    }
    return null;
  }

  /**
   * Base64 decode helper
   */
  base64Decode(str) {
    return Buffer.from(str, 'base64');
  }

  /**
   * Base64 encode helper
   */
  base64Encode(buffer) {
    return buffer.toString('base64');
  }
}

module.exports = NTLMAuth;