import { NtlmClient } from 'axios-ntlm';
import crypto from 'crypto';

/**
 * NTLM Authentication handler for WinRM
 * Implements both authentication and message security
 */
export class NTLMAuth {
    /**
     * Create a new NTLM authentication handler
     * @param {Object} config Configuration object
     * @param {string} config.username Username (with optional domain as DOMAIN\\username)
     * @param {string} config.password Password
     * @param {boolean} [config.send_cbt=true] Whether to send channel binding token
     */
    constructor({ username, password, send_cbt = true }) {
        const [domain, user] = username.includes('\\') 
            ? username.split('\\') 
            : ['', username];

        this.username = user;
        this.domain = domain;
        this.password = password;
        this.send_cbt = send_cbt;
        
        // Create the NTLM client for HTTP authentication
        this.client = new NtlmClient({
            username: this.username,
            password: this.password,
            domain: this.domain,
            workstation: ''
        });

        this.session_security = null;
    }

    /**
     * Initialize session security after authentication
     * This should be called after successful authentication
     */
    initializeSessionSecurity() {
        // Generate session keys based on the negotiated security context
        const sessionBaseKey = this.client.getSessionBaseKey();
        
        // Generate signing and sealing keys
        // As per [MS-NLMP] specification section 3.4.5.2
        const clientSigningKey = this._generateSigningKey(sessionBaseKey, 'Client');
        const clientSealingKey = this._generateSealingKey(sessionBaseKey, 'Client');

        // Create the session security context
        this.session_security = new NTLMSessionSecurity({
            signing_key: clientSigningKey,
            sealing_key: clientSealingKey,
            seq_num: 0
        });
    }

    /**
     * Get the modified axios client that handles NTLM authentication
     * @returns {import('axios').AxiosInstance} Axios client with NTLM auth
     */
    getClient() {
        return this.client;
    }

    /**
     * Generate a signing key for message integrity
     * @private
     * @param {Buffer} sessionKey Session key
     * @param {string} label Key label ('Client' or 'Server')
     * @returns {Buffer} Signing key
     */
    _generateSigningKey(sessionKey, label) {
        const signMagic = Buffer.from(`session key to ${label.toLowerCase()} signing key`);
        const hmac = crypto.createHmac('md5', sessionKey);
        hmac.update(signMagic);
        return hmac.digest();
    }

    /**
     * Generate a sealing key for message confidentiality
     * @private
     * @param {Buffer} sessionKey Session key
     * @param {string} label Key label ('Client' or 'Server')
     * @returns {Buffer} Sealing key
     */
    _generateSealingKey(sessionKey, label) {
        const sealMagic = Buffer.from(`session key to ${label.toLowerCase()} sealing key`);
        const hmac = crypto.createHmac('md5', sessionKey);
        hmac.update(sealMagic);
        return hmac.digest();
    }
}

/**
 * Implements NTLM session security for WinRM
 * Based on MS-NLMP specification
 */
class NTLMSessionSecurity {
    /**
     * Creates a new NTLM session security context
     * @param {Object} config - Configuration object
     * @param {Buffer} config.signing_key - Key for signing messages
     * @param {Buffer} config.sealing_key - Key for sealing (encrypting) messages
     * @param {number} config.seq_num - Initial sequence number (defaults to 0)
     */
    constructor({ signing_key, sealing_key, seq_num = 0 }) {
        this.signing_key = signing_key;
        this.sealing_key = sealing_key;
        this.seq_num = seq_num;
    }

    /**
     * Wraps (encrypts and signs) a message
     * @param {Buffer} message - Message to wrap
     * @returns {Object} Object containing sealed_message and signature
     */
    wrap(message) {
        // Get the sequence number as a buffer
        const seq = Buffer.alloc(4);
        seq.writeUInt32LE(this.seq_num);
        this.seq_num++;

        // Create version number buffer (1)
        const version = Buffer.alloc(4);
        version.writeUInt32LE(1);

        // Create the signature
        const hmac = crypto.createHmac('md5', this.signing_key);
        hmac.update(seq);
        hmac.update(message);
        const signature = Buffer.concat([
            version,
            hmac.digest().subarray(0, 8),
            seq
        ]);

        // Seal the message
        const rc4 = crypto.createCipheriv('rc4', this.sealing_key, '');
        const sealed_message = rc4.update(message);

        return {
            sealed_message,
            signature
        };
    }

    /**
     * Unwraps (decrypts and verifies) a message
     * @param {Buffer} sealed_message - Encrypted message
     * @param {Buffer} signature - Message signature
     * @returns {Buffer} Decrypted and verified message
     */
    unwrap(sealed_message, signature) {
        // Extract components from signature
        const version = signature.subarray(0, 4);
        const checksum = signature.subarray(4, 12);
        const seq = signature.subarray(12, 16);

        // Decrypt the message
        const rc4 = crypto.createDecipheriv('rc4', this.sealing_key, '');
        const message = rc4.update(sealed_message);

        // Verify the signature
        const hmac = crypto.createHmac('md5', this.signing_key);
        hmac.update(seq);
        hmac.update(message);
        const calculatedChecksum = hmac.digest().subarray(0, 8);

        if (Buffer.compare(checksum, calculatedChecksum) !== 0) {
            throw new Error('Message signature verification failed');
        }

        return message;
    }
}
