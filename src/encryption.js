import { URL } from 'url';
import { WinRMError } from './exceptions.js';

/**
 * Implementation of WinRM message encryption
 * Based on [MS-WSMV] v30.0 2016-07-14 specification
 */
export class Encryption {
    static SIXTEEN_KB = 16384;
    static MIME_BOUNDARY = Buffer.from('--Encrypted Boundary');

    /**
     * Creates an encryption handler for WinRM messages
     * @param {Object} session The session object that contains auth context
     * @param {string} protocol The authentication protocol (ntlm, kerberos, or credssp)
     */
    constructor(session, protocol) {
        this.protocol = protocol;
        this.session = session;

        // Set protocol-specific handlers based on the authentication type
        switch (protocol) {
            case 'ntlm':
                // Details under Negotiate [2.2.9.1.1] in MS-WSMV
                this.protocol_string = Buffer.from('application/HTTP-SPNEGO-session-encrypted');
                this._build_message = this._build_ntlm_message;
                this._decrypt_message = this._decrypt_ntlm_message;
                break;

            case 'credssp':
                // Details under CredSSP [2.2.9.1.3] in MS-WSMV
                this.protocol_string = Buffer.from('application/HTTP-CredSSP-session-encrypted');
                this._build_message = this._build_credssp_message;
                this._decrypt_message = this._decrypt_credssp_message;
                break;

            case 'kerberos':
                this.protocol_string = Buffer.from('application/HTTP-SPNEGO-session-encrypted');
                this._build_message = this._build_kerberos_message;
                this._decrypt_message = this._decrypt_kerberos_message;
                break;

            default:
                throw new WinRMError(`Encryption for protocol '${protocol}' not supported`);
        }
    }

    /**
     * Creates a prepared request with an encrypted message
     * @param {Object} session The session object
     * @param {string} endpoint The endpoint URL
     * @param {Buffer} message The message to encrypt
     * @returns {Object} Prepared request object
     */
    prepareEncryptedRequest(session, endpoint, message) {
        const host = new URL(endpoint).hostname;
        let contentType, encryptedMessage;

        if (this.protocol === 'credssp' && message.length > Encryption.SIXTEEN_KB) {
            contentType = 'multipart/x-multi-encrypted';
            encryptedMessage = Buffer.alloc(0);
            
            // Split message into 16KB chunks
            for (let i = 0; i < message.length; i += Encryption.SIXTEEN_KB) {
                const chunk = message.subarray(i, i + Encryption.SIXTEEN_KB);
                const encryptedChunk = this._encrypt_message(chunk, host);
                encryptedMessage = Buffer.concat([encryptedMessage, encryptedChunk]);
            }
        } else {
            contentType = 'multipart/encrypted';
            encryptedMessage = this._encrypt_message(message, host);
        }

        encryptedMessage = Buffer.concat([
            encryptedMessage,
            Encryption.MIME_BOUNDARY,
            Buffer.from('--\r\n')
        ]);

        const headers = {
            'Content-Length': encryptedMessage.length.toString(),
            'Content-Type': `${contentType};protocol="${this.protocol_string.toString()}";boundary="Encrypted Boundary"`
        };

        return {
            method: 'POST',
            headers,
            body: encryptedMessage
        };
    }

    /**
     * Decrypts a response from the server
     * @param {Object} response The response object
     * @returns {Buffer} Decrypted message
     */
    parseEncryptedResponse(response) {
        const contentType = response.headers['content-type'];

        if (contentType.includes(`protocol="${this.protocol_string.toString()}"`)) {
            const host = new URL(response.request.url).hostname;
            return this._decrypt_response(response, host);
        }

        return Buffer.from(response.data);
    }

    /**
     * Encrypts a message
     * @private
     * @param {Buffer} message Message to encrypt
     * @param {string} host Target host
     * @returns {Buffer} Encrypted message with MIME headers
     */
    _encrypt_message(message, host) {
        const messageLength = Buffer.from(message.length.toString());
        const encryptedStream = this._build_message(message, host);

        return Buffer.concat([
            Encryption.MIME_BOUNDARY,
            Buffer.from('\r\n\tContent-Type: '),
            this.protocol_string,
            Buffer.from('\r\n\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length='),
            messageLength,
            Buffer.from('\r\n'),
            Encryption.MIME_BOUNDARY,
            Buffer.from('\r\n\tContent-Type: application/octet-stream\r\n'),
            encryptedStream
        ]);
    }

    /**
     * Decrypts a response
     * @private
     * @param {Object} response Response object
     * @param {string} host Source host
     * @returns {Buffer} Decrypted message
     */
    _decrypt_response(response, host) {
        const content = Buffer.from(response.data);
        const parts = this._split_mime_parts(content);
        let message = Buffer.alloc(0);

        for (let i = 0; i < parts.length; i += 2) {
            const header = parts[i].trim();
            const payload = parts[i + 1];

            const expectedLength = parseInt(header.toString().split('Length=')[1]);
            let encryptedData = payload;

            // Remove MIME boundary if it exists
            if (payload.subarray(-24).compare(Buffer.concat([Encryption.MIME_BOUNDARY, Buffer.from('--\r\n')])) === 0) {
                encryptedData = payload.subarray(0, payload.length - 24);
            }

            // Remove content type header
            encryptedData = encryptedData.subarray(Buffer.from('\tContent-Type: application/octet-stream\r\n').length);

            const decryptedMessage = this._decrypt_message(encryptedData, host);

            if (decryptedMessage.length !== expectedLength) {
                throw new WinRMError('Encrypted length from server does not match the expected size, message has been tampered with');
            }

            message = Buffer.concat([message, decryptedMessage]);
        }

        return message;
    }

    /**
     * Splits MIME message into parts
     * @private
     * @param {Buffer} content MIME message
     * @returns {Buffer[]} Message parts
     */
    _split_mime_parts(content) {
        const boundary = Buffer.concat([Encryption.MIME_BOUNDARY, Buffer.from('\r\n')]);
        const parts = [];
        let start = 0;

        while (true) {
            const index = content.indexOf(boundary, start);
            if (index === -1) break;

            if (start !== index) {
                parts.push(content.subarray(start, index));
            }

            start = index + boundary.length;
        }

        // Add the last part if it exists
        if (start < content.length) {
            parts.push(content.subarray(start));
        }

        // Filter out empty parts
        return parts.filter(part => part.length > 0);
    }

    /**
     * Builds NTLM encrypted message
     * @private
     * @param {Buffer} message Message to encrypt
     * @param {string} host Target host
     * @returns {Buffer} Encrypted message
     */
    _build_ntlm_message(message, host) {
        const { sealed_message, signature } = this.session.auth.session_security.wrap(message);
        const signatureLength = Buffer.alloc(4);
        signatureLength.writeInt32LE(signature.length);

        return Buffer.concat([signatureLength, signature, sealed_message]);
    }

    /**
     * Decrypts NTLM message
     * @private
     * @param {Buffer} encryptedData Encrypted message
     * @param {string} host Source host
     * @returns {Buffer} Decrypted message
     */
    _decrypt_ntlm_message(encryptedData, host) {
        const signatureLength = encryptedData.readInt32LE(0);
        const signature = encryptedData.subarray(4, 4 + signatureLength);
        const encryptedMessage = encryptedData.subarray(4 + signatureLength);

        return this.session.auth.session_security.unwrap(encryptedMessage, signature);
    }

    /**
     * Builds CredSSP encrypted message
     * @private
     * @param {Buffer} message Message to encrypt
     * @param {string} host Target host
     * @returns {Buffer} Encrypted message
     */
    _build_credssp_message(message, host) {
        const credssp_context = this.session.auth.contexts[host];
        const sealed_message = credssp_context.wrap(message);
        const cipher_negotiated = credssp_context.tls_connection.get_cipher_name();
        const trailerLength = this._get_credssp_trailer_length(message.length, cipher_negotiated);
        
        const lengthBuf = Buffer.alloc(4);
        lengthBuf.writeInt32LE(trailerLength);

        return Buffer.concat([lengthBuf, sealed_message]);
    }

    /**
     * Decrypts CredSSP message
     * @private
     * @param {Buffer} encryptedData Encrypted message
     * @param {string} host Source host
     * @returns {Buffer} Decrypted message
     */
    _decrypt_credssp_message(encryptedData, host) {
        const encryptedMessage = encryptedData.subarray(4);
        const credssp_context = this.session.auth.contexts[host];
        return credssp_context.unwrap(encryptedMessage);
    }

    /**
     * Builds Kerberos encrypted message
     * @private
     * @param {Buffer} message Message to encrypt
     * @param {string} host Target host
     * @returns {Buffer} Encrypted message
     */
    _build_kerberos_message(message, host) {
        const { sealed_message, signature } = this.session.auth.wrap_winrm(host, message);
        const signatureLength = Buffer.alloc(4);
        signatureLength.writeInt32LE(signature.length);

        return Buffer.concat([signatureLength, signature, sealed_message]);
    }

    /**
     * Decrypts Kerberos message
     * @private
     * @param {Buffer} encryptedData Encrypted message
     * @param {string} host Source host
     * @returns {Buffer} Decrypted message
     */
    _decrypt_kerberos_message(encryptedData, host) {
        const signatureLength = encryptedData.readInt32LE(0);
        const signature = encryptedData.subarray(4, 4 + signatureLength);
        const encryptedMessage = encryptedData.subarray(4 + signatureLength);

        return this.session.auth.unwrap_winrm(host, encryptedMessage, signature);
    }

    /**
     * Calculates CredSSP trailer length
     * @private
     * @param {number} messageLength Length of the message
     * @param {string} cipherSuite Name of the cipher suite
     * @returns {number} Trailer length
     */
    _get_credssp_trailer_length(messageLength, cipherSuite) {
        // GCM ciphers have a fixed trailer length of 16 bytes
        if (/-GCM-[\w\d]*$/.test(cipherSuite)) {
            return 16;
        }

        // For non-GCM ciphers, calculate based on hash algorithm and cipher type
        const hashAlgorithm = cipherSuite.split('-').pop();
        let hashLength;

        switch (hashAlgorithm) {
            case 'MD5': hashLength = 16; break;
            case 'SHA': hashLength = 20; break;
            case 'SHA256': hashLength = 32; break;
            case 'SHA384': hashLength = 48; break;
            default: hashLength = 0;
        }

        const prePadLength = messageLength + hashLength;
        let paddingLength;

        if (cipherSuite.includes('RC4')) {
            paddingLength = 0; // Stream cipher, no padding
        } else if (cipherSuite.includes('DES') || cipherSuite.includes('3DES')) {
            paddingLength = 8 - (prePadLength % 8); // 64-bit block cipher
        } else {
            paddingLength = 16 - (prePadLength % 16); // 128-bit block cipher (AES)
        }

        return (prePadLength + paddingLength) - messageLength;
    }
}
