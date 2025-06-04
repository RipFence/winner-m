import axios from 'axios';
import https from 'node:https';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { NtlmClient } from 'axios-ntlm';
import fs from 'fs';
import { WinRMError, InvalidCredentialsError, WinRMTransportError } from './exceptions.js';
import { Encryption } from './encryption.js';
import { NTLMAuth } from './ntlm.js';

// Constants for auth method availability
const HAVE_KERBEROS = false; // TODO: Implement with SPNEGO
const HAVE_NTLM = true;
const HAVE_CREDSSP = false; // TODO: Implement CredSSP support

// Warning state flags
let DISPLAYED_PROXY_WARNING = false;
let DISPLAYED_CA_TRUST_WARNING = false;

/**
 * Helper function to parse string to boolean
 * @param {string} value - The string value to convert to boolean
 * @returns {boolean}
 */
function strToBool(value) {
    const strValue = String(value).toLowerCase();
    if (['true', 't', 'yes', 'y', 'on', '1'].includes(strValue)) return true;
    if (['false', 'f', 'no', 'n', 'off', '0'].includes(strValue)) return false;
    throw new Error(`invalid truth value '${value}'`);
}

export class Transport {
    /**
     * @param {Object} config Configuration object
     * @param {string} config.endpoint WinRM endpoint URL
     * @param {string} [config.username] Username for authentication
     * @param {string} [config.password] Password for authentication
     * @param {string} [config.realm] Authentication realm
     * @param {string} [config.service='HTTP'] Service name for Kerberos
     * @param {string} [config.keytab] Path to keytab file
     * @param {('legacy_requests'|string)} [config.ca_trust_path='legacy_requests'] CA trust path
     * @param {string} [config.cert_pem] Path to certificate file in PEM format
     * @param {string} [config.cert_key_pem] Path to certificate key file in PEM format
     * @param {number} [config.read_timeout_sec] Read timeout in seconds
     * @param {('validate'|'ignore')} [config.server_cert_validation='validate'] Server certificate validation mode
     * @param {boolean|string} [config.kerberos_delegation=false] Enable Kerberos delegation
     * @param {string} [config.kerberos_hostname_override] Kerberos hostname override
     * @param {('auto'|'basic'|'certificate'|'ntlm'|'kerberos'|'credssp'|'plaintext'|'ssl')} [config.auth_method='auto'] Authentication method
     * @param {('auto'|'always'|'never')} [config.message_encryption='auto'] Message encryption mode
     * @param {boolean} [config.credssp_disable_tlsv1_2=false] Disable TLS 1.2 for CredSSP
     * @param {('auto'|'ntlm'|'kerberos')} [config.credssp_auth_mechanism='auto'] CredSSP auth mechanism
     * @param {number} [config.credssp_minimum_version=2] CredSSP minimum version
     * @param {boolean} [config.send_cbt=true] Send channel binding token
     * @param {('legacy_requests'|string|null)} [config.proxy='legacy_requests'] Proxy configuration
     */
    constructor({
        endpoint,
        username = null,
        password = null,
        realm = null,
        service = 'HTTP',
        keytab = null,
        ca_trust_path = 'legacy_requests',
        cert_pem = null,
        cert_key_pem = null,
        read_timeout_sec = null,
        server_cert_validation = 'validate',
        kerberos_delegation = false,
        kerberos_hostname_override = null,
        auth_method = 'auto',
        message_encryption = 'auto',
        credssp_disable_tlsv1_2 = false,
        credssp_auth_mechanism = 'auto',
        credssp_minimum_version = 2,
        send_cbt = true,
        proxy = 'legacy_requests'
    }) {
        // If auth_method is auto, try to determine the best method
        if (auth_method === 'auto') {
            if (HAVE_KERBEROS) {
                auth_method = 'kerberos';
            } else if (HAVE_NTLM) {
                auth_method = 'ntlm';
            } else {
                auth_method = 'basic';
            }
        }
        // Store configuration
        this.endpoint = endpoint;
        this.username = username;
        this.password = password;
        this.realm = realm;
        this.service = service;
        this.keytab = keytab;
        this.ca_trust_path = ca_trust_path;
        this.cert_pem = cert_pem;
        this.cert_key_pem = cert_key_pem;
        this.read_timeout_sec = read_timeout_sec;
        this.server_cert_validation = server_cert_validation;
        this.kerberos_hostname_override = kerberos_hostname_override;
        this.message_encryption = message_encryption;
        this.credssp_disable_tlsv1_2 = credssp_disable_tlsv1_2;
        this.credssp_auth_mechanism = credssp_auth_mechanism;
        this.credssp_minimum_version = credssp_minimum_version;
        this.send_cbt = send_cbt;
        this.proxy = proxy;

        if (!['validate', 'ignore', null].includes(this.server_cert_validation)) {
            throw new WinRMError(`invalid server_cert_validation mode: ${this.server_cert_validation}`);
        }

        // Convert kerberos_delegation to boolean
        this.kerberos_delegation = typeof kerberos_delegation === 'boolean' 
            ? kerberos_delegation 
            : strToBool(String(kerberos_delegation));

        this.auth_method = auth_method;
        this.default_headers = {
            'Content-Type': 'application/soap+xml;charset=UTF-8',
            'User-Agent': 'NodeJS WinRM client'
        };

        // Validate credential requirements
        if (this.auth_method !== 'kerberos') {
            if (this.auth_method === 'certificate' || 
                (this.auth_method === 'ssl' && (this.cert_pem || this.cert_key_pem))) {
                if (!this.cert_pem || !this.cert_key_pem) {
                    throw new InvalidCredentialsError('both cert_pem and cert_key_pem must be specified for cert auth');
                }
                if (!fs.existsSync(this.cert_pem)) {
                    throw new InvalidCredentialsError(`cert_pem file not found (${this.cert_pem})`);
                }
                if (!fs.existsSync(this.cert_key_pem)) {
                    throw new InvalidCredentialsError(`cert_key_pem file not found (${this.cert_key_pem})`);
                }
            } else {
                if (!this.username) {
                    throw new InvalidCredentialsError(`auth method ${this.auth_method} requires a username`);
                }
                if (this.password === null) {
                    throw new InvalidCredentialsError(`auth method ${this.auth_method} requires a password`);
                }
            }
        }

        this.client = null;
        this.encryption = null;
        this.auth = null;

        if (!['auto', 'always', 'never'].includes(this.message_encryption)) {
            throw new WinRMError(`invalid message_encryption arg: ${this.message_encryption}. Should be 'auto', 'always', or 'never'`);
        }
    }

    /**
     * Build or return the axios client with proper configuration
     * @returns {import('axios').AxiosInstance}
     */
    buildClient() {
        if (this.client) {
            return this.client;
        }

        const config = {
            baseURL: this.endpoint,
            timeout: this.read_timeout_sec ? this.read_timeout_sec * 1000 : undefined,
            headers: { ...this.default_headers },
            validateStatus: null, // Handle HTTP errors ourselves
        };

        // Handle proxy configuration
        if (this.proxy === null) {
            config.proxy = false;
        } else if (this.proxy !== 'legacy_requests') {
            config.proxy = {
                protocol: this.endpoint.startsWith('https') ? 'https' : 'http',
                host: new URL(this.proxy).hostname,
                port: new URL(this.proxy).port
            };
            if (config.proxy.protocol === 'https') {
                config.httpsAgent = new HttpsProxyAgent(this.proxy);
            }
        }

        // Handle SSL/TLS configuration
        if (this.server_cert_validation === 'validate') {
            config.httpsAgent = new https.Agent({
                rejectUnauthorized: true,
                ca: this.ca_trust_path !== 'legacy_requests' ? fs.readFileSync(this.ca_trust_path) : undefined
            });
        } else {
            config.httpsAgent = new https.Agent({
                rejectUnauthorized: false
            });
        }

        // Set up authentication
        let encryption_available = false;

        switch (this.auth_method) {
            case 'kerberos':
                if (!HAVE_KERBEROS) {
                    throw new WinRMError('requested auth method is kerberos, but kerberos support is not installed');
                }
                // TODO: Implement Kerberos authentication
                break;

            case 'ntlm':
                if (!HAVE_NTLM) {
                    throw new WinRMError('requested auth method is ntlm, but ntlm support is not installed');
                }
                this.auth = new NTLMAuth({
                    username: this.username,
                    password: this.password,
                    send_cbt: this.send_cbt
                });
                this.client = this.auth.getClient();
                encryption_available = true; // NTLM provides message encryption
                break;

            case 'basic':
            case 'plaintext':
                config.auth = {
                    username: this.username || '',
                    password: this.password || ''
                };
                break;

            case 'certificate':
            case 'ssl':
                if (this.auth_method === 'ssl' && !this.cert_pem && !this.cert_key_pem) {
                    config.auth = {
                        username: this.username || '',
                        password: this.password || ''
                    };
                } else {
                    config.cert = fs.readFileSync(this.cert_pem);
                    config.key = fs.readFileSync(this.cert_key_pem);
                    config.headers['Authorization'] = 'http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual';
                }
                encryption_available = this.auth_method === 'ssl' && config.cert && config.key;
                break;

            case 'credssp':
                if (!HAVE_CREDSSP) {
                    throw new WinRMError('requested auth method is credssp, but credssp support is not installed');
                }
                // TODO: Implement CredSSP authentication
                break;

            default:
                throw new WinRMError(`unsupported auth method: ${this.auth_method}`);
        }

        // Create the axios instance if not already created (NTLM creates its own)
        if (!this.client) {
            this.client = axios.create(config);
        }

        // Set up message encryption if needed
        if (this.message_encryption === 'always' && !encryption_available) {
            throw new WinRMError(`message encryption is set to 'always' but the selected auth method ${this.auth_method} does not support it`);
        } else if (encryption_available) {
            if (this.message_encryption === 'always' ||
                (this.message_encryption === 'auto' && !this.endpoint.toLowerCase().startsWith('https'))) {
                this.setupEncryption();
            }
        }

        return this.client;
    }

    /**
     * Set up message encryption
     */
    async setupEncryption() {
        const client = this.buildClient();
        // Send blank message to initialize security context
        await this._sendMessageRequest(null);

        if (this.auth_method === 'ntlm') {
            this.auth.initializeSessionSecurity();
        }

        this.encryption = new Encryption(this, this.auth_method);
    }

    /**
     * Close the client session
     */
    closeSession() {
        this.client = null;
        this.encryption = null;
    }

    /**
     * Send a message to the WinRM server
     * @param {string|Buffer} message The message to send
     * @returns {Promise<Buffer>} The response
     */
    async sendMessage(message) {
        const client = this.buildClient();

        // Ensure message is a Buffer
        if (typeof message === 'string') {
            message = Buffer.from(message, 'utf8');
        }

        let request;
        if (this.encryption) {
            request = this.encryption.prepareEncryptedRequest(this, this.endpoint, message);
            const response = await this._sendMessageRequest(request.body, request.headers);
            return this.encryption.parseEncryptedResponse(response);
        }

        const response = await this._sendMessageRequest(message);
        return this._getMessageResponseText(response);
    }

    /**
     * Send a request to the WinRM server
     * @param {Buffer|null} data The data to send
     * @param {Object} [extraHeaders={}] Additional headers to include in the request
     * @returns {Promise<import('axios').AxiosResponse>}
     */
    async _sendMessageRequest(data, extraHeaders = {}) {
        try {
            const headers = { ...this.default_headers, ...extraHeaders };
            const response = await this.client.post('', data, { headers });
            
            if (response.status >= 400) {
                if (response.status === 401) {
                    throw new InvalidCredentialsError('the specified credentials were rejected by the server');
                }
                throw new WinRMTransportError('http', response.status, response.data?.toString() || '');
            }
            
            return response;
        } catch (error) {
            if (error.response) {
                throw new WinRMTransportError(
                    'http',
                    error.response.status,
                    error.response.data?.toString() || ''
                );
            }
            throw error;
        }
    }

    /**
     * Get the response text from a response
     * @param {import('axios').AxiosResponse} response The response
     * @returns {Buffer} The response text
     */
    _getMessageResponseText(response) {
        return Buffer.from(response.data);
    }
}
