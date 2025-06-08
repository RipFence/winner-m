// package.json
// This file defines the project and its dependencies.
// To use this library, save this content as package.json in your project root,
// then run 'npm install' or 'yarn install' to download the necessary packages.
{
  "name": "winrm-js-client",
  "version": "0.0.1",
  "description": "A JavaScript (Node.js) client for Windows Remote Management (WinRM) with NTLM authentication.",
  "main": "index.js",
  "private": true,
  "scripts": {
    "start": "node example.js"
  },
  "dependencies": {
    "axios": "^1.6.8",
    "fast-xml-parser": "^4.4.1",
    "md4": "^1.0.0",
    "node-client-ntlm": "^1.1.2"
  },
  "keywords": [
    "winrm",
    "windows",
    "remote management",
    "ntlm",
    "javascript",
    "nodejs"
  ],
  "author": "Gemini AI",
  "license": "MIT"
}
```javascript
// winrm-protocol.js
// This module handles the construction and parsing of WinRM SOAP messages.
// It defines the XML structure for various WinRM operations and extracts
// relevant data from the server's responses.

import { XMLBuilder, XMLParser } from 'fast-xml-parser';

// Define common XML namespaces used in WinRM SOAP messages.
const XML_NAMESPACES = {
    SOAP_ENV: '[http://www.w3.org/2003/05/soap-envelope](http://www.w3.org/2003/05/soap-envelope)',
    WS_A: '[http://schemas.xmlsoap.org/ws/2004/08/addressing](http://schemas.xmlsoap.org/ws/2004/08/addressing)',
    WS_MAN: '[http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd](http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd)',
    WS_ENUM: '[http://schemas.xmlsoap.org/ws/2004/09/enumeration](http://schemas.xmlsoap.org/ws/2004/09/enumeration)',
    WS_TRANSFER: '[http://schemas.xmlsoap.org/ws/2004/09/transfer](http://schemas.xmlsoap.org/ws/2004/09/transfer)',
    WS_SHELL: '[http://schemas.microsoft.com/wbem/wsman/1/windows/shell](http://schemas.microsoft.com/wbem/wsman/1/windows/shell)',
    RSP: '[http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd](http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd)', // WinRM Shell Protocol specific
    CIM: '[http://schemas.dmtf.org/wbem/wscim/1/common](http://schemas.dmtf.org/wbem/wscim/1/common)', // Common Information Model
    WSCIM: '[http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ManagedSystemElement](http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ManagedSystemElement)',
    WS_IDENTITY: '[http://schemas.dmtf.org/wbem/wsman/1/wsman/identity](http://schemas.dmtf.org/wbem/wsman/1/wsman/identity)', // for identify op
    WS_FAULT: '[http://www.w3.org/2003/05/soap-fault](http://www.w3.org/2003/05/soap-fault)',
};

// XML parsing options for fast-xml-parser.
// Crucial to maintain namespaces and attributes for WinRM.
const PARSER_OPTIONS = {
    ignoreAttributes: false,
    attributeNamePrefix: '@_', // Prefix for attributes to differentiate from elements
    textNodeName: '#text',      // Name for text nodes
    ignoreNameSpace: false,
    parseNodeValue: true,
    parseAttributeValue: true,
    trimValues: true,
    cdataPropName: '__cdata', // For CDATA sections, like base64 encoded output
};

// XML building options for fast-xml-parser.
const BUILDER_OPTIONS = {
    attributeNamePrefix: '@_',
    ignoreAttributes: false,
    cdataPropName: '__cdata',
    format: true, // Pretty print XML
    indentBy: "  ",
};

export class WinRmProtocol {
    constructor(options = {}) {
        this.options = {
            locale: options.locale || 'en-US',
            dataLocale: options.dataLocale || 'en-US',
            maxEnvelopeSize: options.maxEnvelopeSize || 153600,
            operationTimeout: options.operationTimeout || 'PT60S', // 60 seconds
            ...options
        };
        this.parser = new XMLParser(PARSER_OPTIONS);
        this.builder = new XMLBuilder(BUILDER_OPTIONS);
    }

    /**
     * Generates a unique message ID for WS-Addressing.
     * @returns {string} A UUID-formatted message ID.
     */
    _generateMessageId() {
        return `uuid:${crypto.randomUUID()}`;
    }

    /**
     * Creates a base SOAP envelope with common headers.
     * @param {string} actionUri - The WS-Addressing Action URI.
     * @param {string} resourceUri - The WS-Management Resource URI.
     * @param {string} toUri - The destination URI for the request.
     * @param {string} messageId - The unique message ID.
     * @returns {object} The base SOAP envelope object structure.
     */
    _createBaseEnvelope(actionUri, resourceUri, toUri, messageId) {
        return {
            's:Envelope': {
                '@_xmlns:s': XML_NAMESPACES.SOAP_ENV,
                '@_xmlns:wsa': XML_NAMESPACES.WS_A,
                '@_xmlns:wsman': XML_NAMESPACES.WS_MAN,
                's:Header': {
                    'wsa:Action': actionUri,
                    'wsa:MessageID': messageId,
                    'wsa:ReplyTo': {
                        'wsa:Address': {
                            '@_s:mustUnderstand': 'true',
                            '#text': XML_NAMESPACES.WS_A + '/anon'
                        }
                    },
                    'wsa:To': toUri,
                    'wsman:Locale': {
                        '@_xml:lang': this.options.locale,
                        '@_mustUnderstand': 'false'
                    },
                    'wsman:DataLocale': {
                        '@_xml:lang': this.options.dataLocale,
                        '@_mustUnderstand': 'false'
                    },
                    'wsman:MaxEnvelopeSize': {
                        '@_s:mustUnderstand': 'true',
                        '#text': this.options.maxEnvelopeSize
                    },
                    'wsman:OperationTimeout': this.options.operationTimeout,
                    'wsman:ResourceURI': {
                        '@_s:mustUnderstand': 'true',
                        '#text': resourceUri
                    }
                },
                's:Body': {}
            }
        };
    }

    /**
     * Builds the XML request for creating a new shell.
     * @param {string} toUri - The destination URI.
     * @returns {string} The XML string for the CreateShell request.
     */
    buildCreateShellRequest(toUri) {
        const messageId = this._generateMessageId();
        const envelope = this._createBaseEnvelope(
            XML_NAMESPACES.WS_SHELL + '/Create',
            XML_NAMESPACES.WS_SHELL + '/cmd',
            toUri,
            messageId
        );

        envelope['s:Envelope']['s:Header']['wsman:OptionSet'] = {
            'wsman:Option': [
                { '@_Name': 'WINRM_COMMUNICATION_MODE', '#text': 'Stream' },
                { '@_Name': 'WINRM_STRICT_CONTENT_TYPE', '#text': 'true' }
            ]
        };

        envelope['s:Envelope']['s:Body']['rsp:Shell'] = {
            '@_xmlns:rsp': XML_NAMESPACES.RSP,
            'rsp:InputStreams': 'stdin',
            'rsp:OutputStreams': 'stdout stderr'
        };

        return this.builder.build(envelope);
    }

    /**
     * Parses the XML response from a CreateShell operation.
     * @param {string} xmlResponse - The XML response string.
     * @returns {object} An object containing the ShellId.
     */
    parseCreateShellResponse(xmlResponse) {
        const jsonObj = this.parser.parse(xmlResponse);
        const shellId = jsonObj['s:Envelope']['s:Body']['rsp:Shell']['wsman:SelectorSet']['wsman:Selector']['#text'];
        return { shellId };
    }

    /**
     * Builds the XML request for running a command within a shell.
     * @param {string} toUri - The destination URI.
     * @param {string} shellId - The ID of the active shell.
     * @param {string} command - The command to execute.
     * @param {string[]} args - An array of command arguments.
     * @returns {string} The XML string for the RunCommand request.
     */
    buildRunCommandRequest(toUri, shellId, command, args = []) {
        const messageId = this._generateMessageId();
        const envelope = this._createBaseEnvelope(
            XML_NAMESPACES.WS_SHELL + '/Command',
            XML_NAMESPACES.WS_SHELL + '/cmd',
            toUri,
            messageId
        );

        envelope['s:Envelope']['s:Header']['wsman:SelectorSet'] = {
            'wsman:Selector': {
                '@_Name': 'ShellId',
                '#text': shellId
            }
        };

        const commandElement = {
            '@_xmlns:rsp': XML_NAMESPACES.RSP,
            'rsp:Command': command
        };

        if (args.length > 0) {
            commandElement['rsp:Arguments'] = args;
        }

        envelope['s:Envelope']['s:Body']['rsp:CommandAndArguments'] = commandElement;

        return this.builder.build(envelope);
    }

    /**
     * Parses the XML response from a RunCommand operation.
     * @param {string} xmlResponse - The XML response string.
     * @returns {object} An object containing the CommandId.
     */
    parseRunCommandResponse(xmlResponse) {
        const jsonObj = this.parser.parse(xmlResponse);
        const commandId = jsonObj['s:Envelope']['s:Body']['rsp:CommandResponse']['rsp:CommandId']['#text'];
        return { commandId };
    }

    /**
     * Builds the XML request for receiving output from a command.
     * @param {string} toUri - The destination URI.
     * @param {string} shellId - The ID of the active shell.
     * @param {string} commandId - The ID of the running command.
     * @param {string} desiredStream - 'stdout' or 'stderr' or 'stdout stderr'.
     * @returns {string} The XML string for the Receive request.
     */
    buildReceiveRequest(toUri, shellId, commandId, desiredStream = 'stdout stderr') {
        const messageId = this._generateMessageId();
        const envelope = this._createBaseEnvelope(
            XML_NAMESPACES.WS_SHELL + '/Receive',
            XML_NAMESPACES.WS_SHELL + '/cmd',
            toUri,
            messageId
        );

        envelope['s:Envelope']['s:Header']['wsman:SelectorSet'] = {
            'wsman:Selector': {
                '@_Name': 'ShellId',
                '#text': shellId
            }
        };

        envelope['s:Envelope']['s:Body']['rsp:Receive'] = {
            '@_xmlns:rsp': XML_NAMESPACES.RSP,
            'rsp:DesiredStream': {
                '@_CommandId': commandId,
                '#text': desiredStream
            }
        };

        return this.builder.build(envelope);
    }

    /**
     * Parses the XML response from a Receive operation.
     * @param {string} xmlResponse - The XML response string.
     * @returns {object} An object containing command status, stdout, and stderr.
     */
    parseReceiveResponse(xmlResponse) {
        const jsonObj = this.parser.parse(xmlResponse);
        const shellResponse = jsonObj['s:Envelope']['s:Body']['rsp:ReceiveResponse']['rsp:Stream'];
        const commandState = jsonObj['s:Envelope']['s:Body']['rsp:ReceiveResponse']['rsp:CommandState'];

        let stdout = '';
        let stderr = '';
        let exitCode = null;

        // Ensure shellResponse is an array for consistent processing, even if only one stream
        const streams = Array.isArray(shellResponse) ? shellResponse : [shellResponse];

        for (const stream of streams) {
            if (stream && stream['@_Name'] === 'stdout' && stream['#text']) {
                stdout += Buffer.from(stream['#text'], 'base64').toString('utf8');
            }
            if (stream && stream['@_Name'] === 'stderr' && stream['#text']) {
                stderr += Buffer.from(stream['#text'], 'base64').toString('utf8');
            }
        }

        if (commandState && commandState['@_State'] === XML_NAMESPACES.WS_SHELL + '/CommandState/Done') {
            exitCode = commandState['rsp:ExitCode']['#text'];
        }

        return {
            stdout,
            stderr,
            exitCode,
            done: commandState ? commandState['@_State'] === XML_NAMESPACES.WS_SHELL + '/CommandState/Done' : false
        };
    }

    /**
     * Builds the XML request for sending a signal to a command.
     * @param {string} toUri - The destination URI.
     * @param {string} shellId - The ID of the active shell.
     * @param {string} commandId - The ID of the running command.
     * @param {string} signalCode - The signal code (e.g., '[http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate](http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate)').
     * @returns {string} The XML string for the Signal request.
     */
    buildSignalRequest(toUri, shellId, commandId, signalCode) {
        const messageId = this._generateMessageId();
        const envelope = this._createBaseEnvelope(
            XML_NAMESPACES.WS_SHELL + '/Signal',
            XML_NAMESPACES.WS_SHELL + '/cmd',
            toUri,
            messageId
        );

        envelope['s:Envelope']['s:Header']['wsman:SelectorSet'] = {
            'wsman:Selector': {
                '@_Name': 'ShellId',
                '#text': shellId
            }
        };

        envelope['s:Envelope']['s:Body']['rsp:Signal'] = {
            '@_xmlns:rsp': XML_NAMESPACES.RSP,
            '@_CommandId': commandId,
            'rsp:Code': signalCode
        };

        return this.builder.build(envelope);
    }

    /**
     * Builds the XML request for deleting a shell.
     * @param {string} toUri - The destination URI.
     * @param {string} shellId - The ID of the shell to delete.
     * @returns {string} The XML string for the DeleteShell request.
     */
    buildDeleteShellRequest(toUri, shellId) {
        const messageId = this._generateMessageId();
        const envelope = this._createBaseEnvelope(
            XML_NAMESPACES.WS_TRANSFER + '/Delete',
            XML_NAMESPACES.WS_SHELL + '/cmd',
            toUri,
            messageId
        );

        envelope['s:Envelope']['s:Header']['wsman:SelectorSet'] = {
            'wsman:Selector': {
                '@_Name': 'ShellId',
                '#text': shellId
            }
        };

        return this.builder.build(envelope);
    }

    /**
     * Parses a generic SOAP fault response.
     * @param {string} xmlResponse - The XML response string.
     * @returns {object} An error object with code and message.
     */
    parseFaultResponse(xmlResponse) {
        const jsonObj = this.parser.parse(xmlResponse);
        const fault = jsonObj['s:Envelope']['s:Body']['s:Fault'];
        const code = fault['s:Code']['s:Subcode']?.['s:Value'] || 'UNKNOWN_FAULT';
        const reason = fault['s:Reason']['s:Text']?.['#text'] || 'An unknown SOAP fault occurred.';
        return { code, message: reason };
    }
}
```javascript
// winrm-transport.js
// This module handles HTTP/HTTPS communication and integrates NTLM authentication.
// It uses Axios for requests and node-client-ntlm for the NTLM handshake.

import axios from 'axios';
import { NtlmClient } from 'node-client-ntlm';

export class WinRmTransport {
    /**
     * @param {string} host - The hostname or IP address of the Windows server.
     * @param {number} port - The port for WinRM (5985 for HTTP, 5986 for HTTPS).
     * @param {string} username - The username for NTLM authentication.
     * @param {string} password - The password for NTLM authentication.
     * @param {object} options - Configuration options for the transport.
     * @param {boolean} [options.https=true] - Whether to use HTTPS. Defaults to true for security.
     * @param {number} [options.timeout=60000] - Request timeout in milliseconds.
     * @param {boolean} [options.rejectUnauthorized=true] - For HTTPS, whether to reject self-signed certs.
     * @param {boolean} [options.allowUnencrypted=false] - Allows unencrypted HTTP with NTLM. HIGHLY INSECURE.
     */
    constructor(host, port, username, password, options = {}) {
        this.host = host;
        this.port = port;
        this.username = username;
        this.password = password;
        this.options = {
            https: true,
            timeout: 60000, // Default to 60 seconds
            rejectUnauthorized: true, // For HTTPS, reject self-signed certificates by default
            allowUnencrypted: false, // Strongly discourage unencrypted HTTP
            ...options
        };

        if (!this.options.https && !this.options.allowUnencrypted) {
            console.warn(
                'WARNING: Using HTTP (not HTTPS) with NTLM is highly insecure ' +
                'and allows credentials and messages to be trivially recovered. ' +
                'Set `allowUnencrypted: true` to proceed, but ONLY for testing. ' +
                'ALWAYS use HTTPS in production.'
            );
            throw new Error('HTTP with NTLM is blocked by default for security. Set allowUnencrypted: true to override.');
        }

        this.baseUrl = `${this.options.https ? 'https' : 'http'}://${host}:${port}/wsman`;
        this.axiosInstance = axios.create({
            baseURL: this.baseUrl,
            timeout: this.options.timeout,
            headers: {
                'Content-Type': 'application/soap+xml;charset=UTF-8',
                'User-Agent': 'WinRM-JS-Client'
            },
            // Ensure response is treated as a string, not parsed as JSON
            transformResponse: [data => data],
            // For Node.js HTTPS, configure certificate rejection
            ...(this.options.https && {
                httpsAgent: new (require('https').Agent)({
                    rejectUnauthorized: this.options.rejectUnauthorized
                })
            })
        });

        this.ntlmClient = new NtlmClient(this.username, this.password, this.host);
        this._setupNtlmInterceptor();
    }

    /**
     * Sets up an Axios interceptor to handle the NTLM challenge-response handshake.
     * This intercepts 401 Unauthorized responses and injects NTLM authorization headers.
     * The NTLM handshake involves three steps:
     * 1. Client sends Type 1 (Negotiate) message.
     * 2. Server responds with 401 and WWW-Authenticate containing Type 2 (Challenge) message.
     * 3. Client sends Type 3 (Authenticate) message with Authorization header.
     */
    _setupNtlmInterceptor() {
        this.axiosInstance.interceptors.request.use(async (config) => {
            // Check if NTLM negotiation has already started or completed
            if (this.ntlmClient.isNegotiating || this.ntlmClient.isAuthenticated) {
                return config;
            }

            // Start NTLM negotiation by sending Type 1 message
            this.ntlmClient.startNegotiation();
            const type1Msg = this.ntlmClient.createType1Message();
            config.headers['Authorization'] = `NTLM ${type1Msg}`;
            return config;
        }, (error) => {
            return Promise.reject(error);
        });

        this.axiosInstance.interceptors.response.use(
            (response) => {
                // If NTLM negotiation was in progress and we got a successful response,
                // it means authentication finished, or it was not NTLM auth.
                if (this.ntlmClient.isNegotiating) {
                    this.ntlmClient.markAuthenticated();
                }
                return response;
            },
            async (error) => {
                const originalRequest = error.config;
                // If it's a 401 Unauthorized and NTLM negotiation is ongoing or can start
                if (error.response && error.response.status === 401 &&
                    error.response.headers['www-authenticate'] &&
                    error.response.headers['www-authenticate'].includes('NTLM') &&
                    !originalRequest._retry) { // Ensure we don't get into an infinite retry loop

                    originalRequest._retry = true; // Mark request as retried

                    const wwwAuthenticateHeader = error.response.headers['www-authenticate'];
                    const ntlmChallengeMatch = wwwAuthenticateHeader.match(/NTLM\s+([a-zA-Z0-9\/+=]+)/);

                    if (ntlmChallengeMatch && ntlmChallengeMatch[1]) {
                        const type2Msg = ntlmChallengeMatch[1];
                        try {
                            // Process Type 2 (Challenge) and create Type 3 (Authenticate) message
                            const type3Msg = this.ntlmClient.createType3Message(type2Msg);

                            // Update the Authorization header for the original request and retry
                            originalRequest.headers['Authorization'] = `NTLM ${type3Msg}`;
                            this.ntlmClient.markAuthenticated(); // Assume success if Type 3 generated
                            return this.axiosInstance(originalRequest);
                        } catch (ntlmError) {
                            console.error('NTLM authentication error:', ntlmError.message);
                            return Promise.reject(new Error(`NTLM authentication failed: ${ntlmError.message}`));
                        }
                    }
                }
                // For any other error or if NTLM already failed
                return Promise.reject(error);
            }
        );
    }

    /**
     * Sends a WinRM SOAP request.
     * @param {string} xmlBody - The XML string representing the SOAP request body.
     * @returns {Promise<string>} A promise that resolves with the XML response body.
     */
    async sendRequest(xmlBody) {
        try {
            const response = await this.axiosInstance.post('', xmlBody);
            return response.data;
        } catch (error) {
            let errorMessage = 'An unknown error occurred during WinRM request.';
            if (error.response) {
                // The request was made and the server responded with a status code
                // that falls out of the range of 2xx
                errorMessage = `WinRM HTTP Error: ${error.response.status} ${error.response.statusText}. Response: ${error.response.data}`;
            } else if (error.request) {
                // The request was made but no response was received
                errorMessage = `WinRM Network Error: No response received. ${error.message}`;
            } else {
                // Something happened in setting up the request that triggered an Error
                errorMessage = `WinRM Request Setup Error: ${error.message}`;
            }
            console.error('WinRM Transport Error:', errorMessage);
            throw new Error(errorMessage);
        }
    }
}
```javascript
// winrm-client.js
// This is the main client interface for interacting with WinRM.
// It orchestrates calls to the WinRmTransport and WinRmProtocol layers.

import { WinRmTransport } from './winrm-transport.js';
import { WinRmProtocol } from './winrm-protocol.js';

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
     * @param {boolean} [options.allowUnencrypted=false] - Allows unencrypted HTTP with NTLM. HIGHLY INSECURE.
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
            allowUnencrypted: false,
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
```javascript
// example.js
// This file demonstrates how to use the WinRmClient.
// Before running:
// 1. Ensure you have Node.js installed.
// 2. Save this file, package.json, winrm-client.js, winrm-transport.js, and winrm-protocol.js
//    in the same directory.
// 3. Run `npm install` in your terminal in that directory to install dependencies.
// 4. Configure your Windows server for WinRM (e.g., `winrm quickconfig -q` on the server).
//    Ensure the firewall allows connections on port 5986 (HTTPS) or 5985 (HTTP).
//    For NTLM over HTTP, you might need to enable `AllowUnencrypted` on the server (DANGER: INSECURE).
//    `winrm set winrm/config/service '@{AllowUnencrypted="true"}'`

import { WinRmClient } from './winrm-client.js';

// --- Configuration ---
const WINRM_HOST = 'YOUR_WINDOWS_SERVER_IP_OR_HOSTNAME'; // e.g., '192.168.1.100' or 'mywindowsserver.local'
const WINRM_USERNAME = 'YOUR_USERNAME'; // e.g., 'Administrator' or 'DOMAIN\\username'
const WINRM_PASSWORD = 'YOUR_PASSWORD';

// IMPORTANT: For production, ALWAYS use HTTPS.
// If your server uses a self-signed certificate, set rejectUnauthorized to false (less secure but needed for testing).
const CLIENT_OPTIONS = {
    port: 5986,          // Default WinRM HTTPS port
    https: true,         // Always prefer HTTPS
    timeout: 60000,      // 60 seconds
    rejectUnauthorized: false, // Set to false if using self-signed certificates for testing
    allowUnencrypted: false // Set to true ONLY IF using HTTP (port 5985) and accept severe security risks
};

async function runExample() {
    console.log('Starting WinRM client example...');

    const client = new WinRmClient(
        WINRM_HOST,
        WINRM_USERNAME,
        WINRM_PASSWORD,
        CLIENT_OPTIONS
    );

    try {
        console.log('\n--- Running a simple command (ipconfig) ---');
        const cmdResult = await client.runPsCommand('ipconfig /all');
        console.log('ipconfig Output:');
        console.log('STDOUT:\n', cmdResult.stdout);
        console.log('STDERR:\n', cmdResult.stderr);
        console.log('Exit Code:', cmdResult.exitCode);

        console.log('\n--- Running a PowerShell command (Get-Process) ---');
        // Example PowerShell command: Get-Process | Select-Object -First 5
        const psCommand = 'Get-Process | Select-Object -First 5 | Format-Table -AutoSize';
        const psResult = await client.runPsCommand('powershell -EncodedCommand', [psCommand]);
        console.log('Get-Process Output:');
        console.log('STDOUT:\n', psResult.stdout);
        console.log('STDERR:\n', psResult.stderr);
        console.log('Exit Code:', psResult.exitCode);

        console.log('\n--- Running a command that fails (nonExistentCommand) ---');
        try {
            const failResult = await client.runPsCommand('nonExistentCommand');
            console.log('Unexpected success for failing command:', failResult);
        } catch (error) {
            console.log('Expected error caught for failing command:', error.message);
        }

    } catch (error) {
        console.error('An unhandled error occurred during the example:', error);
    }
}

// Ensure the example runs when the script is executed.
runExample();

