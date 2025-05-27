import { Protocol } from './protocol.js';
import { parseString } from 'xml2js';
import { promisify } from 'util';

const parseXMLString = promisify(parseString);
export const VERSION = '0.0.1';

// Feature support attributes for multi-version clients
export const FEATURE_SUPPORTED_AUTHTYPES = ['basic', 'certificate', 'ntlm', 'kerberos', 'plaintext', 'ssl', 'credssp'];
export const FEATURE_READ_TIMEOUT = true;
export const FEATURE_OPERATION_TIMEOUT = true;
export const FEATURE_PROXY_SUPPORT = true;

/**
 * Response from a remote command execution
 */
export class Response {
    /**
     * @param {Object} args Response data
     * @param {Buffer} args.std_out Standard output
     * @param {Buffer} args.std_err Standard error
     * @param {number} args.status_code Exit status code
     */
    constructor({ std_out, std_err, status_code }) {
        this.std_out = std_out;
        this.std_err = std_err;
        this.status_code = status_code;
    }

    /**
     * String representation of the response
     * @returns {string}
     */
    toString() {
        return `<Response code ${this.status_code}, out "${this.std_out.slice(0, 20)}", err "${this.std_err.slice(0, 20)}">`;
    }
}

/**
 * WinRM Session handler
 */
export class Session {
    /**
     * Create a new WinRM session
     * @param {string} target Target host
     * @param {Object} auth Authentication credentials
     * @param {string} auth.username Username
     * @param {string} auth.password Password
     * @param {Object} [options] Additional options
     * @param {string} [options.transport='plaintext'] Transport type
     * @param {number} [options.read_timeout_sec] Read timeout in seconds
     * @param {number} [options.operation_timeout_sec] Operation timeout in seconds
     * @param {string} [options.realm] Authentication realm
     * @param {string} [options.service] Service name
     * @param {string} [options.keytab] Path to keytab file
     * @param {string} [options.ca_trust_path] CA trust path
     * @param {string} [options.cert_pem] Path to certificate file
     * @param {string} [options.cert_key_pem] Path to certificate key file
     * @param {string} [options.server_cert_validation] Server certificate validation
     * @param {boolean} [options.kerberos_delegation] Enable Kerberos delegation
     * @param {string} [options.kerberos_hostname_override] Kerberos hostname override
     * @param {string} [options.message_encryption] Message encryption mode
     * @param {boolean} [options.credssp_disable_tlsv1_2] Disable TLS 1.2 for CredSSP
     * @param {string} [options.credssp_auth_mechanism] CredSSP auth mechanism
     * @param {number} [options.credssp_minimum_version] CredSSP minimum version
     * @param {boolean} [options.send_cbt] Send channel binding token
     * @param {string} [options.proxy] Proxy configuration
     */
    constructor(target, { username, password }, options = {}) {
        this.url = this._buildUrl(target, options.transport || 'plaintext');
        this.protocol = new Protocol({
            endpoint: this.url,
            username,
            password,
            ...options
        });
    }

    /**
     * Run a command on the remote host
     * @param {string} command Command to run
     * @param {string[]} [args=[]] Command arguments
     * @returns {Promise<Response>} Command response
     */
    async runCmd(command, args = []) {
        const shellId = await this.protocol.openShell();
        const commandId = await this.protocol.runCommand(shellId, command, args);
        const [std_out, std_err, status_code] = await this.protocol.getCommandOutput(shellId, commandId);
        await this.protocol.cleanupCommand(shellId, commandId);
        await this.protocol.closeShell(shellId);
        
        return new Response({ std_out, std_err, status_code });
    }

    /**
     * Run a PowerShell script on the remote host
     * @param {string} script PowerShell script to run
     * @returns {Promise<Response>} Script response
     */
    async runPS(script) {
        // PowerShell requires UTF-16LE encoding for scripts
        const encodedScript = Buffer.from(script, 'utf16le').toString('base64');
        const response = await this.runCmd('powershell', ['-encodedcommand', encodedScript]);

        if (response.std_err.length) {
            response.std_err = await this._cleanErrorMsg(response.std_err);
        }

        return response;
    }

    /**
     * Clean up PowerShell CLIXML error messages
     * @private
     * @param {Buffer} msg Error message
     * @returns {Buffer} Cleaned error message
     */
    async _cleanErrorMsg(msg) {
        // Check if message starts with CLIXML header
        if (msg.slice(0, 11).toString() === '#< CLIXML\r\n') {
            try {
                // Remove CLIXML header
                const xmlString = msg.slice(11).toString();
                // Remove namespaces
                const strippedXml = this._stripNamespace(xmlString);
                
                // Parse XML
                const result = await parseXMLString(strippedXml);
                
                // Find all S nodes (error messages)
                const nodes = [];
                for (const key in result) {
                    if (Array.isArray(result[key])) {
                        nodes.push(...result[key].filter(node => node.S).map(node => node.S));
                    }
                }
                
                let newMsg = '';
                for (const node of nodes) {
                    if (node && node[0]) {
                        newMsg += node[0].replace(/_x000D__x000A_/g, '\n');
                    }
                }
                
                if (newMsg) {
                    return Buffer.from(newMsg.trim());
                }
            } catch (e) {
                console.warn('Error converting PowerShell error message:', e);
            }
        }
        
        return msg;
    }

    /**
     * Strip XML namespaces
     * @private
     * @param {string} xml XML string
     * @returns {string} XML without namespaces
     */
    _stripNamespace(xml) {
        return xml.replace(/xmlns=["'][^"']*["']/g, '');
    }

    /**
     * Build WinRM URL from target and transport
     * @private
     * @param {string} target Target host
     * @param {string} transport Transport type
     * @returns {string} WinRM URL
     */
    _buildUrl(target, transport) {
        // Fixed regex to be JavaScript compatible and case-insensitive
        const match = target.match(/^((?<scheme>https?):\/\/)?(?<host>[0-9a-z-_.]+)(:(?<port>\d+))?(?<path>(\/)?(wsman)?)?/i);
        if (!match) {
            throw new Error(`Invalid target URL: ${target}`);
        }

        const { groups } = match;
        const scheme = groups.scheme || (transport === 'ssl' ? 'https' : 'http');
        const host = groups.host;
        const port = groups.port || (transport === 'ssl' ? 5986 : 5985);
        const path = groups.path ? groups.path.replace(/^\//, '') : 'wsman';

        return `${scheme}://${host}:${port}/${path}`;
    }
}