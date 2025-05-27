// Contains client side logic of WinRM SOAP protocol implementation
import { v4 as uuidv4 } from 'uuid';
import { parseStringPromise, Builder } from 'xml2js';
import {
  WinRMError,
  WinRMOperationTimeoutError,
  WinRMTransportError,
  WSManFaultError,
} from './exceptions.js';

// Will be imported from transport.js once implemented
import { Transport } from './transport.js';

export const xmlns = {
  soapenv: 'http://www.w3.org/2003/05/soap-envelope',
  soapaddr: 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
  wsmanfault: 'http://schemas.microsoft.com/wbem/wsman/1/wsmanfault',
  wmierror: 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/MSFT_WmiError',
};

export class Protocol {
  static DEFAULT_READ_TIMEOUT_SEC = 30;
  static DEFAULT_OPERATION_TIMEOUT_SEC = 20;
  static DEFAULT_MAX_ENV_SIZE = 153600;
  static DEFAULT_LOCALE = 'en-US';

  /**
   * @param {Object} config The configuration object
   * @param {string} config.endpoint The WinRM webservice endpoint
   * @param {string} [config.transport='plaintext'] Transport type: 'plaintext', 'kerberos', 'ssl', 'ntlm', 'credssp'
   * @param {string} [config.username] Username for authentication
   * @param {string} [config.password] Password for authentication
   * @param {string} [config.realm] Realm for authentication
   * @param {string} [config.service='HTTP'] Service name
   * @param {string} [config.keytab] Path to keytab file
   * @param {string} [config.ca_trust_path='legacy_requests'] CA trust path
   * @param {string} [config.cert_pem] Path to certificate file in PEM format
   * @param {string} [config.cert_key_pem] Path to certificate key file in PEM format
   * @param {string} [config.server_cert_validation='validate'] Server certificate validation mode
   * @param {boolean} [config.kerberos_delegation=false] Enable Kerberos delegation
   * @param {number} [config.read_timeout_sec=30] Read timeout in seconds
   * @param {number} [config.operation_timeout_sec=20] Operation timeout in seconds
   * @param {string} [config.kerberos_hostname_override] Kerberos hostname override
   * @param {string} [config.message_encryption='auto'] Message encryption mode
   * @param {boolean} [config.credssp_disable_tlsv1_2=false] Disable TLS 1.2 for CredSSP
   * @param {boolean} [config.send_cbt=true] Send channel binding token
   * @param {string} [config.proxy='legacy_requests'] Proxy configuration
   */
  constructor({
    endpoint,
    transport = 'plaintext',
    username = null,
    password = null,
    realm = null,
    service = 'HTTP',
    keytab = null,
    ca_trust_path = 'legacy_requests',
    cert_pem = null,
    cert_key_pem = null,
    server_cert_validation = 'validate',
    kerberos_delegation = false,
    read_timeout_sec = Protocol.DEFAULT_READ_TIMEOUT_SEC,
    operation_timeout_sec = Protocol.DEFAULT_OPERATION_TIMEOUT_SEC,
    kerberos_hostname_override = null,
    message_encryption = 'auto',
    credssp_disable_tlsv1_2 = false,
    send_cbt = true,
    proxy = 'legacy_requests',
  }) {
    if (operation_timeout_sec >= read_timeout_sec || operation_timeout_sec < 1) {
      throw new WinRMError('Invalid operation_timeout_sec value');
    }

    this.read_timeout_sec = read_timeout_sec;
    this.operation_timeout_sec = operation_timeout_sec;
    this.max_env_sz = Protocol.DEFAULT_MAX_ENV_SIZE;
    this.locale = Protocol.DEFAULT_LOCALE;

    this.transport = new Transport({
      endpoint,
      username,
      password,
      realm,
      service,
      keytab,
      ca_trust_path,
      cert_pem,
      cert_key_pem,
      read_timeout_sec: this.read_timeout_sec,
      server_cert_validation,
      kerberos_delegation,
      kerberos_hostname_override,
      auth_method: transport,
      message_encryption,
      credssp_disable_tlsv1_2,
      send_cbt,
      proxy,
    });
  }

  /**
   * Build the WSMan header needed for operations
   * @param {Object} params Header parameters
   * @param {string} params.action The WSMan action to perform
   * @param {string} params.resource_uri The WSMan resource URI
   * @param {string} [params.shell_id] Optional shell UUID
   * @param {string} [params.message_id] Optional message UUID
   * @returns {Object} The WSMan header as an object
   */
  buildWsmanHeader({ action, resource_uri, shell_id = null, message_id = null }) {
    message_id = message_id || uuidv4();

    const header = {
      '@xmlns:xsd': 'http://www.w3.org/2001/XMLSchema',
      '@xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
      '@xmlns:env': xmlns.soapenv,
      '@xmlns:a': xmlns.soapaddr,
      '@xmlns:b': 'http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd',
      '@xmlns:n': 'http://schemas.xmlsoap.org/ws/2004/09/enumeration',
      '@xmlns:x': 'http://schemas.xmlsoap.org/ws/2004/09/transfer',
      '@xmlns:w': 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd',
      '@xmlns:p': 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd',
      '@xmlns:rsp': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell',
      '@xmlns:cfg': 'http://schemas.microsoft.com/wbem/wsman/1/config',
      'env:Header': {
        'a:To': 'http://windows-host:5985/wsman',
        'a:ReplyTo': {
          'a:Address': {
            '@mustUnderstand': 'true',
            '#text': 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous',
          },
        },
        'w:MaxEnvelopeSize': { '@mustUnderstand': 'true', '#text': '153600' },
        'a:MessageID': `uuid:${message_id}`,
        'w:Locale': { '@mustUnderstand': 'false', '@xml:lang': 'en-US' },
        'p:DataLocale': { '@mustUnderstand': 'false', '@xml:lang': 'en-US' },
        'w:OperationTimeout': `PT${parseInt(this.operation_timeout_sec)}S`,
        'w:ResourceURI': { '@mustUnderstand': 'true', '#text': resource_uri },
        'a:Action': { '@mustUnderstand': 'true', '#text': action },
      },
    };

    if (shell_id) {
      header['env:Header']['w:SelectorSet'] = {
        'w:Selector': { '@Name': 'ShellId', '#text': shell_id },
      };
    }

    return header;
  }

  /**
   * Open a shell on the destination host
   * @param {Object} options Shell options
   * @param {string} [options.i_stream='stdin'] Input stream
   * @param {string} [options.o_stream='stdout stderr'] Output stream
   * @param {string} [options.working_directory] Working directory
   * @param {Object} [options.env_vars] Environment variables
   * @param {boolean} [options.noprofile=false] No profile
   * @param {number} [options.codepage=437] Code page
   * @param {string} [options.lifetime] Shell lifetime
   * @param {number|string} [options.idle_timeout] Idle timeout
   * @returns {Promise<string>} Shell ID
   */
  async openShell({
    i_stream = 'stdin',
    o_stream = 'stdout stderr',
    working_directory = null,
    env_vars = null,
    noprofile = false,
    codepage = 437,
    lifetime = null,
    idle_timeout = null,
  } = {}) {
    const req = {
      'env:Envelope': this.buildWsmanHeader({
        resource_uri: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
        action: 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create',
      }),
    };

    const header = req['env:Envelope']['env:Header'];
    header['w:OptionSet'] = {
      'w:Option': [
        { '@Name': 'WINRS_NOPROFILE', '#text': String(noprofile).toUpperCase() },
        { '@Name': 'WINRS_CODEPAGE', '#text': String(codepage) },
      ],
    };

    const shell = req['env:Envelope']['env:Body'] = {
      'rsp:Shell': {
        'rsp:InputStreams': i_stream,
        'rsp:OutputStreams': o_stream,
      },
    };

    if (working_directory) {
      shell['rsp:Shell']['rsp:WorkingDirectory'] = working_directory;
    }

    if (idle_timeout) {
      shell['rsp:Shell']['rsp:IdleTimeout'] = `PT${idle_timeout}S`;
    }

    if (env_vars) {
      shell['rsp:Shell']['rsp:Environment'] = {
        'rsp:Variable': Object.entries(env_vars).map(([name, value]) => ({
          '@Name': name,
          '#text': value,
        })),
      };
    }

    const builder = new Builder();
    const res = await this.transport.sendMessage(builder.buildObject(req));
    const result = await parseStringPromise(res);
    
    return result['s:Envelope']['s:Body'][0]['x:ResourceCreated'][0]
      ['a:ReferenceParameters'][0]['w:SelectorSet'][0]['w:Selector'][0]['_'];
  }

  /**
   * Run a command on a machine with an open shell
   * @param {string} shell_id The shell id on the remote machine
   * @param {string} command The command to run
   * @param {string[]} [arguments=[]] Command arguments
   * @param {boolean} [console_mode_stdin=true] Console mode stdin
   * @param {boolean} [skip_cmd_shell=false] Skip CMD shell
   * @returns {Promise<string>} Command ID
   */
  async runCommand(
    shell_id,
    command,
    arguments_ = [],
    console_mode_stdin = true,
    skip_cmd_shell = false
  ) {
    const req = {
      'env:Envelope': this.buildWsmanHeader({
        resource_uri: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
        action: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command',
        shell_id,
      }),
    };

    const header = req['env:Envelope']['env:Header'];
    header['w:OptionSet'] = {
      'w:Option': [
        {
          '@Name': 'WINRS_CONSOLEMODE_STDIN',
          '#text': String(console_mode_stdin).toUpperCase(),
        },
        {
          '@Name': 'WINRS_SKIP_CMD_SHELL',
          '#text': String(skip_cmd_shell).toUpperCase(),
        },
      ],
    };

    const cmd_line = req['env:Envelope']['env:Body'] = {
      'rsp:CommandLine': {
        'rsp:Command': { '#text': command },
      },
    };

    if (arguments_.length > 0) {
      cmd_line['rsp:CommandLine']['rsp:Arguments'] = arguments_.map(arg => ({
        '#text': arg,
      }));
    }

    const builder = new Builder();
    const res = await this.transport.sendMessage(builder.buildObject(req));
    const result = await parseStringPromise(res);
    
    return result['s:Envelope']['s:Body'][0]['rsp:CommandResponse'][0]['rsp:CommandId'][0];
  }

  /**
   * Clean-up after a command
   * @param {string} shell_id The shell id on the remote machine
   * @param {string} command_id The command id to clean up
   * @returns {Promise<void>}
   */
  async cleanupCommand(shell_id, command_id) {
    const message_id = uuidv4();
    const req = {
      'env:Envelope': this.buildWsmanHeader({
        resource_uri: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
        action: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal',
        shell_id,
        message_id,
      }),
    };

    const signal = req['env:Envelope']['env:Body'] = {
      'rsp:Signal': {
        '@CommandId': command_id,
        'rsp:Code':
          'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate',
      },
    };

    const builder = new Builder();
    const res = await this.transport.sendMessage(builder.buildObject(req));
    const result = await parseStringPromise(res);
    
    const relates_to = result['s:Envelope']['s:Header'][0]['a:RelatesTo'][0];
    if (relates_to.replace('uuid:', '') !== message_id) {
      throw new WinRMError('Invalid response message ID');
    }
  }

  /**
   * Close the shell
   * @param {string} shell_id The shell id on the remote machine
   * @param {boolean} [close_session=true] Whether to close the session
   * @returns {Promise<void>}
   */
  async closeShell(shell_id, close_session = true) {
    const message_id = uuidv4();
    const req = {
      'env:Envelope': this.buildWsmanHeader({
        resource_uri: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
        action: 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete',
        shell_id,
        message_id,
      }),
    };

    try {
      const builder = new Builder();
      const res = await this.transport.sendMessage(builder.buildObject(req));
      const result = await parseStringPromise(res);
      
      const relates_to = result['s:Envelope']['s:Header'][0]['a:RelatesTo'][0];
      if (relates_to.replace('uuid:', '') !== message_id) {
        throw new WinRMError('Invalid response message ID');
      }
    } finally {
      if (close_session) {
        this.transport.closeSession();
      }
    }
  }

  /**
   * Get the raw output of a command, including whether it has finished executing
   * @param {string} shell_id The shell id on the remote machine
   * @param {string} command_id The command id on the remote machine
   * @returns {Promise<[Buffer, Buffer, number, boolean]>} Returns a tuple with stdout, stderr, return code, and done status
   * @throws {WinRMOperationTimeoutError} When there is no output from the command
   */
  async getCommandOutputRaw(shell_id, command_id) {
    const req = {
      'env:Envelope': this.buildWsmanHeader({
        resource_uri: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
        action: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive',
        shell_id,
      }),
    };

    req['env:Envelope']['env:Body'] = {
      'rsp:Receive': {
        'rsp:DesiredStream': {
          '@CommandId': command_id,
          '#text': 'stdout stderr',
        },
      },
    };

    const builder = new Builder();
    const res = await this.transport.sendMessage(builder.buildObject(req));
    const result = await parseStringPromise(res);

    const stdout = [];
    const stderr = [];
    let return_code = -1;
    let command_done = false;

    // Get Response node
    const receiveResponse = result['s:Envelope']['s:Body'][0]['rsp:ReceiveResponse'][0];

    // Process stream output
    if (receiveResponse['rsp:Stream']) {
      for (const stream of receiveResponse['rsp:Stream']) {
        const streamAttrs = stream.$;
        if (streamAttrs.Name === 'stdout' && stream._) {
          stdout.push(Buffer.from(stream._, 'base64'));
        } else if (streamAttrs.Name === 'stderr' && stream._) {
          stderr.push(Buffer.from(stream._, 'base64'));
        }
      }
    }

    // Check if command is done and get exit code
    if (receiveResponse['rsp:CommandState']) {
      const state = receiveResponse['rsp:CommandState'][0].$.State;
      command_done = state.endsWith('CommandState/Done');
      if (command_done && receiveResponse['rsp:CommandState'][0]['rsp:ExitCode']) {
        return_code = parseInt(receiveResponse['rsp:CommandState'][0]['rsp:ExitCode'][0], 10);
      }
    }

    return [
      Buffer.concat(stdout),
      Buffer.concat(stderr),
      return_code,
      command_done,
    ];
  }

  /**
   * Get the output of a command, waiting until it completes
   * @param {string} shell_id The shell id on the remote machine
   * @param {string} command_id The command id on the remote machine
   * @returns {Promise<[Buffer, Buffer, number]>} Returns a tuple with stdout, stderr, and return code
   */
  async getCommandOutput(shell_id, command_id) {
    const stdout_buffer = [];
    const stderr_buffer = [];
    let return_code = -1;
    let command_done = false;

    while (!command_done) {
      try {
        const [stdout, stderr, code, done] = await this.getCommandOutputRaw(shell_id, command_id);
        if (stdout.length) stdout_buffer.push(stdout);
        if (stderr.length) stderr_buffer.push(stderr);
        return_code = code;
        command_done = done;
      } catch (error) {
        if (error instanceof WinRMOperationTimeoutError) {
          // This is expected for long-running processes, just retry
          continue;
        }
        throw error;
      }
    }

    return [
      Buffer.concat(stdout_buffer),
      Buffer.concat(stderr_buffer),
      return_code,
    ];
  }
}