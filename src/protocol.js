// Contains client side logic of WinRM SOAP protocol implementation
import { v4 as uuidv4 } from 'uuid';
import { create } from 'xmlbuilder2';
import {
  WinRMError,
  WinRMOperationTimeoutError,
  WinRMTransportError,
  WSManFaultError,
} from './exceptions.js';
import { Transport } from './transport.js';

// XML Namespace definitions
export const xmlns = {
  s: 'http://www.w3.org/2003/05/soap-envelope',
  a: 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
  w: 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd',
  p: 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd',
  rsp: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell',
  x: 'http://schemas.xmlsoap.org/ws/2004/09/transfer'
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

    const doc = create({ version: '1.0', encoding: 'UTF-8' })
      .ele('s:Envelope', { 
        's': xmlns.s,
        'a': xmlns.a,
        'w': xmlns.w,
        'p': xmlns.p,
        'rsp': xmlns.rsp,
        'x': xmlns.x
      });

    const header = doc.ele('s:Header');
    header.ele('a:To').txt('http://windows-host:5985/wsman');
    header.ele('a:ReplyTo')
      .ele('a:Address', { mustUnderstand: 'true' })
      .txt('http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous');
    header.ele('w:MaxEnvelopeSize', { mustUnderstand: 'true' }).txt('153600');
    header.ele('a:MessageID').txt(`uuid:${message_id}`);
    header.ele('w:Locale', { mustUnderstand: 'false', 'xml:lang': 'en-US' });
    header.ele('p:DataLocale', { mustUnderstand: 'false', 'xml:lang': 'en-US' });
    header.ele('w:OperationTimeout').txt(`PT${parseInt(this.operation_timeout_sec)}S`);
    header.ele('w:ResourceURI', { mustUnderstand: 'true' }).txt(resource_uri);
    header.ele('a:Action', { mustUnderstand: 'true' }).txt(action);

    if (shell_id) {
      header.ele('w:SelectorSet')
        .ele('w:Selector', { Name: 'ShellId' })
        .txt(shell_id);
    }

    return doc;
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
    const doc = this.buildWsmanHeader({
      resource_uri: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
      action: 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create',
    });

    const optionSet = doc.root().ele('s:Body')
      .ele('w:OptionSet')
      .ele('w:Option', { Name: 'WINRS_NOPROFILE' }).txt(String(noprofile).toUpperCase()).up()
      .ele('w:Option', { Name: 'WINRS_CODEPAGE' }).txt(String(codepage));

    const shell = doc.root().ele('rsp:Shell');
    shell.ele('rsp:InputStreams').txt(i_stream);
    shell.ele('rsp:OutputStreams').txt(o_stream);

    if (working_directory) {
      shell.ele('rsp:WorkingDirectory').txt(working_directory);
    }

    if (idle_timeout) {
      shell.ele('rsp:IdleTimeout').txt(`PT${idle_timeout}S`);
    }

    if (env_vars) {
      const env = shell.ele('rsp:Environment');
      for (const [name, value] of Object.entries(env_vars)) {
        env.ele('rsp:Variable', { Name: name }).txt(value);
      }
    }

    const xmlStr = doc.end({ prettyPrint: false });
    const res = await this.transport.sendMessage(xmlStr);
    const result = create(res).toObject();

    return result['s:Envelope']['s:Body']['x:ResourceCreated']
      ['a:ReferenceParameters']['w:SelectorSet']['w:Selector']['_'];
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
    const doc = this.buildWsmanHeader({
      resource_uri: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
      action: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command',
      shell_id,
    });

    const optionSet = doc.root().ele('s:Body')
      .ele('w:OptionSet')
      .ele('w:Option', { Name: 'WINRS_CONSOLEMODE_STDIN' }).txt(String(console_mode_stdin).toUpperCase()).up()
      .ele('w:Option', { Name: 'WINRS_SKIP_CMD_SHELL' }).txt(String(skip_cmd_shell).toUpperCase());

    const cmdLine = doc.root().ele('s:Body')
      .ele('rsp:CommandLine')
      .ele('rsp:Command').txt(command);

    if (arguments_.length > 0) {
      const argsElem = cmdLine.up().ele('rsp:Arguments');
      for (const arg of arguments_) {
        argsElem.txt(arg);
      }
    }

    const xmlStr = doc.end({ prettyPrint: false });
    const res = await this.transport.sendMessage(xmlStr);
    const result = create(res).toObject();
    
    return result['s:Envelope']['s:Body']['rsp:CommandResponse']['rsp:CommandId'];
  }

  /**
   * Clean-up after a command
   * @param {string} shell_id The shell id on the remote machine
   * @param {string} command_id The command id to clean up
   * @returns {Promise<void>}
   */
  async cleanupCommand(shell_id, command_id) {
    const message_id = uuidv4();
    const doc = this.buildWsmanHeader({
      resource_uri: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
      action: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal',
      shell_id,
      message_id,
    });

    doc.root().ele('s:Body')
      .ele('rsp:Signal', { CommandId: command_id })
      .ele('rsp:Code')
      .txt('http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate');

    const xmlStr = doc.end({ prettyPrint: false });
    const res = await this.transport.sendMessage(xmlStr);
    const result = create(res).toObject();
    
    const relates_to = result['s:Envelope']['s:Header']['a:RelatesTo'].replace('uuid:', '');
    if (relates_to !== message_id) {
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
    const doc = this.buildWsmanHeader({
      resource_uri: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
      action: 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete',
      shell_id,
      message_id,
    });

    try {
      const xmlStr = doc.end({ prettyPrint: false });
      const res = await this.transport.sendMessage(xmlStr);
      const result = create(res).toObject();
      
      const relates_to = result['s:Envelope']['s:Header']['a:RelatesTo'].replace('uuid:', '');
      if (relates_to !== message_id) {
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
    const doc = this.buildWsmanHeader({
      resource_uri: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
      action: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive',
      shell_id,
    });

    doc.root().ele('s:Body')
      .ele('rsp:Receive')
      .ele('rsp:DesiredStream', { CommandId: command_id })
      .txt('stdout stderr');

    const xmlStr = doc.end({ prettyPrint: false });
    const res = await this.transport.sendMessage(xmlStr);
    const result = create(res).toObject();

    const stdout = [];
    const stderr = [];
    let return_code = -1;
    let command_done = false;

    // Get Response node
    const receiveResponse = result['s:Envelope']['s:Body']['rsp:ReceiveResponse'];

    // Process stream output
    if (receiveResponse['rsp:Stream']) {
      const streams = Array.isArray(receiveResponse['rsp:Stream']) 
        ? receiveResponse['rsp:Stream'] 
        : [receiveResponse['rsp:Stream']];

      for (const stream of streams) {
        if (stream['@Name'] === 'stdout' && stream['_']) {
          stdout.push(Buffer.from(stream['_'], 'base64'));
        } else if (stream['@Name'] === 'stderr' && stream['_']) {
          stderr.push(Buffer.from(stream['_'], 'base64'));
        }
      }
    }

    // Check if command is done and get exit code
    if (receiveResponse['rsp:CommandState']) {
      const state = receiveResponse['rsp:CommandState']['@State'];
      command_done = state.endsWith('CommandState/Done');
      if (command_done && receiveResponse['rsp:CommandState']['rsp:ExitCode']) {
        return_code = parseInt(receiveResponse['rsp:CommandState']['rsp:ExitCode'], 10);
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