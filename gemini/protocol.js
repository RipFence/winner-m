// This module handles the construction and parsing of WinRM SOAP messages.
// It defines the XML structure for various WinRM operations and extracts
// relevant data from the server's responses.

import crypto from 'crypto';
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
