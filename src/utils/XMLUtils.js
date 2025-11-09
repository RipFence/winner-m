const { parseString, Builder } = require('xml2js');
const { v4: uuidv4 } = require('uuid');

/**
 * XML manipulation utilities for WinRM SOAP operations
 */
class XMLUtils {
  /**
   * Generate a unique UUID for message correlation
   */
  static generateUUID() {
    return uuidv4().toUpperCase();
  }

  /**
   * Build a WinRM SOAP envelope for shell creation
   */
  static buildCreateShell() {
    const messageId = this.generateUUID();
    
    return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/anonymous</a:Action>
    <w:OperationTimeout>PT60S</w:OperationTimeout>
    <a:MessageID>uuid:${messageId}</a:MessageID>
    <s:Body>
      <r:Shell xmlns:r="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd">
        <r:OperatingEnvironment>cmd</r:OperatingEnvironment>
      </r:Shell>
    </s:Body>
  </s:Header>
</s:Envelope>`;
  }

  /**
   * Build a WinRM SOAP envelope for command execution
   */
  static buildRunCommand(shellId, command) {
    const messageId = this.generateUUID();
    
    return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <a:Action s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wsman/1/cimrd/1/Command</a:Action>
    <a:MessageID>uuid:${messageId}</a:MessageID>
    <w:SelectorSet>
      <w:Selector Name="ShellId">${shellId}</w:Selector>
    </w:SelectorSet>
    <s:Body>
      <r:CommandLine xmlns:r="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd">
        <r:Command>${command}</r:Command>
      </r:CommandLine>
    </s:Body>
  </s:Header>
</s:Envelope>`;
  }

  /**
   * Build a WinRM SOAP envelope for getting command output
   */
  static buildGetCommandOutput(shellId, commandId) {
    const messageId = this.generateUUID();
    
    return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <a:Action s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wsman/1/cimrd/1/Receive</a:Action>
    <a:MessageID>uuid:${messageId}</a:MessageID>
    <w:SelectorSet>
      <w:Selector Name="ShellId">${shellId}</w:Selector>
      <w:Selector Name="CommandId">${commandId}</w:Selector>
    </w:SelectorSet>
    <s:Body>
      <r:Receive xmlns:r="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"/>
    </s:Body>
  </s:Header>
</s:Envelope>`;
  }

  /**
   * Build a WinRM SOAP envelope for deleting a command
   */
  static buildDeleteCommand(shellId, commandId) {
    const messageId = this.generateUUID();
    
    return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <a:Action s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wsman/1/cimrd/1/Delete</a:Action>
    <a:MessageID>uuid:${messageId}</a:MessageID>
    <w:SelectorSet>
      <w:Selector Name="ShellId">${shellId}</w:Selector>
      <w:Selector Name="CommandId">${commandId}</w:Selector>
    </w:SelectorSet>
    <s:Body/>
  </s:Header>
</s:Envelope>`;
  }

  /**
   * Build a WinRM SOAP envelope for closing a shell
   */
  static buildCloseShell(shellId) {
    const messageId = this.generateUUID();
    
    return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <a:Action s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wsman/1/cimrd/1/Delete</a:Action>
    <a:MessageID>uuid:${messageId}</a:MessageID>
    <w:SelectorSet>
      <w:Selector Name="ShellId">${shellId}</w:Selector>
    </w:SelectorSet>
    <s:Body/>
  </s:Header>
</s:Envelope>`;
  }

  /**
   * Parse WinRM SOAP response and extract shell ID
   */
  static parseCreateShellResponse(xml) {
    return new Promise((resolve, reject) => {
      parseString(xml, { explicitArray: false }, (err, result) => {
        if (err) {
          reject(err);
          return;
        }

        try {
          const envelope = result['s:Envelope'];
          if (!envelope) {
            throw new Error('Invalid SOAP envelope: missing Envelope element');
          }

          const body = envelope['s:Body'];
          if (!body) {
            throw new Error('Invalid SOAP envelope: missing Body element');
          }

          const shellResponse = body['r:ShellResponse'];
          if (!shellResponse) {
            throw new Error('Invalid response: missing ShellResponse element');
          }

          const shellId = shellResponse.ShellId;
          if (!shellId) {
            throw new Error('Invalid response: missing ShellId element');
          }

          resolve(shellId);
        } catch (parseError) {
          reject(parseError);
        }
      });
    });
  }

  /**
   * Parse WinRM command execution response
   */
  static parseRunCommandResponse(xml) {
    return new Promise((resolve, reject) => {
      parseString(xml, { explicitArray: false }, (err, result) => {
        if (err) {
          reject(err);
          return;
        }

        try {
          const envelope = result['s:Envelope'];
          const body = envelope['s:Body'];
          const commandResponse = body['r:CommandResponse'];
          
          resolve(commandResponse.CommandId);
        } catch (parseError) {
          reject(parseError);
        }
      });
    });
  }

  /**
   * Parse command output response
   */
  static parseCommandOutputResponse(xml) {
    return new Promise((resolve, reject) => {
      parseString(xml, { explicitArray: false }, (err, result) => {
        if (err) {
          reject(err);
          return;
        }

        try {
          const envelope = result['s:Envelope'];
          const body = envelope['s:Body'];
          const receiveResponse = body['r:ReceiveResponse'];
          
          if (!receiveResponse) {
            resolve({ stdout: '', stderr: '', exitCode: 0 });
            return;
          }

          const stream = receiveResponse.Stream;
          if (!stream) {
            resolve({ stdout: '', stderr: '', exitCode: 0 });
            return;
          }

          let stdout = '';
          let stderr = '';

          if (Array.isArray(stream)) {
            stream.forEach(s => {
              if (s.$.Name === 'stdout') {
                stdout += Buffer.from(s._, 'base64').toString('utf8');
              } else if (s.$.Name === 'stderr') {
                stderr += Buffer.from(s._, 'base64').toString('utf8');
              }
            });
          } else {
            if (stream.$.Name === 'stdout') {
              stdout = Buffer.from(stream._, 'base64').toString('utf8');
            } else if (stream.$.Name === 'stderr') {
              stderr = Buffer.from(stream._, 'base64').toString('utf8');
            }
          }

          const exitCode = receiveResponse.ExitCode ? parseInt(receiveResponse.ExitCode) : 0;

          resolve({ stdout, stderr, exitCode });
        } catch (parseError) {
          reject(parseError);
        }
      });
    });
  }

  /**
   * Check if response contains a fault
   */
  static checkForFault(xml) {
    if (xml.includes('<s:Fault>')) {
      return new Promise((resolve, reject) => {
        parseString(xml, { explicitArray: false }, (err, result) => {
          if (err) {
            reject(err);
            return;
          }

          try {
            const envelope = result['s:Envelope'];
            const body = envelope['s:Body'];
            const fault = body['s:Fault'];
            
            const faultCode = fault.faultcode;
            const faultString = fault.faultstring;
            const detail = fault.detail;
            
            const error = new Error(`WinRM Fault: ${faultString} (Code: ${faultCode})`);
            error.code = faultCode;
            error.detail = detail;
            
            reject(error);
          } catch (parseError) {
            reject(parseError);
          }
        });
      });
    }
    return Promise.resolve(false);
  }
}

module.exports = XMLUtils;