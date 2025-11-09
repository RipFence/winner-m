# JavaScript WinRM Library Design Document

## Executive Summary

This document outlines the architecture and design for a JavaScript WinRM library that enables Node.js applications to remotely execute commands on Windows servers using the Windows Remote Management (WinRM) protocol. The library will provide both high-level and low-level APIs similar to pywinrm's Session and Protocol classes, with comprehensive NTLM authentication support and SSL/TLS connection security.

## Design Principles

1. **API Compatibility**: Follow pywinrm's dual-layer architecture for familiarity
2. **Security First**: Default to secure configurations, require TLS for production
3. **Promise-based**: Modern JavaScript async/await patterns
4. **Modular Design**: Separate concerns for authentication, transport, and protocol
5. **Robust Error Handling**: Comprehensive error types and debugging information
6. **TypeScript Ready**: Full type definitions for better developer experience

## Library Architecture

### Core Components

```
winner-m/
├── src/
│   ├── WinRM.js              # Main library entry point
│   ├── Session.js            # High-level API (like pywinrm Session)
│   ├── Protocol.js           # Low-level API (like pywinrm Protocol)
│   ├── auth/
│   │   ├── AuthManager.js    # Authentication orchestration
│   │   ├── NTLMAuth.js       # NTLM authentication implementation
│   │   └── BasicAuth.js      # Basic authentication (optional)
│   ├── protocol/
│   │   ├── SOAPBuilder.js    # WinRM SOAP message construction
│   │   ├── XMLParser.js      # WinRM response parsing
│   │   ├── CommandExecutor.js # Command execution logic
│   │   └── ShellManager.js   # Shell lifecycle management
│   ├── transport/
│   │   ├── HttpClient.js     # HTTP connection management
│   │   ├── SSLValidator.js   # Certificate validation
│   │   └── ConnectionPool.js # Connection reuse and pooling
│   ├── types/
│   │   ├── WinRMTypes.ts     # TypeScript type definitions
│   │   └── AuthTypes.ts      # Authentication type definitions
│   └── utils/
│       ├── XMLUtils.js       # XML manipulation utilities
│       ├── Logging.js        # Logging framework
│       └── ErrorTypes.js     # Custom error classes
```

### API Design

#### High-Level API (Session)

```javascript
const winrm = require('winner-m');

// Create a session with configuration
const session = new winrm.Session({
  host: 'windows-server.example.com',
  port: 5986, // HTTPS port
  protocol: 'https',
  auth: {
    type: 'ntlm',
    username: 'domain\\user',
    password: 'password',
    workstation: 'LINUX-CLIENT',
    domain: 'EXAMPLE'
  },
  ssl: {
    rejectUnauthorized: true, // Certificate validation
    ca: customCA, // Custom CA certificate
    timeout: 30000
  },
  operationTimeout: 60000,
  readTimeout: 30000,
  maxShellTime: 60
});

// Execute commands
const result = await session.run('ipconfig /all');
console.log(result.stdout);
console.log(result.stderr);
console.log(result.statusCode);

// Execute PowerShell
const psResult = await session.runPS('Get-Process | Select-Object -First 5');
console.log(psResult.stdout);

// Execute commands with environment variables
const envResult = await session.run('echo %USERNAME%', {
  workingDirectory: 'C:\\temp',
  environmentVars: {
    CUSTOM_VAR: 'custom_value'
  }
});
```

#### Low-Level API (Protocol)

```javascript
const winrm = require('winner-m');

const protocol = new winrm.Protocol({
  host: 'windows-server.example.com',
  port: 5986,
  protocol: 'https',
  transport: 'ntlm',
  username: 'domain\\user',
  password: 'password',
  workstation: 'LINUX-CLIENT',
  domain: 'EXAMPLE',
  path: '/wsman'
});

// Low-level operations
await protocol.openShell();
const commandId = await protocol.runCommand('cmd.exe', '/c dir C:\\');
const output = await protocol.getCommandOutput(commandId);
await protocol.cleanupCommand(commandId);
await protocol.closeShell();
```

## Authentication Architecture

### NTLM Authentication Flow

```javascript
class NTLMAuth {
  constructor(options) {
    this.domain = options.domain;
    this.username = options.username;
    this.password = options.password;
    this.workstation = options.workstation || 'UNKNOWN-WORKSTATION';
  }

  async authenticate(agent, authHeaders = {}) {
    // NTLM Type 1: Negotiate
    const type1 = this.buildType1Message();
    authHeaders['Authorization'] = `NTLM ${type1}`;
    
    // Send initial request
    const challengeResponse = await agent.request(authHeaders);
    
    // NTLM Type 3: Authentication
    const type3 = this.buildType3Message(challengeResponse);
    authHeaders['Authorization'] = `NTLM ${type3}`;
    
    // Send final request
    return await agent.request(authHeaders);
  }

  buildType1Message() {
    // Build NTLM Type 1 message with proper flags
    const flags = this.getNegotiateFlags();
    return this.encodeMessage({
      signature: 'NTLMSSP\0',
      messageType: 1,
      flags,
      suppliedDomain: this.domain,
      suppliedWorkstation: this.workstation
    });
  }

  buildType3Message(serverChallenge) {
    // Parse Type 2 challenge and build Type 3 response
    const challenge = this.parseChallenge(serverChallenge);
    const ntlmResponse = this.calculateNTLMResponse(challenge);
    const lmResponse = this.calculateLMResponse(challenge);
    
    return this.encodeMessage({
      signature: 'NTLMSSP\0',
      messageType: 3,
      lmResponse,
      ntlmResponse,
      targetName: this.domain,
      userName: this.username,
      workstation: this.workstation
    });
  }
}
```

### Authentication Manager

```javascript
class AuthManager {
  constructor(options) {
    this.authMethods = {
      ntlm: new NTLMAuth(options),
      basic: new BasicAuth(options)
    };
    this.defaultMethod = options.type || 'ntlm';
  }

  async authenticate(agent, method = this.defaultMethod) {
    const authMethod = this.authMethods[method];
    if (!authMethod) {
      throw new Error(`Unsupported authentication method: ${method}`);
    }
    
    return await authMethod.authenticate(agent);
  }
}
```

## Protocol Implementation

### SOAP Message Builder

```javascript
class SOAPBuilder {
  static buildCreateShell() {
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
    <a:MessageID>uuid:${this.generateUUID()}</a:MessageID>
    <s:Body>
      <r:Shell xmlns:r="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd">
        <r:OperatingEnvironment>cmd</r:OperatingEnvironment>
      </r:Shell>
    </s:Body>
  </s:Header>
</s:Envelope>`;
  }

  static buildRunCommand(commandId, command) {
    return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <a:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</a:Action>
    <a:MessageID>uuid:${this.generateUUID()}</a:MessageID>
    <w:SelectorSet>
      <w:Selector Name="ShellId">${commandId}</w:Selector>
    </w:SelectorSet>
    <s:Body>
      <r:CommandLine xmlns:r="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd">
        <r:Command>${command}</r:Command>
      </r:CommandLine>
    </s:Body>
  </s:Header>
</s:Envelope>`;
  }
}
```

### Connection Management

```javascript
class HttpClient {
  constructor(options) {
    this.baseURL = `${options.protocol}://${options.host}:${options.port}`;
    this.timeout = options.timeout || 30000;
    this.agent = new https.Agent({
      keepAlive: true,
      keepAliveMsecs: 60000,
      maxFreeSockets: 10,
      maxSockets: 10,
      rejectUnauthorized: options.ssl?.rejectUnauthorized !== false
    });
  }

  async request(method, path, data, headers = {}) {
    const options = {
      method,
      path,
      headers: {
        'Content-Type': 'application/soap+xml; charset=UTF-8',
        'User-Agent': 'JS-WinRM Client',
        ...headers
      },
      timeout: this.timeout,
      agent: this.agent
    };

    try {
      const response = await this.performRequest(options, data);
      return this.parseResponse(response);
    } catch (error) {
      throw new WinRMConnectionError(`HTTP request failed: ${error.message}`, error);
    }
  }
}
```

## Configuration Options

### Session Configuration

```typescript
interface SessionConfig {
  host: string;
  port?: number;
  protocol?: 'http' | 'https';
  path?: string;
  auth: {
    type: 'ntlm' | 'basic';
    username: string;
    password: string;
    domain?: string;
    workstation?: string;
  };
  ssl?: {
    rejectUnauthorized?: boolean;
    ca?: string | Buffer;
    cert?: string;
    key?: string;
    passphrase?: string;
  };
  timeouts?: {
    operationTimeout?: number; // Command execution timeout
    readTimeout?: number;      // HTTP read timeout
    connectTimeout?: number;   // Connection timeout
    maxShellTime?: number;     // Maximum shell lifetime
  };
  retries?: {
    maxRetries?: number;
    retryDelay?: number;
  };
}
```

### Result Object

```typescript
interface WinRMResult {
  statusCode: number;
  stdout: string;
  stderr: string;
  exitCode?: number;
  shellId?: string;
  commandId?: string;
  startTime?: Date;
  endTime?: Date;
  duration?: number;
}
```

## Error Handling

### Custom Error Classes

```javascript
class WinRMError extends Error {
  constructor(message, code, details) {
    super(message);
    this.name = 'WinRMError';
    this.code = code;
    this.details = details;
  }
}

class WinRMAuthenticationError extends WinRMError {
  constructor(message, authMethod) {
    super(message, 'AUTHENTICATION_FAILED', { authMethod });
    this.name = 'WinRMAuthenticationError';
  }
}

class WinRMConnectionError extends WinRMError {
  constructor(message, cause) {
    super(message, 'CONNECTION_FAILED', { cause });
    this.name = 'WinRMConnectionError';
  }
}

class WinRMCommandError extends WinRMError {
  constructor(message, command, exitCode, stdout, stderr) {
    super(message, 'COMMAND_FAILED', { command, exitCode, stdout, stderr });
    this.name = 'WinRMCommandError';
  }
}
```

## Security Considerations

### SSL/TLS Configuration

```javascript
// Secure SSL configuration
const secureOptions = {
  ssl: {
    rejectUnauthorized: true, // Always validate certificates
    ca: customCA, // Use custom CA for internal certs
    // Or provide specific cert/key for client authentication
    cert: clientCert,
    key: clientKey
  }
};

// Insecure configuration (only for testing)
const insecureOptions = {
  ssl: {
    rejectUnauthorized: false // ❌ Never use in production
  }
};
```

### Best Practices

1. **Always use HTTPS** in production environments
2. **Validate server certificates** to prevent man-in-the-middle attacks
3. **Use strong passwords** and prefer certificate-based authentication
4. **Implement proper timeout handling** to prevent resource exhaustion
5. **Log security events** for auditing and monitoring
6. **Use connection pooling** to maintain persistent connections
7. **Implement retry logic** with exponential backoff for transient failures

## Testing Strategy

### Unit Tests
- Authentication flow testing
- SOAP message generation
- Response parsing
- Error handling scenarios

### Integration Tests
- Mock Windows server responses
- End-to-end command execution
- SSL/TLS certificate validation
- NTLM authentication with test domain

### Security Tests
- Certificate validation edge cases
- Authentication failure handling
- Timeout and retry behavior
- Connection pool management

## Dependencies

### Core Dependencies
- `xml2js` - XML parsing and building
- `uuid` - UUID generation for correlation IDs
- `undici` - Modern HTTP client for persistent connections
- `https` - TLS/SSL connection handling

### Optional Dependencies
- `ntlm-js` - NTLM protocol implementation (or use our own)
- `@types/node` - TypeScript type definitions

## Performance Considerations

1. **Connection Reuse**: Maintain persistent HTTP connections for NTLM
2. **Connection Pooling**: Limit concurrent connections per target
3. **Command Queuing**: Queue commands when shell limit reached
4. **Async/Await**: Use modern JavaScript patterns for better performance
5. **Memory Management**: Properly dispose of shells and command contexts
6. **Timeout Optimization**: Balance between responsiveness and reliability

## Future Enhancements

1. **Kerberos Authentication**: Support for modern domain authentication
2. **PowerShell Remoting**: Rich PowerShell-specific features
3. **File Transfer**: SCP/SFTP integration for file operations
4. **Event Subscription**: Windows Event Log monitoring
5. **PowerShell Core Support**: Cross-platform PowerShell integration
6. **Batch Execution**: Execute multiple commands in a single shell
7. **Interactive Sessions**: Pseudo-terminal support for interactive commands

This design provides a solid foundation for a production-ready JavaScript WinRM library that will be familiar to pywinrm users while providing modern JavaScript/Node.js best practices.