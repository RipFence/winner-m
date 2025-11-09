# JS-WinRM: JavaScript Windows Remote Management Library

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-16%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

A robust JavaScript library for Windows Remote Management (WinRM) that enables Node.js applications to remotely execute commands and PowerShell scripts on Windows servers with multiple authentication methods including NTLM, Kerberos, and CredSSP.

## Features

- ✅ **Multiple Authentication Methods** - NTLM, Kerberos, and CredSSP support
- ✅ **NTLM Authentication** - Secure domain authentication
- ✅ **Kerberos Authentication** - Enterprise-grade single sign-on
- ✅ **CredSSP Authentication** - Network level authentication with credentials
- ✅ **SSL/TLS Support** - HTTPS connections with certificate validation
- ✅ **Dual API Architecture** - High-level Session and low-level Protocol classes
- ✅ **PowerShell Support** - Execute PowerShell scripts with proper encoding
- ✅ **Command Execution** - Run Windows commands and batch files
- ✅ **Connection Management** - Persistent connections and connection pooling
- ✅ **Error Handling** - Comprehensive error types and detailed error messages
- ✅ **Timeout Management** - Configurable timeouts for different operations
- ✅ **TypeScript Support** - Full type definitions for better development experience
- ✅ **Logging** - Configurable logging with sanitized sensitive data
- ✅ **Batch Operations** - Execute multiple commands sequentially
- ✅ **Environment Management** - Working directory and environment variable support

## Installation

```bash
npm install winner-m
```

### Kerberos Dependencies

For Kerberos authentication, you may need to install system dependencies depending on your platform:

**Ubuntu/Debian:**
```bash
sudo apt-get install krb5-user libkrb5-dev
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install krb5-devel krb5-workstation
# or on newer versions:
sudo dnf install krb5-devel krb5-workstation
```

**macOS:**
```bash
brew install krb5
```

**Windows:**
Kerberos is typically built into Windows, but you may need the Microsoft Visual C++ Redistributable for native module compilation.

### Environment Configuration

For Kerberos authentication, configure your krb5.conf file:

```ini
[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log

[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    EXAMPLE.COM = {
        kdc = kerberos.example.com
        admin_server = kerberos.example.com
        default_domain = example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
```

## Quick Start

### Basic Usage

```javascript
const winrm = require('winner-m');

// Quick command execution
const result = await winrm.runCommand({
  host: 'windows-server.example.com',
  protocol: 'https',
  port: 5986,
  auth: {
    type: 'ntlm',
    username: 'domain\\user',
    password: 'password',
    domain: 'EXAMPLE'
  }
}, 'hostname');

console.log(result.stdout);
console.log(result.exitCode);
```

### Session-based Usage

```javascript
const { Session } = require('winner-m');

const session = new Session({
  host: 'windows-server.example.com',
  protocol: 'https',
  port: 5986,
  auth: {
    type: 'ntlm',
    username: 'domain\\user',
    password: 'password',
    domain: 'EXAMPLE'
  },
  ssl: {
    rejectUnauthorized: false  // Set to true in production
  }
});

// Test connection
const isConnected = await session.ping();

// Run commands
const hostname = await session.run('hostname');
const systemInfo = await session.runPS('Get-ComputerInfo | Select-Object -Property *');

await session.close();
```

### PowerShell Execution

```javascript
const psScript = `
# Get system information
$os = Get-WmiObject -Class Win32_OperatingSystem
Write-Output "OS: $($os.Caption)"
Write-Output "Version: $($os.Version)"
Write-Output "Memory: $([math]::Round($os.TotalVisibleMemorySize / 1MB, 2)) GB"
`;

const result = await session.runPS(psScript);
console.log(result.stdout);
```

## Authentication Methods

Winner-m supports three authentication methods, each with different security properties and use cases:

### NTLM Authentication
- **Use case**: Basic domain authentication for environments without Kerberos
- **Security**: Medium - vulnerable to relay attacks
- **Setup complexity**: Low
- **Domain requirements**: Active Directory domain
- **Single Sign-On**: No

### Kerberos Authentication  
- **Use case**: Enterprise environments requiring strong authentication and SSO
- **Security**: High - mutual authentication, ticket-based
- **Setup complexity**: Medium - requires Kerberos infrastructure
- **Domain requirements**: Active Directory domain with Kerberos enabled
- **Single Sign-On**: Yes

### CredSSP Authentication
- **Use case**: Environments requiring credential delegation and NLA
- **Security**: High - network level authentication with credential delegation
- **Setup complexity**: Medium-High - requires CredSSP configuration
- **Domain requirements**: Active Directory domain
- **Single Sign-On**: Limited - requires credential caching

## API Reference

### Session Class (High-level API)

The Session class provides a simplified interface for most common WinRM operations.

#### Constructor

```javascript
const session = new Session(options);
```

**Options:**
- `host` (string, required) - Windows host address
- `port` (number) - WinRM port (default: 5986 for HTTPS, 5985 for HTTP)
- `protocol` ('http' | 'https') - Connection protocol (default: 'https')
- `auth` (object, required) - Authentication configuration
  - `type` ('ntlm' | 'kerberos' | 'credssp' | 'basic') - Authentication method
  - `username` (string) - Username
  - `password` (string) - Password
  - `domain` (string) - Domain name (required for Kerberos, optional for others)
  - `workstation` (string) - Workstation name (optional, used for NTLM)
  - `spn` (string) - Service Principal Name (required for Kerberos)
  - `realm` (string) - Kerberos realm (required for Kerberos)
  - `keytab` (string) - Path to keytab file (optional for Kerberos)
  - `delegateCredentials` (boolean) - Enable credential delegation (CredSSP only)
- `ssl` (object) - SSL/TLS configuration
  - `rejectUnauthorized` (boolean) - Validate server certificates
  - `ca` (string | Buffer) - Custom CA certificate
  - `cert` (string | Buffer) - Client certificate
  - `key` (string | Buffer) - Client key
- `timeouts` (object) - Timeout configuration
  - `connectTimeout` (number) - Connection timeout in ms (default: 30000)
  - `readTimeout` (number) - Read timeout in ms (default: 60000)
  - `operationTimeout` (number) - Operation timeout in ms (default: 300000)
- `workingDirectory` (string) - Default working directory (default: 'C:\\')
- `environmentVars` (object) - Default environment variables

#### Methods

##### `run(command, options)`
Execute a Windows command.

```javascript
const result = await session.run('ipconfig /all', {
  workingDirectory: 'C:\\temp',
  environmentVars: { CUSTOM_VAR: 'value' }
});
```

##### `runPS(powerShellScript, options)`
Execute a PowerShell script.

```javascript
const psScript = `
Get-Process | Where-Object {$_.ProcessName -eq 'chrome'} | 
Select-Object ProcessName, Id, CPU, WorkingSet
`;

const result = await session.runPS(psScript);
```

##### `runBatch(commands)`
Execute multiple commands sequentially.

```javascript
const commands = [
  { command: 'mkdir C:\\temp\\test', continueOnError: false },
  { command: 'echo "test" > C:\\temp\\test\\file.txt', continueOnError: false },
  { command: 'type C:\\temp\\test\\file.txt', continueOnError: false }
];

const results = await session.runBatch(commands);
```

##### `getSystemInfo()`
Get system information.

```javascript
const info = await session.getSystemInfo();
console.log(info); // { hostname, osVersion, currentUser, connected }
```

##### `test()`
Test connection to the host.

```javascript
const isAlive = await session.test();
```

##### `close()`
Close the session and clean up resources.

```javascript
await session.close();
```

### Protocol Class (Low-level API)

The Protocol class provides direct access to WinRM operations for advanced use cases.

#### Methods

##### `openShell()`
Open a WinRM shell.

```javascript
await protocol.openShell();
```

##### `closeShell()`
Close the current shell.

```javascript
await protocol.closeShell();
```

##### `runCommand(command, args)`
Run a command and return the command ID.

```javascript
const commandId = await protocol.runCommand('cmd.exe', '/c dir C:\\');
```

##### `getCommandOutput(commandId)`
Get output from a running command.

```javascript
const output = await protocol.getCommandOutput(commandId);
```

##### `waitForCommand(commandId, pollInterval)`
Wait for command completion and return output.

```javascript
const result = await protocol.waitForCommand(commandId);
```

##### `runCommandAndWait(command, args, pollInterval)`
Run a command and wait for completion in one call.

```javascript
const result = await protocol.runCommandAndWait('cmd.exe', '/c echo "Hello World"');
```

### WinRM Main Class

Utility functions for quick operations.

#### `connect(options)`
Create and test a connection to a Windows host.

```javascript
const session = await winrm.connect(config);
```

#### `runCommand(options, command)`
Execute a single command.

```javascript
const result = await winrm.runCommand(config, 'hostname');
```

#### `runPowerShell(options, script)`
Execute a single PowerShell script.

```javascript
const result = await winrm.runPowerShell(config, 'Get-Host | Select-Object Version');
```

## Error Handling

The library provides comprehensive error handling with custom error types:

```javascript
const winrm = require('winner-m');

const {
  WinRMError,
  WinRMAuthenticationError,
  WinRMConnectionError,
  WinRMCommandError,
  WinRMConfigurationError
} = winrm;

try {
  await session.run('some-command');
} catch (error) {
  switch (error.constructor.name) {
    case 'WinRMAuthenticationError':
      console.error('Authentication failed:', error.message);
      break;
    case 'WinRMConnectionError':
      console.error('Connection failed:', error.message);
      break;
    case 'WinRMCommandError':
      console.error('Command failed:', error.message);
      console.error('Exit code:', error.details.exitCode);
      console.error('Output:', error.details.stdout);
      console.error('Error:', error.details.stderr);
      break;
    default:
      console.error('Unknown error:', error.message);
  }
}
```

## Security Considerations

### Authentication Method Security

#### NTLM Security Considerations
- **Vulnerability**: Susceptible to relay attacks and man-in-the-middle attacks
- **Mitigation**: Always use HTTPS, implement proper network segmentation
- **Best Practice**: Use in trusted networks only, combine with certificate validation
- **Recommendation**: Prefer Kerberos in enterprise environments

#### Kerberos Security Considerations
- **Strengths**: Mutual authentication, ticket-based, resistant to replay attacks
- **Requirements**: Proper time synchronization (max 5 minutes difference)
- **Mitigation**: Use strong keytab file permissions, regular ticket rotation
- **Best Practice**: Implement proper SPN configuration and monitoring
- **Recommendation**: Best choice for enterprise environments with AD

#### CredSSP Security Considerations
- **Strengths**: Network Level Authentication, credential delegation support
- **Vulnerability**: Credentials are transmitted to target server when delegating
- **Mitigation**: Only enable delegateCredentials when necessary
- **Best Practice**: Use with proper access controls and auditing
- **Recommendation**: Use when credential delegation is required

### General Security Best Practices

#### 1. Use HTTPS Always

```javascript
const config = {
  protocol: 'https',  // Always prefer HTTPS
  port: 5986,         // HTTPS port
  ssl: {
    rejectUnauthorized: true  // Validate certificates
  }
};
```

### 2. Certificate Validation

```javascript
const config = {
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync('ca-certificate.crt'),    // Custom CA
    cert: fs.readFileSync('client-certificate.crt'), // Client cert
    key: fs.readFileSync('client-private-key.key')    // Client key
  }
};
```

### 3. Environment Variables

```javascript
const config = {
  auth: {
    username: process.env.WINRM_USERNAME,
    password: process.env.WINRM_PASSWORD,
    domain: process.env.WINRM_DOMAIN
  }
};
```

## Configuration Examples

### Domain Authentication

```javascript
const domainConfig = {
  host: 'server.example.com',
  protocol: 'https',
  port: 5986,
  auth: {
    type: 'ntlm',
    username: 'john.doe',
    password: 'secure_password',
    domain: 'EXAMPLE',  // Domain name
    workstation: 'MY-COMPUTER'
  }
};
```

### Local Account Authentication

```javascript
const localConfig = {
  host: '192.168.1.100',
  protocol: 'https',
  port: 5986,
  auth: {
    type: 'ntlm',
    username: 'administrator',
    password: 'local_password',
    domain: '',  // Empty for local accounts
    workstation: 'MY-COMPUTER'
  }
};
```

### Certificate-based Authentication

```javascript
const certConfig = {
  host: 'server.example.com',
  protocol: 'https',
  port: 5986,
  auth: {
    type: 'basic',  // Note: Basic auth over HTTPS
    username: 'service-account',
    password: 'service_password'
  },
  ssl: {
    ca: fs.readFileSync('ca.crt'),
    cert: fs.readFileSync('client.crt'),
    key: fs.readFileSync('client.key')
  }
};
```

### Kerberos Authentication

#### With Password
```javascript
const kerberosConfig = {
  host: 'server.example.com',
  protocol: 'https',
  port: 5986,
  auth: {
    type: 'kerberos',
    username: 'john.doe',
    password: 'password',
    domain: 'EXAMPLE',           // Domain name
    realm: 'EXAMPLE.COM',        // Kerberos realm
    spn: 'HTTP/server.example.com'  // Service Principal Name
  }
};

const session = new Session(kerberosConfig);
const result = await session.run('whoami');
```

#### With Keytab File
```javascript
const kerberosKeytabConfig = {
  host: 'server.example.com',
  protocol: 'https',
  port: 5986,
  auth: {
    type: 'kerberos',
    username: 'service-account',
    domain: 'EXAMPLE',
    realm: 'EXAMPLE.COM',
    spn: 'HTTP/server.example.com',
    keytab: '/path/to/service-account.keytab'  // Path to keytab file
  }
};
```

#### With Custom KDC Configuration
```javascript
const kerberosCustomKDC = {
  host: 'server.example.com',
  protocol: 'https',
  port: 5986,
  auth: {
    type: 'kerberos',
    username: 'john.doe',
    password: 'password',
    domain: 'EXAMPLE',
    realm: 'EXAMPLE.COM',
    spn: 'HTTP/server.example.com',
    kdc: 'kerberos.example.com',  // Custom KDC server
    kdcPort: 88                   // Custom KDC port
  }
};
```

### CredSSP Authentication

#### With Credential Delegation
```javascript
const credsspConfig = {
  host: 'server.example.com',
  protocol: 'https',
  port: 5986,
  auth: {
    type: 'credssp',
    username: 'domain\\user',
    password: 'password',
    domain: 'EXAMPLE',
    delegateCredentials: true  // Enable credential delegation
  }
};

const session = new Session(credsspConfig);
// Credentials will be delegated to target server
const result = await session.run('hostname');
```

#### Without Credential Delegation
```javascript
const credsspNoDelegateConfig = {
  host: 'server.example.com',
  protocol: 'https',
  port: 5986,
  auth: {
    type: 'credssp',
    username: 'domain\\user',
    password: 'password',
    domain: 'EXAMPLE',
    delegateCredentials: false  // No credential delegation
  }
};
```

## Authentication Type Comparison

| Feature | NTLM | Kerberos | CredSSP |
|---------|------|----------|---------|
| **Security Level** | Medium | High | High |
| **Mutual Authentication** | No | Yes | Yes |
| **Credential Delegation** | Limited | Yes | Yes |
| **Single Sign-On** | No | Yes | Limited |
| **Setup Complexity** | Low | Medium | Medium-High |
| **Network Level Authentication** | No | No | Yes |
| **Ticket-based** | No | Yes | No |
| **Domain Requirements** | AD Domain | AD Domain + Kerberos | AD Domain |
| **Performance** | Fast | Fast | Slower |
| **Best For** | Simple domain auth | Enterprise SSO | Credential delegation |

### When to Use Each Method

- **NTLM**: Use when you need simple domain authentication without complex setup
- **Kerberos**: Use in enterprise environments where SSO and mutual authentication are required
- **CredSSP**: Use when you need credential delegation or network level authentication

## Troubleshooting

### Common Issues

#### 1. Authentication Failures

```javascript
// Test authentication configuration
const session = new Session(config);
try {
  await session.test();
  console.log('Authentication successful');
} catch (error) {
  if (error.code === 'AUTHENTICATION_FAILED') {
    console.error('Check username, password, and domain');
  }
}
```

#### 2. Connection Timeouts

```javascript
const config = {
  timeouts: {
    connectTimeout: 60000,      // Increase connection timeout
    readTimeout: 120000,        // Increase read timeout
    operationTimeout: 300000    // Increase operation timeout
  }
};
```

#### 3. Certificate Issues

```javascript
const config = {
  ssl: {
    rejectUnauthorized: false,  // Only for testing!
    ca: fs.readFileSync('corporate-ca.crt')  // Use corporate CA
  }
};
```

#### 4. Kerberos Authentication Issues

```javascript
// Test Kerberos configuration
const kerberosConfig = {
  host: 'server.example.com',
  auth: {
    type: 'kerberos',
    username: 'user',
    password: 'password',
    domain: 'EXAMPLE',
    realm: 'EXAMPLE.COM',
    spn: 'HTTP/server.example.com'
  }
};

// Check time synchronization
const session = new Session(kerberosConfig);
try {
  await session.test();
  console.log('Kerberos authentication successful');
} catch (error) {
  console.error('Kerberos error:', error.message);
  // Check: Time synchronization, SPN configuration, DNS resolution
}
```

**Common Kerberos Issues:**
- Time synchronization (check with `date` command)
- Incorrect SPN format or configuration
- DNS resolution issues
- Missing Kerberos dependencies
- KDC server unreachable

#### 5. CredSSP Authentication Issues

```javascript
// Test CredSSP configuration
const credsspConfig = {
  host: 'server.example.com',
  auth: {
    type: 'credssp',
    username: 'domain\\user',
    password: 'password',
    domain: 'EXAMPLE',
    delegateCredentials: true
  }
};

const session = new Session(credsspConfig);
try {
  await session.test();
  console.log('CredSSP authentication successful');
} catch (error) {
  console.error('CredSSP error:', error.message);
  // Check: CredSSP enabled on server, firewall rules, authentication delegation
}
```

**Common CredSSP Issues:**
- CredSSP not enabled on target server
- Firewall blocking WS-Management traffic
- Credential delegation policies
- Insufficient user privileges

### Debug Logging

Enable debug logging to troubleshoot issues:

```javascript
const winrm = require('winner-m');
const { logger } = winrm;
logger.setLevel('debug');
```

### Network Testing

Test network connectivity first:

```bash
# Test port connectivity
telnet windows-server.example.com 5986

# Test if WinRM is listening
nc -v windows-server.example.com 5986
```

## Running Examples

The library includes example scripts that demonstrate various features:

```bash
# Basic usage example
node examples/basic-usage.js

# Advanced usage example  
node examples/advanced-usage.js
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### v1.1.0
- **NEW**: Kerberos authentication support with enterprise SSO
- **NEW**: CredSSP authentication with credential delegation
- **NEW**: Multiple authentication method comparison and selection guide
- **NEW**: Enhanced security considerations for each authentication method
- **NEW**: Installation instructions for Kerberos dependencies
- **IMPROVED**: Updated documentation with comprehensive authentication examples
- **IMPROVED**: Authentication type comparison table and security matrix

### v1.0.0
- Initial release
- NTLM authentication support
- Session and Protocol classes
- PowerShell execution
- SSL/TLS support
- Comprehensive error handling
- TypeScript definitions

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the examples
3. Open an issue on GitHub

## Roadmap

- [x] Kerberos authentication
- [x] CredSSP authentication
- [ ] PowerShell Core support
- [ ] File transfer capabilities
- [ ] Event subscription
- [ ] Batch command execution optimization
- [ ] Interactive session support