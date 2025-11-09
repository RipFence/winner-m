#!/usr/bin/env node

/**
 * Basic usage example for JS-WinRM library
 * Demonstrates common operations like connecting and running commands
 */

const winrm = require('../src/WinRM');

async function basicExample() {
  console.log('=== JS-WinRM Basic Usage Example ===\n');

  // Configuration for the Windows host
  const config = {
    host: 'windows-server.example.com',
    protocol: 'https',  // Prefer HTTPS for security
    port: 5986,         // HTTPS port
    auth: {
      type: 'ntlm',     // NTLM authentication
      username: 'domain\\user',
      password: 'password',
      domain: 'EXAMPLE',  // Optional: domain name
      workstation: 'LINUX-CLIENT'  // Optional: your workstation name
    },
    ssl: {
      rejectUnauthorized: false, // Set to true in production with proper certificates
      // ca: customCA,              // Optional: custom CA certificate
      // cert: clientCert,          // Optional: client certificate
      // key: clientKey             // Optional: client key
    },
    timeouts: {
      connectTimeout: 30000,
      readTimeout: 60000,
      operationTimeout: 300000  // 5 minutes for PowerShell scripts
    }
  };

  let session;
  
  try {
    console.log('1. Testing connectivity...');
    
    // Test connection (creates and closes session automatically)
    const isConnected = await winrm.testConnection(config);
    if (!isConnected) {
      throw new Error('Connection test failed');
    }
    console.log('✅ Connection successful\n');

    console.log('2. Creating a persistent session...');
    
    // Create a session for multiple operations
    session = winrm.createSession(config);
    console.log('✅ Session created\n');

    console.log('3. Testing session connectivity...');
    
    // Test the session
    if (await session.test()) {
      console.log('✅ Session test successful\n');
    } else {
      throw new Error('Session test failed');
    }

    console.log('4. Running simple commands...');
    
    // Get system information
    console.log('Getting system info...');
    const sysInfo = await session.getSystemInfo();
    console.log('System Info:', sysInfo);
    console.log();

    // Run a simple command
    console.log('Running "hostname" command...');
    const hostnameResult = await session.run('hostname');
    console.log('Output:', hostnameResult.stdout);
    console.log('Exit Code:', hostnameResult.exitCode);
    console.log();

    // Run multiple commands in sequence
    console.log('Running multiple commands...');
    const commands = [
      'echo "Current date:"',
      'date /t',
      'echo "Current time:"',
      'time /t'
    ];

    for (const command of commands) {
      const result = await session.run(command);
      console.log(`Command: ${command}`);
      console.log(`Output: ${result.stdout}`);
    }
    console.log();

    console.log('5. Running PowerShell commands...');
    
    // Execute PowerShell commands
    console.log('Getting PowerShell version...');
    const psVersionResult = await session.runPS('Get-Host | Select-Object -ExpandProperty Version');
    console.log('PowerShell Version:', psVersionResult.stdout);

    console.log('\nGetting process information...');
    const psProcessResult = await session.runPS('Get-Process | Select-Object -First 5 | Format-Table -AutoSize');
    console.log('First 5 processes:');
    console.log(psProcessResult.stdout);

    console.log('\n6. Working with environment variables...');
    
    // Set and get environment variable
    const setEnvResult = await session.run('set CUSTOM_VAR="Hello from WinRM"');
    const getEnvResult = await session.run('echo %CUSTOM_VAR%');
    console.log('Custom environment variable:', getEnvResult.stdout);

    console.log('\n7. Working directory and batch operations...');
    
    // Change to a different directory
    const cdResult = await session.run('cd /d C:\\Users', {
      workingDirectory: 'C:\\Windows\\System32'
    });
    console.log('Change directory result:', cdResult);

    // Run commands with working directory
    const dirResult = await session.run('dir /b *.exe', {
      workingDirectory: 'C:\\Windows\\System32'
    });
    console.log('Directory listing in System32:');
    console.log(dirResult.stdout);

    console.log('\n8. Error handling example...');
    
    try {
      // This should succeed
      const successResult = await session.run('echo "This should work"');
      console.log('Expected success:', successResult.stdout);
    } catch (error) {
      console.log('Unexpected error:', error.message);
    }

    try {
      // This should fail
      const errorResult = await session.run('nonexistent-command');
      console.log('Should not reach here');
    } catch (error) {
      console.log('✅ Expected error caught:', error.code, '-', error.message);
      if (error.details && error.details.exitCode) {
        console.log('Exit code:', error.details.exitCode);
      }
    }

    console.log('\n✅ All examples completed successfully!');

  } catch (error) {
    console.error('\n❌ Error during example execution:');
    console.error('Error code:', error.code || 'UNKNOWN');
    console.error('Error message:', error.message);
    
    if (error.details) {
      console.error('Additional details:', error.details);
    }
    
    process.exit(1);
  } finally {
    // Clean up the session
    if (session) {
      console.log('\n9. Cleaning up session...');
      await session.close();
      console.log('✅ Session closed');
    }
  }
}

// Run the example if this script is executed directly
if (require.main === module) {
  basicExample().catch(error => {
    console.error('Unhandled error:', error);
    process.exit(1);
  });
}

module.exports = basicExample;