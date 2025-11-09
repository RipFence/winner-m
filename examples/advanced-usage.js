#!/usr/bin/env node

/**
 * Advanced usage example for JS-WinRM library
 * Demonstrates advanced features like protocol usage, batch operations, and error handling
 */

const winrm = require('../src/WinRM');

async function advancedExample() {
  console.log('=== JS-WinRM Advanced Usage Example ===\n');

  // Configuration
  const config = {
    host: 'windows-server.example.com',
    protocol: 'https',
    port: 5986,
    auth: {
      type: 'ntlm',
      username: 'domain\\admin',
      password: 'admin_password',
      domain: 'EXAMPLE',
      workstation: 'LINUX-SERVER'
    },
    ssl: {
      rejectUnauthorized: false
    },
    timeouts: {
      connectTimeout: 30000,
      readTimeout: 60000,
      operationTimeout: 600000  // 10 minutes for complex operations
    }
  };

  let protocol = null;
  let session = null;

  try {
    console.log('1. Using Protocol class for low-level control...\n');
    
    // Create Protocol instance for low-level operations
    protocol = winrm.createProtocol(config);
    
    // Get initial status
    console.log('Initial Protocol status:');
    console.log(protocol.getStatus());
    console.log();

    // Test connectivity using Protocol
    console.log('Testing connectivity with Protocol...');
    const isConnected = await protocol.ping();
    if (isConnected) {
      console.log('✅ Protocol connectivity test successful\n');
    } else {
      throw new Error('Protocol connectivity test failed');
    }

    console.log('2. Executing low-level commands with Protocol...\n');
    
    // Open shell for low-level operations
    await protocol.openShell();
    console.log('✅ Shell opened');
    console.log('Shell ID:', protocol.getStatus().shellId);
    console.log();

    // Run command and get output separately
    console.log('Running command "ver" to get Windows version...');
    const commandId = await protocol.runCommand('ver', '/b');
    console.log('Command ID:', commandId);

    // Wait for command completion and get output
    const versionResult = await protocol.waitForCommand(commandId);
    console.log('Version output:', versionResult.stdout);
    console.log('Exit code:', versionResult.exitCode);
    console.log();

    // Get process information with polling
    console.log('Getting running processes...');
    const psCommandId = await protocol.runCommand('tasklist', '/fi "imagemame ne *chrome*"');
    const psResult = await protocol.waitForCommand(psCommandId);
    console.log('Running Chrome processes:');
    console.log(psResult.stdout);

    // Cleanup command
    await protocol.cleanupCommand(psCommandId);
    console.log('✅ Command cleaned up\n');

    console.log('3. Using Session class for high-level operations...\n');
    
    // Close protocol shell first
    await protocol.closeShell();
    protocol = null;
    
    // Create Session for high-level operations
    session = winrm.createSession(config);
    console.log('✅ Session created\n');

    console.log('4. Batch operations with Session...\n');
    
    // Define a series of commands
    const systemSetupCommands = [
      { command: 'mkdir C:\\temp\\winrm-test', continueOnError: false },
      { command: 'echo "Test data" > C:\\temp\\winrm-test\\data.txt', continueOnError: false },
      { command: 'type C:\\temp\\winrm-test\\data.txt', continueOnError: false },
      { command: 'rmdir /s /q C:\\temp\\winrm-test', continueOnError: false }
    ];

    console.log('Running batch system setup commands...');
    const batchResults = await session.runBatch(systemSetupCommands);
    
    batchResults.forEach((result, index) => {
      console.log(`Command ${index + 1}: ${systemSetupCommands[index].command}`);
      console.log(`Exit code: ${result.exitCode}`);
      if (result.stdout) {
        console.log(`Output: ${result.stdout}`);
      }
    });
    console.log();

    console.log('5. PowerShell advanced examples...\n');
    
    // PowerShell script to get system information
    const systemInfoScript = `
# Get comprehensive system information
$os = Get-WmiObject -Class Win32_OperatingSystem
$cs = Get-WmiObject -Class Win32_ComputerSystem
$bios = Get-WmiObject -Class Win32_BIOS

[PSCustomObject]@{
    ComputerName = $os.CSName
    OSName = $os.Caption
    OSVersion = $os.Version
    OSBuild = $os.BuildNumber
    InstallDate = $os.InstallDate
    LastBootUpTime = $os.ConvertToDateTime($os.LastBootUpTime)
    TotalMemory = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    Manufacturer = $cs.Manufacturer
    Model = $cs.Model
    BIOSVersion = $bios.SMBIOSBIOSVersion
}
`;

    console.log('Getting comprehensive system information...');
    const infoResult = await session.runPS(systemInfoScript);
    console.log('System Information:');
    console.log(infoResult.stdout);

    // PowerShell script with error handling
    const advancedPsScript = `
try {
    # Get service information
    $services = Get-Service | Where-Object { $_.Status -eq 'Running' } | 
                Select-Object Name, DisplayName, StartType |
                Sort-Object Name | Select-Object -First 5
    
    Write-Output "Top 5 running services:"
    $services | Format-Table -AutoSize
    
    # Test network connectivity
    $ping = Test-Connection -ComputerName "localhost" -Count 1 -Quiet
    Write-Output "Localhost ping test: $ping"
    
} catch {
    Write-Error "Error executing PowerShell script: $($_.Exception.Message)"
}
`;

    console.log('\nRunning advanced PowerShell with error handling...');
    const advancedResult = await session.runPS(advancedPsScript);
    console.log('Advanced PowerShell output:');
    console.log(advancedResult.stdout);

    console.log('6. Environment and working directory examples...\n');
    
    // Set custom working directory
    const dirResult = await session.run('dir /b', {
      workingDirectory: 'C:\\Windows\\System32',
      operationTimeout: 30000
    });
    console.log('Files in C:\\Windows\\System32 (first few):');
    console.log(dirResult.stdout);

    // Environment variables
    const envResult = await session.run('set | findstr /i "user\\|path\\|comspec"', {
      environmentVars: {
        CUSTOM_TEST: 'This is a test variable',
        WINRM_TEST: 'Advanced WinRM test'
      }
    });
    console.log('Environment variables:');
    console.log(envResult.stdout);

    console.log('7. Error handling and recovery examples...\n');
    
    // Simulate a timeout scenario
    console.log('Testing timeout handling...');
    try {
      const timeoutResult = await session.run('ping 127.0.0.1 -n 1 -w 1000', {
        operationTimeout: 5000  // Very short timeout
      });
      console.log('Result:', timeoutResult.stdout);
    } catch (error) {
      console.log('✅ Expected timeout error:', error.code, '-', error.message);
    }

    // Test with non-existent command
    console.log('\nTesting command not found...');
    try {
      const notFoundResult = await session.run('command-does-not-exist');
    } catch (error) {
      console.log('✅ Expected command not found error:', error.code, '-', error.message);
    }

    // Test with access denied command
    console.log('\nTesting access denied...');
    try {
      const accessDeniedResult = await session.run('del C:\\Windows\\System32\\ntoskrnl.exe');
    } catch (error) {
      console.log('✅ Expected access denied error:', error.code, '-', error.message);
    }

    console.log('\n8. Performance monitoring...\n');
    
    // Monitor command execution time
    const startTime = Date.now();
    await session.run('echo "Performance test"');
    const duration = Date.now() - startTime;
    console.log(`Command execution time: ${duration}ms`);

    // Get session statistics
    console.log('\nFinal session status:');
    const finalStatus = session.getStatus();
    console.log(JSON.stringify(finalStatus, null, 2));

    console.log('\n✅ All advanced examples completed successfully!');

  } catch (error) {
    console.error('\n❌ Error during advanced example execution:');
    console.error('Error code:', error.code || 'UNKNOWN');
    console.error('Error message:', error.message);
    
    if (error.details) {
      console.error('Additional details:', error.details);
    }
    
    if (error.stack) {
      console.error('Stack trace:', error.stack);
    }
    
    process.exit(1);
  } finally {
    // Clean up resources
    console.log('\n9. Cleaning up resources...');
    
    if (protocol) {
      try {
        await protocol.close();
        console.log('✅ Protocol closed');
      } catch (error) {
        console.warn('Warning: Error closing protocol:', error.message);
      }
    }
    
    if (session) {
      try {
        await session.close();
        console.log('✅ Session closed');
      } catch (error) {
        console.warn('Warning: Error closing session:', error.message);
      }
    }
  }
}

// Run the example if this script is executed directly
if (require.main === module) {
  advancedExample().catch(error => {
    console.error('Unhandled error:', error);
    process.exit(1);
  });
}

module.exports = advancedExample;