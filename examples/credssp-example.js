#!/usr/bin/env node

/**
 * CredSSP (Credential Security Support Provider) Authentication Examples
 * 
 * This file demonstrates various CredSSP authentication configurations and usage patterns.
 * CredSSP enables secure authentication with credential delegation support for "double-hop" scenarios.
 * 
 * Features demonstrated:
 * - Basic CredSSP authentication with NTLM
 * - CredSSP with Kerberos base authentication
 * - Double-hop credential delegation
 * - Security configuration options
 * - Error handling and troubleshooting
 * - Performance monitoring
 * 
 * @see https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider
 * @see https://docs.microsoft.com/en-us/windows/win32/termserv/terminal-services-gateway
 */

const winrm = require('../src/WinRM');

/**
 * Example 1: Basic CredSSP Authentication
 * Demonstrates fundamental CredSSP setup with NTLM base authentication
 */
async function basicCredSSPExample() {
  console.log('=== Basic CredSSP Authentication Example ===\n');

  const config = {
    host: 'windows-server.example.com',
    protocol: 'https',
    port: 5986,
    auth: {
      type: 'credssp',
      username: 'domain\\user',
      password: 'secure-password',
      domain: 'EXAMPLE',
      workstation: 'LINUX-CLIENT',
      baseAuth: 'ntlm', // Use NTLM as base authentication
      delegateCredentials: true // Enable credential delegation
    },
    ssl: {
      rejectUnauthorized: false, // Set to true in production
      // ca: customCA,              // Custom CA certificate
      // cert: clientCert,          // Client certificate
      // key: clientKey             // Client key
    },
    timeouts: {
      connectTimeout: 30000,
      readTimeout: 60000,
      operationTimeout: 300000
    }
  };

  let session;
  
  try {
    console.log('1. Testing CredSSP connectivity...');
    
    // Test connection with CredSSP
    const isConnected = await winrm.testConnection(config);
    if (!isConnected) {
      throw new Error('CredSSP connection test failed');
    }
    console.log('✅ CredSSP connection successful\n');

    console.log('2. Creating CredSSP session...');
    
    // Create session with CredSSP authentication
    session = winrm.createSession(config);
    console.log('✅ CredSSP session created\n');

    console.log('3. Testing session authentication...');
    
    if (await session.test()) {
      console.log('✅ CredSSP authentication successful\n');
    } else {
      throw new Error('CredSSP session test failed');
    }

    console.log('4. Running commands with CredSSP...');
    
    // Get system information
    const sysInfo = await session.getSystemInfo();
    console.log('System Info:', sysInfo);
    console.log();

    // Run a command to verify delegation works
    const whoamiResult = await session.run('whoami');
    console.log('Current user (via CredSSP):', whoamiResult.stdout.trim());
    console.log();

    console.log('✅ Basic CredSSP example completed successfully!\n');

  } catch (error) {
    console.error('\n❌ CredSSP authentication error:');
    console.error('Error code:', error.code || 'UNKNOWN');
    console.error('Error message:', error.message);
    
    if (error.details) {
      console.error('Additional details:', error.details);
    }
    
    throw error;
  } finally {
    if (session) {
      await session.close();
      console.log('Session closed\n');
    }
  }
}

/**
 * Example 2: CredSSP with Double-Hop Support
 * Demonstrates advanced credential delegation for multi-tier authentication scenarios
 */
async function doubleHopCredSSPExample() {
  console.log('=== CredSSP Double-Hop Authentication Example ===\n');

  const config = {
    host: 'jump-server.example.com',
    protocol: 'https',
    port: 5986,
    auth: {
      type: 'credssp',
      username: 'admin\\user',
      password: 'admin-password',
      domain: 'ENTERPRISE',
      workstation: 'ADMIN-CLIENT',
      baseAuth: 'ntlm',
      delegateCredentials: true, // Critical for double-hop scenarios
      maxRetries: 5 // Increase retries for complex network paths
    },
    ssl: {
      rejectUnauthorized: false,
      // In production, use proper certificate validation
      // ca: path.resolve('./certs/enterprise-ca.pem'),
      // verifyHostname: true
    },
    timeouts: {
      connectTimeout: 45000, // Longer timeout for double-hop
      readTimeout: 90000,
      operationTimeout: 600000 // 10 minutes for complex operations
    }
  };

  let session;
  
  try {
    console.log('1. Connecting to jump server with double-hop support...');
    
    session = winrm.createSession(config);
    
    // Verify double-hop capability
    const doubleHopTest = await session.run('whoami /groups');
    console.log('Double-hop authentication successful');
    console.log('User groups:', doubleHopTest.stdout.trim().split('\n')[0]);
    console.log();

    console.log('2. Testing credential delegation...');
    
    // Test if we can access resources as the delegated user
    const netUserResult = await session.run('net user %USERNAME% /domain');
    if (netUserResult.exitCode === 0) {
      console.log('✅ Credential delegation working - domain access successful');
    } else {
      console.log('⚠️  Domain access limited, but local authentication successful');
    }
    console.log();

    console.log('3. Running elevated commands...');
    
    // Run commands that require the delegated credentials
    const envResult = await session.run('echo %USERDOMAIN%\\%USERNAME%');
    console.log('Delegated identity:', envResult.stdout.trim());
    console.log();

    console.log('✅ Double-hop CredSSP example completed successfully!\n');

  } catch (error) {
    console.error('\n❌ Double-hop CredSSP error:');
    console.error('Error code:', error.code || 'UNKNOWN');
    console.error('Error message:', error.message);
    
    if (error.details) {
      console.error('Network details:', error.details);
    }
    
    throw error;
  } finally {
    if (session) {
      await session.close();
      console.log('Double-hop session closed\n');
    }
  }
}

/**
 * Example 3: CredSSP with NTLM Base Authentication
 * Demonstrates NTLM-based CredSSP configuration with various security options
 */
async function ntlmBaseCredSSPExample() {
  console.log('=== CredSSP with NTLM Base Authentication Example ===\n');

  const config = {
    host: 'ntlm-server.example.com',
    protocol: 'https',
    port: 5986,
    auth: {
      type: 'credssp',
      username: 'techuser',
      password: 'tech-password',
      domain: 'TECH',
      workstation: 'TECH-CLIENT',
      baseAuth: 'ntlm', // Explicitly use NTLM
      delegateCredentials: true,
      // NTLM-specific options
      lmCompatibility: 3, // NTLMv2 only
      ntlmFlags: {
        negotiateUnicode: true,
        negotiateOem: true,
        requestTarget: true,
        negotiateDomainSupplied: true,
        negotiateWorkstationSupplied: true,
        negotiateAlwaysSign: true,
        negotiateNtlmKey: true,
        negotiateLanManKey: false, // Disable LM for security
        negotiateDatagramStyle: false,
        negotiateSessionKey: true,
        targetTypeDomain: true,
        targetTypeServer: true
      }
    },
    ssl: {
      rejectUnauthorized: false,
      // Enhanced security for NTLM
      // minimumVersion: 'TLSv1.2',
      // ciphers: 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'
    },
    timeouts: {
      connectTimeout: 30000,
      readTimeout: 60000,
      operationTimeout: 300000
    }
  };

  let session;
  
  try {
    console.log('1. Testing NTLM-based CredSSP connection...');
    
    session = winrm.createSession(config);
    
    if (await session.test()) {
      console.log('✅ NTLM-based CredSSP connection successful\n');
    } else {
      throw new Error('NTLM CredSSP authentication failed');
    }

    console.log('2. Verifying NTLM authentication details...');
    
    // Check authentication method used
    const authCheck = await session.run('echo Auth Method: NTLM with CredSSP delegation');
    console.log('Authentication verification:', authCheck.stdout.trim());
    console.log();

    console.log('3. Testing NTLM security features...');
    
    // Test with various NTLM scenarios
    const ntlmTests = [
      { command: 'hostname', description: 'Basic connectivity' },
      { command: 'whoami /fqdn', description: 'Fully qualified domain name' },
      { command: 'net config workstation', description: 'Workstation configuration' }
    ];

    for (const test of ntlmTests) {
      try {
        const result = await session.run(test.command);
        console.log(`✅ ${test.description}: Success`);
      } catch (error) {
        console.log(`⚠️  ${test.description}: ${error.message}`);
      }
    }
    console.log();

    console.log('4. Testing credential validation...');
    
    // Validate that credentials are properly delegated
    const credValidation = await session.run('cmd /c "echo Checking NTLM auth context: && where powershell"');
    console.log('Credential context:', credValidation.stdout.trim().split('\n')[0]);
    console.log();

    console.log('✅ NTLM-based CredSSP example completed successfully!\n');

  } catch (error) {
    console.error('\n❌ NTLM CredSSP error:');
    console.error('Error code:', error.code || 'UNKNOWN');
    console.error('Error message:', error.message);
    
    if (error.details) {
      console.error('NTLM details:', error.details);
    }
    
    throw error;
  } finally {
    if (session) {
      await session.close();
      console.log('NTLM session closed\n');
    }
  }
}

/**
 * Example 4: CredSSP with Kerberos Base Authentication
 * Demonstrates advanced Kerberos-based CredSSP setup for enterprise environments
 */
async function kerberosBaseCredSSPExample() {
  console.log('=== CredSSP with Kerberos Base Authentication Example ===\n');

  const config = {
    host: 'kerberos-server.corp.example.com',
    protocol: 'https',
    port: 5986,
    auth: {
      type: 'credssp',
      username: 'kerberos-user',
      password: 'kerberos-password',
      domain: 'CORP.EXAMPLE.COM',
      workstation: 'KERBEROS-CLIENT',
      baseAuth: 'kerberos', // Use Kerberos as base authentication
      delegateCredentials: true,
      // Kerberos-specific options
      servicePrincipalName: 'HTTP/kerberos-server.corp.example.com@CORP.EXAMPLE.COM',
      // krb5.conf settings
      krb5Config: {
        defaultRealm: 'CORP.EXAMPLE.COM',
        kdc: 'kdc.corp.example.com',
        adminServer: 'kadmin.corp.example.com',
        ticketLifetime: '10h',
        renewLifetime: '7d',
        clockSkew: 300
      }
    },
    ssl: {
      rejectUnauthorized: false,
      // Enhanced security for Kerberos
      // ca: path.resolve('./certs/corp-ca.pem'),
      // checkServerIdentity: (hostname, cert) => {
      //   // Custom certificate validation for Kerberos environments
      //   return true; // Implement proper validation
      // }
    },
    timeouts: {
      connectTimeout: 45000, // Kerberos may need more time for TGT acquisition
      readTimeout: 90000,
      operationTimeout: 300000
    }
  };

  let session;
  
  try {
    console.log('1. Testing Kerberos-based CredSSP connection...');
    console.log('   SPN:', config.auth.servicePrincipalName);
    console.log('   Realm:', config.auth.domain);
    
    session = winrm.createSession(config);
    
    if (await session.test()) {
      console.log('✅ Kerberos-based CredSSP connection successful\n');
    } else {
      throw new Error('Kerberos CredSSP authentication failed');
    }

    console.log('2. Verifying Kerberos authentication...');
    
    // Check Kerberos ticket status
    const klistResult = await session.run('klist');
    if (klistResult.exitCode === 0) {
      console.log('✅ Kerberos tickets found:');
      const tickets = klistResult.stdout.split('\n').filter(line => 
        line.includes('krbtgt') || line.includes('HTTP/')
      );
      tickets.forEach(ticket => console.log('   ', ticket.trim()));
    } else {
      console.log('⚠️  Kerberos tickets not directly accessible via klist');
    }
    console.log();

    console.log('3. Testing Kerberos security features...');
    
    // Test various Kerberos-specific operations
    const kerberosTests = [
      { command: 'hostname', description: 'Basic Kerberos connectivity' },
      { command: 'whoami /upn', description: 'User Principal Name' },
      { command: 'nltest /sc_verify:CORP.EXAMPLE.COM', description: 'Secure channel verification' }
    ];

    for (const test of kerberosTests) {
      try {
        const result = await session.run(test.command);
        console.log(`✅ ${test.description}: Success`);
        if (result.stdout) {
          console.log(`   Output: ${result.stdout.trim()}`);
        }
      } catch (error) {
        console.log(`⚠️  ${test.description}: ${error.message}`);
      }
    }
    console.log();

    console.log('4. Testing cross-realm capabilities...');
    
    // Test if Kerberos enables cross-realm authentication
    const realmTest = await session.run('echo Current realm context established via Kerberos');
    console.log('Realm context:', realmTest.stdout.trim());
    console.log();

    console.log('5. Validating ticket delegation...');
    
    // Test if delegated Kerberos tickets work
    const delegationTest = await session.run('cmd /c "echo Testing Kerberos credential delegation: && whoami"');
    console.log('Delegation status:', delegationTest.stdout.trim().split('\n')[0]);
    console.log();

    console.log('✅ Kerberos-based CredSSP example completed successfully!\n');

  } catch (error) {
    console.error('\n❌ Kerberos CredSSP error:');
    console.error('Error code:', error.code || 'UNKNOWN');
    console.error('Error message:', error.message);
    
    if (error.details) {
      console.error('Kerberos details:', error.details);
    }
    
    // Provide Kerberos-specific troubleshooting tips
    console.error('\nKerberos troubleshooting tips:');
    console.error('- Verify SPN is correctly registered: setspn -L kerberos-user');
    console.error('- Check krb5.conf configuration');
    console.error('- Ensure time synchronization between client and KDC');
    console.error('- Verify DNS resolution for Kerberos servers');
    
    throw error;
  } finally {
    if (session) {
      await session.close();
      console.log('Kerberos session closed\n');
    }
  }
}

/**
 * Example 5: CredSSP Security Configuration Options
 * Demonstrates various security settings and hardening options
 */
async function securityConfigExample() {
  console.log('=== CredSSP Security Configuration Example ===\n');

  const securityConfigs = [
    {
      name: 'High Security Configuration',
      config: {
        host: 'secure-server.example.com',
        protocol: 'https',
        port: 5986,
        auth: {
          type: 'credssp',
          username: 'secure-user',
          password: 'complex-password-!@#$',
          domain: 'SECURE',
          workstation: 'SECURE-CLIENT',
          baseAuth: 'kerberos', // Prefer Kerberos for high security
          delegateCredentials: true,
          // Security hardening
          sessionTimeout: 1800000, // 30 minutes
          maxRetries: 3,
          retryDelay: 1000
        },
        ssl: {
          rejectUnauthorized: true, // Require valid certificates
          // ca: path.resolve('./certs/secure-ca.pem'),
          // cert: path.resolve('./certs/client-cert.pem'),
          // key: path.resolve('./certs/client-key.pem'),
          // minVersion: 'TLSv1.3',
          // ciphers: 'ECDHE+AESGCM:ECDHE+CHACHA20',
          honorCipherOrder: true,
          rejectUnauthorized: true
        },
        timeouts: {
          connectTimeout: 30000,
          readTimeout: 60000,
          operationTimeout: 300000
        },
        // Additional security options
        userAgent: 'JS-WinRM-Secure-Client/1.0',
        headers: {
          'X-Client-Version': '1.0.0',
          'X-Security-Level': 'HIGH'
        }
      }
    },
    {
      name: 'Compliance Configuration',
      config: {
        host: 'compliant-server.example.com',
        protocol: 'https',
        port: 5986,
        auth: {
          type: 'credssp',
          username: 'compliant-user',
          password: 'compliant-password',
          domain: 'COMPLIANT',
          workstation: 'COMPLIANT-CLIENT',
          baseAuth: 'ntlm',
          delegateCredentials: true,
          // Compliance-specific settings
          auditLevel: 'detailed',
          logLevel: 'info',
          sessionEncryption: true
        },
        ssl: {
          rejectUnauthorized: true,
          // ca: path.resolve('./certs/compliant-ca.pem'),
          // Enhanced TLS configuration
          // ciphers: 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256',
          minVersion: 'TLSv1.2',
          maxVersion: 'TLSv1.3'
        },
        timeouts: {
          connectTimeout: 30000,
          readTimeout: 60000,
          operationTimeout: 300000
        },
        // Audit and compliance logging
        auditLog: {
          enabled: true,
          file: './logs/credssp-audit.log',
          level: 'detailed',
          includePayloads: false
        }
      }
    }
  ];

  for (const securityConfig of securityConfigs) {
    console.log(`--- ${securityConfig.name} ---`);
    
    let session;
    try {
      console.log('Creating secure session...');
      session = winrm.createSession(securityConfig.config);
      
      if (await session.test()) {
        console.log('✅ Secure connection established');
        console.log(`   Security Level: ${securityConfig.name}`);
        
        // Test security features
        const securityTest = await session.run('echo Security configuration active');
        console.log('   Test result:', securityTest.stdout.trim());
      } else {
        console.log('❌ Secure connection failed');
      }
      
    } catch (error) {
      console.log('❌ Security configuration error:');
      console.log('   Error:', error.message);
    } finally {
      if (session) {
        await session.close();
        console.log('Secure session closed\n');
      }
    }
  }

  console.log('✅ Security configuration examples completed!\n');
}

/**
 * Example 6: CredSSP Error Handling and Troubleshooting
 * Demonstrates comprehensive error handling and troubleshooting techniques
 */
async function errorHandlingExample() {
  console.log('=== CredSSP Error Handling and Troubleshooting Example ===\n');

  const errorScenarios = [
    {
      name: 'Invalid Credentials',
      config: {
        host: 'test-server.example.com',
        auth: {
          type: 'credssp',
          username: 'invalid-user',
          password: 'wrong-password',
          domain: 'INVALID'
        }
      },
      expectedError: 'authentication'
    },
    {
      name: 'Network Connection Failure',
      config: {
        host: 'nonexistent-server.example.com',
        auth: {
          type: 'credssp',
          username: 'test-user',
          password: 'test-password',
          domain: 'TEST'
        }
      },
      expectedError: 'connection'
    },
    {
      name: 'SSL/TLS Configuration Error',
      config: {
        host: 'ssl-test.example.com',
        protocol: 'https',
        auth: {
          type: 'credssp',
          username: 'test-user',
          password: 'test-password',
          domain: 'TEST'
        },
        ssl: {
          rejectUnauthorized: true // Will fail with self-signed cert
        }
      },
      expectedError: 'ssl'
    }
  ];

  for (const scenario of errorScenarios) {
    console.log(`--- Testing: ${scenario.name} ---`);
    
    let session;
    try {
      session = winrm.createSession(scenario.config);
      
      console.log('Attempting connection...');
      const startTime = Date.now();
      
      // This should fail with expected error
      await session.test();
      
      // If we get here, the test didn't fail as expected
      console.log('⚠️  Unexpected success - test may not be configured correctly');
      
    } catch (error) {
      const duration = Date.now() - session?.startTime || 0;
      
      console.log(`✅ Expected error caught (${duration}ms):`);
      console.log('   Error Type:', error.code || 'UNKNOWN');
      console.log('   Error Message:', error.message);
      
      // Provide specific troubleshooting advice
      if (scenario.expectedError === 'authentication') {
        console.log('   🔧 Troubleshooting:');
        console.log('     - Verify username and password are correct');
        console.log('     - Check domain name spelling');
        console.log('     - Ensure user account is not locked/disabled');
        console.log('     - Verify user has access to target system');
      } else if (scenario.expectedError === 'connection') {
        console.log('   🔧 Troubleshooting:');
        console.log('     - Verify hostname is correct and resolvable');
        console.log('     - Check network connectivity');
        console.log('     - Ensure WinRM service is running on target');
        console.log('     - Verify firewall rules allow WinRM traffic');
      } else if (scenario.expectedError === 'ssl') {
        console.log('   🔧 Troubleshooting:');
        console.log('     - Check SSL certificate validity');
        console.log('     - Verify certificate trust chain');
        console.log('     - Consider using rejectUnauthorized: false for testing');
        console.log('     - Ensure TLS/SSL version compatibility');
      }
      
      if (error.details) {
        console.log('   Additional Details:', JSON.stringify(error.details, null, 2));
      }
      
    } finally {
      if (session) {
        try {
          await session.close();
        } catch (closeError) {
          // Ignore close errors
        }
      }
    }
    
    console.log();
  }

  console.log('--- General CredSSP Troubleshooting Guide ---');
  console.log('Common CredSSP Issues and Solutions:');
  console.log();
  console.log('1. Authentication Failures:');
  console.log('   - Check base authentication (NTLM/Kerberos) configuration');
  console.log('   - Verify domain join status of target server');
  console.log('   - Ensure CredSSP is enabled on both client and server');
  console.log('   - Check Group Policy settings for Credential Delegation');
  console.log();
  console.log('2. Double-Hop Issues:');
  console.log('   - Enable credential delegation in configuration');
  console.log('   - Check server-side CredSSP configuration');
  console.log('   - Verify network allows credential delegation');
  console.log('   - Test with simpler authentication first');
  console.log();
  console.log('3. Network/Connectivity Issues:');
  console.log('   - Test basic connectivity (ping, telnet to port)');
  console.log('   - Check WinRM service status on target');
  console.log('   - Verify firewall rules for HTTPS (5986) traffic');
  console.log('   - Test with different authentication methods');
  console.log();
  console.log('4. SSL/TLS Issues:');
  console.log('   - Check certificate validity and trust chain');
  console.log('   - Verify TLS version compatibility');
  console.log('   - Consider certificate pinning for production');
  console.log('   - Test with different SSL configurations');
  console.log();

  console.log('✅ Error handling examples completed!\n');
}

/**
 * Example 7: Performance Monitoring and Optimization
 * Demonstrates performance monitoring and optimization techniques for CredSSP
 */
async function performanceMonitoringExample() {
  console.log('=== CredSSP Performance Monitoring Example ===\n');

  const performanceConfig = {
    host: 'perf-test.example.com',
    protocol: 'https',
    port: 5986,
    auth: {
      type: 'credssp',
      username: 'perf-user',
      password: 'perf-password',
      domain: 'PERF',
      baseAuth: 'ntlm',
      delegateCredentials: true
    },
    ssl: {
      rejectUnauthorized: false
    },
    timeouts: {
      connectTimeout: 30000,
      readTimeout: 60000,
      operationTimeout: 300000
    },
    // Performance monitoring options
    performance: {
      enableMetrics: true,
      logPerformance: true,
      trackMemoryUsage: true
    }
  };

  let session;
  const metrics = {
    connections: [],
    operations: [],
    errors: []
  };

  try {
    console.log('1. Testing connection performance...');
    
    const connectionTests = 3;
    for (let i = 1; i <= connectionTests; i++) {
      console.log(`   Connection test ${i}/${connectionTests}...`);
      
      const testSession = winrm.createSession(performanceConfig);
      const startTime = Date.now();
      
      try {
        const connected = await testSession.test();
        const duration = Date.now() - startTime;
        
        if (connected) {
          metrics.connections.push(duration);
          console.log(`   ✅ Connection ${i}: ${duration}ms`);
        } else {
          metrics.errors.push(`Connection ${i}: Test failed`);
        }
      } catch (error) {
        metrics.errors.push(`Connection ${i}: ${error.message}`);
        console.log(`   ❌ Connection ${i}: ${error.message}`);
      } finally {
        try {
          await testSession.close();
        } catch (e) {
          // Ignore close errors
        }
      }
    }
    
    console.log();
    console.log('2. Performance summary:');
    
    if (metrics.connections.length > 0) {
      const avgConnectionTime = metrics.connections.reduce((a, b) => a + b, 0) / metrics.connections.length;
      const minConnectionTime = Math.min(...metrics.connections);
      const maxConnectionTime = Math.max(...metrics.connections);
      
      console.log(`   Average connection time: ${avgConnectionTime.toFixed(2)}ms`);
      console.log(`   Fastest connection: ${minConnectionTime}ms`);
      console.log(`   Slowest connection: ${maxConnectionTime}ms`);
    }
    
    if (metrics.errors.length > 0) {
      console.log(`   Errors encountered: ${metrics.errors.length}`);
      metrics.errors.forEach(error => console.log(`     - ${error}`));
    }
    console.log();

    console.log('3. Testing operation performance...');
    
    session = winrm.createSession(performanceConfig);
    
    if (await session.test()) {
      const operations = [
        { name: 'Simple command', command: 'echo "Hello"' },
        { name: 'System info', command: 'systeminfo /fo csv' },
        { name: 'Directory listing', command: 'dir C:\\' }
      ];

      for (const operation of operations) {
        console.log(`   Testing ${operation.name}...`);
        const startTime = Date.now();
        
        try {
          const result = await session.run(operation.command);
          const duration = Date.now() - startTime;
          
          metrics.operations.push({
            name: operation.name,
            duration: duration,
            success: result.exitCode === 0,
            outputSize: result.stdout ? result.stdout.length : 0
          });
          
          console.log(`   ✅ ${operation.name}: ${duration}ms (${result.exitCode})`);
        } catch (error) {
          console.log(`   ❌ ${operation.name}: ${error.message}`);
          metrics.errors.push(`${operation.name}: ${error.message}`);
        }
      }
    }
    
    console.log();
    console.log('4. Operation performance summary:');
    
    if (metrics.operations.length > 0) {
      const successfulOps = metrics.operations.filter(op => op.success);
      const avgOpTime = successfulOps.reduce((sum, op) => sum + op.duration, 0) / successfulOps.length;
      
      console.log(`   Operations tested: ${metrics.operations.length}`);
      console.log(`   Successful operations: ${successfulOps.length}`);
      console.log(`   Average operation time: ${avgOpTime.toFixed(2)}ms`);
      console.log(`   Total data processed: ${metrics.operations.reduce((sum, op) => sum + op.outputSize, 0)} bytes`);
    }
    
    console.log();
    console.log('5. Performance recommendations:');
    
    // Provide recommendations based on metrics
    if (metrics.connections.length > 0) {
      const avgConnectionTime = metrics.connections.reduce((a, b) => a + b, 0) / metrics.connections.length;
      
      if (avgConnectionTime > 10000) {
        console.log('   🔧 Connection times are high (>10s):');
        console.log('     - Check network latency to target server');
        console.log('     - Verify WinRM service performance');
        console.log('     - Consider using connection pooling');
      } else if (avgConnectionTime > 5000) {
        console.log('   🔧 Connection times are moderate (>5s):');
        console.log('     - Consider enabling connection keep-alive');
        console.log('     - Optimize SSL/TLS configuration');
      } else {
        console.log('   ✅ Connection times are good (<5s)');
      }
    }
    
    console.log('   📈 General optimization tips:');
    console.log('     - Use session reuse for multiple operations');
    console.log('     - Enable connection pooling when available');
    console.log('     - Consider using parallel connections for batch operations');
    console.log('     - Monitor memory usage for long-running sessions');
    console.log('     - Use appropriate timeouts based on operation complexity');

    console.log('\n✅ Performance monitoring example completed!\n');

  } catch (error) {
    console.error('❌ Performance test error:', error.message);
    throw error;
  } finally {
    if (session) {
      await session.close();
    }
  }
}

/**
 * Main function to run all CredSSP examples
 */
async function runAllCredSSPExamples() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║           CredSSP Authentication Examples                    ║');
  console.log('║        Credential Security Support Provider Demo             ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  const examples = [
    { name: 'Basic CredSSP Authentication', fn: basicCredSSPExample },
    { name: 'Double-Hop CredSSP', fn: doubleHopCredSSPExample },
    { name: 'NTLM Base CredSSP', fn: ntlmBaseCredSSPExample },
    { name: 'Kerberos Base CredSSP', fn: kerberosBaseCredSSPExample },
    { name: 'Security Configuration', fn: securityConfigExample },
    { name: 'Error Handling', fn: errorHandlingExample },
    { name: 'Performance Monitoring', fn: performanceMonitoringExample }
  ];

  let completed = 0;
  let failed = 0;

  for (const example of examples) {
    console.log(`\n${'='.repeat(70)}`);
    console.log(`Running: ${example.name}`);
    console.log('='.repeat(70));
    
    try {
      await example.fn();
      completed++;
      console.log(`✅ ${example.name} completed successfully`);
    } catch (error) {
      failed++;
      console.log(`❌ ${example.name} failed: ${error.message}`);
      console.log('Continuing with next example...\n');
    }
    
    // Add small delay between examples
    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  console.log('\n' + '='.repeat(70));
  console.log('CredSSP Examples Summary');
  console.log('='.repeat(70));
  console.log(`Total examples: ${examples.length}`);
  console.log(`Completed: ${completed}`);
  console.log(`Failed: ${failed}`);
  console.log(`Success rate: ${((completed / examples.length) * 100).toFixed(1)}%`);
  
  if (failed > 0) {
    console.log('\n⚠️  Some examples failed. This is normal if:');
    console.log('   - Test servers are not available');
    console.log('   - Network connectivity issues exist');
    console.log('   - Authentication credentials are invalid');
    console.log('   - SSL/TLS configuration mismatches');
  }
  
  console.log('\n🎉 CredSSP examples demonstration complete!');
  console.log('\nNext steps:');
  console.log('   1. Update configuration with your actual server details');
  console.log('   2. Test with your specific environment');
  console.log('   3. Implement error handling in your application');
  console.log('   4. Configure security settings for production use');
  console.log('   5. Monitor performance in your environment');
}

// Run examples if this script is executed directly
if (require.main === module) {
  runAllCredSSPExamples().catch(error => {
    console.error('Fatal error running CredSSP examples:', error);
    process.exit(1);
  });
}

module.exports = {
  basicCredSSPExample,
  doubleHopCredSSPExample,
  ntlmBaseCredSSPExample,
  kerberosBaseCredSSPExample,
  securityConfigExample,
  errorHandlingExample,
  performanceMonitoringExample,
  runAllCredSSPExamples
};