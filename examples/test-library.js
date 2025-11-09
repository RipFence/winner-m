#!/usr/bin/env node

/**
 * Simple test script to verify JS-WinRM library functionality
 * This tests the basic components without requiring a real Windows server
 */

const winrm = require('../src/WinRM');

function testBasicFunctionality() {
  console.log('=== JS-WinRM Library Test ===\n');

  try {
    // Test 1: Module loading
    console.log('1. Testing module loading...');
    if (typeof winrm.Session === 'function' && typeof winrm.Protocol === 'function') {
      console.log('✅ Module loading successful');
    } else {
      throw new Error('Module loading failed');
    }

    // Test 2: Error classes
    console.log('\n2. Testing error classes...');
    const { WinRMError, WinRMAuthenticationError, WinRMConnectionError } = winrm;
    const testError = new WinRMError('Test error', 'TEST_CODE', { test: true });
    if (testError.code === 'TEST_CODE' && testError.details.test === true) {
      console.log('✅ Error classes working');
    } else {
      throw new Error('Error classes not working correctly');
    }

    // Test 3: Configuration validation
    console.log('\n3. Testing configuration validation...');
    const validConfig = {
      host: 'test.example.com',
      protocol: 'https',
      auth: {
        type: 'ntlm',
        username: 'test',
        password: 'test123',
        domain: 'TESTDOMAIN'
      }
    };

    const validationErrors = winrm.validateConfig(validConfig);
    if (validationErrors.length === 0) {
      console.log('✅ Configuration validation working');
    } else {
      throw new Error('Configuration validation failed: ' + validationErrors.join(', '));
    }

    // Test 4: Invalid configuration
    console.log('\n4. Testing invalid configuration...');
    const invalidConfig = { host: 'test.example.com' };
    const invalidErrors = winrm.validateConfig(invalidConfig);
    if (invalidErrors.length > 0 && invalidErrors.includes('Authentication configuration is required')) {
      console.log('✅ Invalid configuration detection working');
    } else {
      throw new Error('Invalid configuration not detected correctly');
    }

    // Test 5: Session creation
    console.log('\n5. Testing Session creation...');
    const session = winrm.createSession(validConfig);
    if (session && typeof session.run === 'function') {
      console.log('✅ Session creation successful');
    } else {
      throw new Error('Session creation failed');
    }

    // Test 6: Protocol creation
    console.log('\n6. Testing Protocol creation...');
    const protocol = winrm.createProtocol(validConfig);
    if (protocol && typeof protocol.openShell === 'function') {
      console.log('✅ Protocol creation successful');
    } else {
      throw new Error('Protocol creation failed');
    }

    // Test 7: Utility functions
    console.log('\n7. Testing utility functions...');
    const status = protocol.getStatus();
    if (status.connected === false && status.auth) {
      console.log('✅ Status reporting working');
    } else {
      throw new Error('Status reporting not working correctly');
    }

    console.log('\n✅ All basic functionality tests passed!');

  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  }
}

function testNTLMAuthentication() {
  console.log('\n=== NTLM Authentication Test ===\n');

  try {
    // Test NTLM class loading
    const NTLMAuth = require('../src/auth/NTLMAuth');
    console.log('1. NTLMAuth class loaded successfully');

    // Test NTLM instance creation
    const ntlmAuth = new NTLMAuth({
      username: 'testuser',
      password: 'testpass',
      domain: 'TESTDOMAIN',
      workstation: 'TESTWORKSTATION'
    });
    console.log('2. NTLMAuth instance created successfully');

    // Test Type 1 message generation
    const type1Message = ntlmAuth.buildType1Message();
    if (type1Message && type1Message.length > 0) {
      console.log('3. Type 1 message generated successfully (length:', type1Message.length, 'bytes)');
    } else {
      throw new Error('Type 1 message generation failed');
    }

    // Test authentication manager
    const AuthManager = require('../src/auth/AuthManager');
    const authManager = new AuthManager({
      host: 'test.example.com',
      protocol: 'https',
      auth: {
        type: 'ntlm',
        username: 'testuser',
        password: 'testpass',
        domain: 'TESTDOMAIN'
      }
    });
    console.log('4. AuthManager created successfully');

    const availableMethods = authManager.getAvailableMethods();
    if (availableMethods.includes('ntlm')) {
      console.log('5. NTLM method available in AuthManager');
    } else {
      throw new Error('NTLM method not available');
    }

    console.log('\n✅ NTLM authentication tests passed!');

  } catch (error) {
    console.error('\n❌ NTLM test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  }
}

function testXMLUtils() {
  console.log('\n=== XML Utilities Test ===\n');

  try {
    const XMLUtils = require('../src/utils/XMLUtils');
    
    // Test SOAP message generation
    console.log('1. Testing SOAP message generation...');
    
    const createShellMessage = XMLUtils.buildCreateShell();
    if (createShellMessage.includes('<s:Envelope') && createShellMessage.includes('Shell')) {
      console.log('   ✅ Create shell message generated');
    } else {
      throw new Error('Create shell message invalid');
    }

    const runCommandMessage = XMLUtils.buildRunCommand('test-shell-id', 'ipconfig /all');
    if (runCommandMessage.includes('CommandLine') && runCommandMessage.includes('test-shell-id')) {
      console.log('   ✅ Run command message generated');
    } else {
      throw new Error('Run command message invalid');
    }

    const getOutputMessage = XMLUtils.buildGetCommandOutput('test-shell-id', 'test-command-id');
    if (getOutputMessage.includes('Receive') && getOutputMessage.includes('test-command-id')) {
      console.log('   ✅ Get command output message generated');
    } else {
      throw new Error('Get command output message invalid');
    }

    console.log('\n✅ XML utilities tests passed!');

  } catch (error) {
    console.error('\n❌ XML utilities test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  }
}

function testSSLValidator() {
  console.log('\n=== SSL Validator Test ===\n');

  try {
    const SSLValidator = require('../src/transport/SSLValidator');
    
    console.log('1. Testing SSLValidator creation...');
    const sslValidator = new SSLValidator();
    console.log('   ✅ SSLValidator created successfully');

    console.log('2. Testing SSL options generation...');
    const sslOptions = sslValidator.buildSSLOptions({
      rejectUnauthorized: true,
      servername: 'test.example.com'
    });
    if (sslOptions.rejectUnauthorized && sslOptions.servername === 'test.example.com') {
      console.log('   ✅ SSL options generated correctly');
    } else {
      throw new Error('SSL options generation failed');
    }

    console.log('3. Testing recommended configuration...');
    const recommended = sslValidator.getRecommendedConfig();
    if (recommended.ssl.rejectUnauthorized === true && recommended.ssl.minVersion === 'TLSv1.2') {
      console.log('   ✅ Recommended configuration looks good');
    } else {
      throw new Error('Recommended configuration invalid');
    }

    console.log('\n✅ SSL validator tests passed!');

  } catch (error) {
    console.error('\n❌ SSL validator test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  }
}

function testConnectionManager() {
  console.log('\n=== Connection Manager Test ===\n');

  try {
    const HttpClient = require('../src/transport/HttpClient');
    
    console.log('1. Testing HttpClient creation...');
    const httpClient = new HttpClient({
      host: 'test.example.com',
      protocol: 'https',
      port: 5986,
      timeouts: {
        connectTimeout: 10000,
        readTimeout: 30000
      }
    });
    console.log('   ✅ HttpClient created successfully');

    console.log('2. Testing connection statistics...');
    const stats = httpClient.getConnectionStats();
    if (stats.activeConnections === 0 && stats.maxConnections === 10) {
      console.log('   ✅ Connection statistics working');
    } else {
      throw new Error('Connection statistics invalid');
    }

    console.log('3. Testing SSL configuration...');
    const httpsClient = new HttpClient({
      host: 'test.example.com',
      protocol: 'https',
      port: 5986,
      ssl: {
        rejectUnauthorized: false,
        ca: 'test-ca'
      }
    });
    console.log('   ✅ HTTPS client with SSL config created');

    console.log('\n✅ Connection manager tests passed!');

  } catch (error) {
    console.error('\n❌ Connection manager test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  }
}

// Run all tests
if (require.main === module) {
  console.log('Starting JS-WinRM library tests...\n');
  
  testBasicFunctionality();
  testNTLMAuthentication();
  testXMLUtils();
  testSSLValidator();
  testConnectionManager();

  console.log('\n🎉 All tests completed successfully!');
  console.log('\nThe JS-WinRM library is ready for use.');
  console.log('To use it in production, you will need:');
  console.log('  - A Windows server with WinRM enabled');
  console.log('  - Proper authentication credentials (NTLM)');
  console.log('  - SSL certificates for secure connections');
  console.log('\nSee examples/basic-usage.js for detailed usage examples.');
}

module.exports = {
  testBasicFunctionality,
  testNTLMAuthentication,
  testXMLUtils,
  testSSLValidator,
  testConnectionManager
};