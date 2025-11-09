#!/usr/bin/env node

/**
 * Verification script for CredSSP authentication tests
 * Validates test structure and basic functionality
 */

const fs = require('fs');
const path = require('path');

function verifyTestFile() {
  console.log('=== CredSSP Test Verification ===\n');

  const testFilePath = path.join(__dirname, 'tests', 'credssp-auth-test.js');
  
  if (!fs.existsSync(testFilePath)) {
    throw new Error('Test file not found: ' + testFilePath);
  }

  const testContent = fs.readFileSync(testFilePath, 'utf8');

  console.log('1. Checking test file structure...');
  
  // Check for required imports
  const requiredImports = [
    "require('../src/auth/CredSSPAuth')",
    "require('../src/utils/ErrorTypes')",
    "describe('CredSSPAuth'"
  ];
  
  for (const importStr of requiredImports) {
    if (testContent.includes(importStr)) {
      console.log(`   ✅ Contains: ${importStr}`);
    } else {
      throw new Error(`Missing: ${importStr}`);
    }
  }

  console.log('\n2. Checking test categories...');
  
  // Check for required test categories
  const requiredCategories = [
    'CredSSPAuth class instantiation',
    'Configuration validation',
    'Base authentication method validation',
    'TSP request/response handling',
    'Double-hop configuration',
    'Error handling'
  ];
  
  for (const category of requiredCategories) {
    if (testContent.includes(category)) {
      console.log(`   ✅ Test category: ${category}`);
    } else {
      throw new Error(`Missing test category: ${category}`);
    }
  }

  console.log('\n3. Checking test count...');
  
  // Count test cases
  const testCount = (testContent.match(/test\(/g) || []).length;
  console.log(`   ✅ Found ${testCount} test cases`);

  console.log('\n4. Checking error handling tests...');
  
  // Check for error handling tests
  const errorTests = [
    'should throw error when username is missing',
    'should throw error when password is missing',
    'should throw error for invalid base authentication method',
    'should handle missing username gracefully',
    'should handle missing password gracefully'
  ];
  
  for (const test of errorTests) {
    if (testContent.includes(test)) {
      console.log(`   ✅ Error test: ${test}`);
    } else {
      console.log(`   ⚠️  Warning: Missing error test: ${test}`);
    }
  }

  console.log('\n5. Checking TSP protocol tests...');
  
  // Check for TSP tests
  const tspTests = [
    'should create TSP credential structure',
    'should create CredSSP message',
    'should parse CredSSP response correctly',
    'should extract CredSSP challenge from response body'
  ];
  
  for (const test of tspTests) {
    if (testContent.includes(test)) {
      console.log(`   ✅ TSP test: ${test}`);
    } else {
      console.log(`   ⚠️  Warning: Missing TSP test: ${test}`);
    }
  }

  console.log('\n6. Checking double-hop configuration tests...');
  
  // Check for double-hop tests
  const doubleHopTests = [
    'should configure with credential delegation enabled by default',
    'should configure with credential delegation disabled',
    'should generate service principal name for Kerberos'
  ];
  
  for (const test of doubleHopTests) {
    if (testContent.includes(test)) {
      console.log(`   ✅ Double-hop test: ${test}`);
    } else {
      console.log(`   ⚠️  Warning: Missing double-hop test: ${test}`);
    }
  }

  console.log('\n7. Checking authentication flow tests...');
  
  // Check for authentication flow tests
  const flowTests = [
    'should complete authentication flow with NTLM base',
    'should complete authentication flow with Kerberos base',
    'should handle multi-step CredSSP handshake'
  ];
  
  for (const test of flowTests) {
    if (testContent.includes(test)) {
      console.log(`   ✅ Flow test: ${test}`);
    } else {
      console.log(`   ⚠️  Warning: Missing flow test: ${test}`);
    }
  }

  console.log('\n8. Checking edge case tests...');
  
  // Check for edge case tests
  const edgeCaseTests = [
    'should handle empty domain string',
    'should handle very long username and password',
    'should handle special characters in credentials',
    'should handle Unicode characters in credentials'
  ];
  
  for (const test of edgeCaseTests) {
    if (testContent.includes(test)) {
      console.log(`   ✅ Edge case test: ${test}`);
    } else {
      console.log(`   ⚠️  Warning: Missing edge case test: ${test}`);
    }
  }

  console.log('\n9. Verifying test file size and complexity...');
  
  const lines = testContent.split('\n').length;
  console.log(`   ✅ Test file size: ${lines} lines`);
  
  const fileSize = fs.statSync(testFilePath).size;
  console.log(`   ✅ Test file size: ${fileSize} bytes`);

  console.log('\n10. Checking for Jest patterns...');
  
  const jestPatterns = [
    { pattern: 'describe(', name: 'describe' },
    { pattern: 'test(', name: 'test' },
    { pattern: 'beforeEach(', name: 'beforeEach' },
    { pattern: 'afterEach(', name: 'afterEach' },
    { pattern: 'jest.fn()', name: 'jest.fn' },
    { pattern: 'expect(', name: 'expect' }
  ];
  
  for (const { pattern, name } of jestPatterns) {
    const escapedPattern = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const count = (testContent.match(new RegExp(escapedPattern, 'g')) || []).length;
    if (count > 0) {
      console.log(`   ✅ Jest pattern "${pattern}": ${count} occurrences`);
    } else {
      console.log(`   ⚠️  Warning: Jest pattern "${pattern}" not found`);
    }
  }

  console.log('\n✅ Test file verification completed successfully!');
  console.log(`\n📊 Test Summary:`);
  console.log(`   Test file: ${testFilePath}`);
  console.log(`   Total lines: ${lines}`);
  console.log(`   File size: ${fileSize} bytes`);
  console.log(`   Estimated test cases: ${testCount}`);
  console.log(`   Test coverage areas: ${requiredCategories.length}`);

  return true;
}

function verifyTestDirectory() {
  console.log('\n=== Test Directory Structure ===\n');

  const testsDir = path.join(__dirname, 'tests');
  
  if (!fs.existsSync(testsDir)) {
    throw new Error('Tests directory not found: ' + testsDir);
  }

  const testFiles = fs.readdirSync(testsDir).filter(file => file.endsWith('-test.js'));
  
  console.log(`Found ${testFiles.length} test files:`);
  for (const file of testFiles) {
    const filePath = path.join(testsDir, file);
    const stats = fs.statSync(filePath);
    console.log(`   ✅ ${file} (${stats.size} bytes)`);
  }

  console.log('\n✅ Test directory verification completed!');
}

function checkPackageJsonTestConfig() {
  console.log('\n=== Package.json Test Configuration ===\n');

  const packageJsonPath = path.join(__dirname, 'package.json');
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

  if (packageJson.scripts && packageJson.scripts.test) {
    console.log(`   ✅ npm test script: ${packageJson.scripts.test}`);
  } else {
    console.log('   ⚠️  Warning: No test script found in package.json');
  }

  if (packageJson.devDependencies && packageJson.devDependencies.jest) {
    console.log(`   ✅ Jest dependency: ${packageJson.devDependencies.jest}`);
  } else {
    console.log('   ⚠️  Warning: Jest not found in devDependencies');
  }

  if (packageJson.scripts && packageJson.scripts['test:watch']) {
    console.log(`   ✅ npm test:watch script: ${packageJson.scripts['test:watch']}`);
  }

  if (packageJson.scripts && packageJson.scripts['test:coverage']) {
    console.log(`   ✅ npm test:coverage script: ${packageJson.scripts['test:coverage']}`);
  }

  console.log('\n✅ Package.json configuration verification completed!');
}

function main() {
  try {
    console.log('Starting CredSSP test verification...\n');
    
    verifyTestFile();
    verifyTestDirectory();
    checkPackageJsonTestConfig();
    
    console.log('\n🎉 All verifications passed successfully!');
    console.log('\n📋 To run the tests:');
    console.log('   1. npm install (to install dependencies)');
    console.log('   2. npm test (to run all tests)');
    console.log('   3. npm test -- --testPathPattern=credssp-auth-test.js (to run specific test)');
    
  } catch (error) {
    console.error('\n❌ Verification failed:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  verifyTestFile,
  verifyTestDirectory,
  checkPackageJsonTestConfig
};