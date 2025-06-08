// example.js
// This file demonstrates how to use the WinRmClient.
// Before running:
// 1. Ensure you have Node.js installed.
// 2. Save this file, package.json, winrm-client.js, winrm-transport.js, and winrm-protocol.js
//    in the same directory.
// 3. Run `npm install` in your terminal in that directory to install dependencies.
// 4. Configure your Windows server for WinRM (e.g., `winrm quickconfig -q` on the server).
//    Ensure the firewall allows connections on port 5986 (HTTPS) or 5985 (HTTP).

import { WinRmClient } from './winrm-client.js';

// --- Configuration ---
const WINRM_HOST = 'YOUR_WINDOWS_SERVER_IP_OR_HOSTNAME'; // e.g., '192.168.1.100' or 'mywindowsserver.local'
const WINRM_USERNAME = 'YOUR_USERNAME'; // e.g., 'Administrator' or 'DOMAIN\\username'
const WINRM_PASSWORD = 'YOUR_PASSWORD';

// IMPORTANT: For production, ALWAYS use HTTPS.
// If your server uses a self-signed certificate, set rejectUnauthorized to false (less secure but needed for testing).
const CLIENT_OPTIONS = {
    port: 5986,          // Default WinRM HTTPS port
    https: true,         // Always prefer HTTPS
    timeout: 60000,      // 60 seconds
    rejectUnauthorized: false, // Set to false if using self-signed certificates for testing
};

async function runExample() {
    console.log('Starting WinRM client example...');

    const client = new WinRmClient(
        WINRM_HOST,
        WINRM_USERNAME,
        WINRM_PASSWORD,
        CLIENT_OPTIONS
    );

    try {
        console.log('\n--- Running a simple command (ipconfig) ---');
        const cmdResult = await client.runPsCommand('ipconfig /all');
        console.log('ipconfig Output:');
        console.log('STDOUT:\n', cmdResult.stdout);
        console.log('STDERR:\n', cmdResult.stderr);
        console.log('Exit Code:', cmdResult.exitCode);

        console.log('\n--- Running a PowerShell command (Get-Process) ---');
        // Example PowerShell command: Get-Process | Select-Object -First 5
        const psCommand = 'Get-Process | Select-Object -First 5 | Format-Table -AutoSize';
        const psResult = await client.runPsCommand('powershell -EncodedCommand', [psCommand]);
        console.log('Get-Process Output:');
        console.log('STDOUT:\n', psResult.stdout);
        console.log('STDERR:\n', psResult.stderr);
        console.log('Exit Code:', psResult.exitCode);

        console.log('\n--- Running a command that fails (nonExistentCommand) ---');
        try {
            const failResult = await client.runPsCommand('nonExistentCommand');
            console.log('Unexpected success for failing command:', failResult);
        } catch (error) {
            console.log('Expected error caught for failing command:', error.message);
        }

    } catch (error) {
        console.error('An unhandled error occurred during the example:', error);
    }
}
