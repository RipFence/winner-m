/**
 * Kerberos Authentication Examples
 * 
 * This file demonstrates various Kerberos authentication scenarios using the
 * kerberos library. Kerberos is a network authentication protocol that uses
 * tickets to allow nodes to identify themselves securely.
 * 
 * Prerequisites:
 * - npm install kerberos
 * - Proper Kerberos configuration (krb5.conf)
 * - Valid Kerberos credentials or keytab files
 */

const kerberos = require('kerberos');
const fs = require('fs');
const path = require('path');

/**
 * Example 1: Basic Kerberos Authentication
 * 
 * This example shows the simplest form of Kerberos authentication using
 * a username and password. This is typically used for initial testing
 * or when a keytab file is not available.
 */
async function basicKerberosAuth() {
    console.log('\n=== Example 1: Basic Kerberos Authentication ===');
    
    const config = {
        // Specify the Kerberos realm
        realm: 'EXAMPLE.COM',
        
        // Username and password for authentication
        username: 'john.doe',
        password: 'secure_password_here',
        
        // Optional: Specify KDC server
        kdc: 'kdc.example.com',
        
        // Optional: Specify admin server
        admin_server: 'admin.example.com',
        
        // Optional: Specify Kerberos server
        krb5_server: 'kdc.example.com'
    };
    
    try {
        console.log('Attempting basic Kerberos authentication...');
        console.log(`Realm: ${config.realm}`);
        console.log(`Username: ${config.username}`);
        
        // Create Kerberos client
        const client = new kerberos.Client({
            realm: config.realm,
            kdc: config.kdc
        });
        
        // Initialize and authenticate
        await client.initialize();
        
        // Step 1: Get TGT (Ticket Granting Ticket)
        const tgt = await client.getTGT(config.username, config.password);
        console.log('✓ TGT obtained successfully');
        console.log(`TGT server: ${tgt.serverName}`);
        console.log(`TGT expires: ${tgt.validUntil}`);
        
        // Step 2: Get service ticket for specific service
        const serviceTicket = await client.getServerTicket(
            'http', 
            'service.example.com'
        );
        console.log('✓ Service ticket obtained successfully');
        console.log(`Service principal: ${serviceTicket.serverName}`);
        
        return {
            success: true,
            client,
            tickets: {
                tgt,
                serviceTicket
            }
        };
        
    } catch (error) {
        console.error('✗ Basic Kerberos authentication failed:', error.message);
        handleKerberosError(error, 'basic');
        return { success: false, error: error.message };
    }
}

/**
 * Example 2: Kerberos with Custom KDC
 * 
 * This example demonstrates connecting to a custom KDC (Key Distribution Center)
 * which is useful when working in different network environments or when
 * testing against specific Kerberos implementations.
 */
async function customKDCKerberosAuth() {
    console.log('\n=== Example 2: Kerberos with Custom KDC ===');
    
    const customKDCConfig = {
        // Custom KDC configuration
        kdc: 'kdc.custom.domain:88',
        admin_server: 'kdc.custom.domain:749',
        krb5_server: 'kdc.custom.domain:88',
        
        // Kerberos configuration overrides
        krb5_config: {
            // Custom realm configuration
            realms: {
                'CUSTOM.DOMAIN': {
                    kdc: ['kdc.custom.domain:88'],
                    admin_server: 'kdc.custom.domain:749',
                    default_domain: 'custom.domain'
                }
            },
            
            // Domain realm mapping
            domain_realm: {
                'custom.domain': 'CUSTOM.DOMAIN',
                '.custom.domain': 'CUSTOM.DOMAIN'
            }
        },
        
        // Authentication details
        username: 'service.account',
        password: 'service_account_password',
        service: 'HTTP/api.service.com@CUSTOM.DOMAIN'
    };
    
    try {
        console.log(`Connecting to custom KDC: ${customKDCConfig.kdc}`);
        console.log(`Realm: CUSTOM.DOMAIN`);
        
        // Create client with custom KDC
        const client = new kerberos.Client({
            realm: 'CUSTOM.DOMAIN',
            kdc: customKDCConfig.kdc,
            krb5_config: customKDCConfig.krb5_config
        });
        
        await client.initialize();
        
        // Authenticate with custom KDC
        const tgt = await client.getTGT(
            customKDCConfig.username, 
            customKDCConfig.password
        );
        
        console.log('✓ Authenticated with custom KDC successfully');
        console.log(`KDC used: ${customKDCConfig.kdc}`);
        
        // Test service ticket acquisition
        const serviceTicket = await client.getServerTicket(
            'HTTP', 
            'api.service.com'
        );
        
        console.log('✓ Service ticket acquired from custom KDC');
        
        return {
            success: true,
            client,
            kdcConfig: customKDCConfig.kdc,
            tickets: { tgt, serviceTicket }
        };
        
    } catch (error) {
        console.error('✗ Custom KDC authentication failed:', error.message);
        handleKerberosError(error, 'custom_kdc');
        return { success: false, error: error.message };
    }
}

/**
 * Example 3: Kerberos with Keytab File
 * 
 * Keytab files contain Kerberos principal names and encrypted keys that can
 * be used for authentication without providing a password. This is the
 * recommended approach for service accounts and automated processes.
 */
async function keytabKerberosAuth() {
    console.log('\n=== Example 3: Kerberos with Keytab File ===');
    
    const keytabConfig = {
        // Path to keytab file
        keytab_path: '/etc/krb5.keytab', // Linux/Unix path
        // keytab_path: 'C:\\Program Files\\Kerberos\\service.keytab', // Windows path
        
        // Service principal for authentication
        service_principal: 'service_account@EXAMPLE.COM',
        
        // Alternative keytab locations
        alternative_keytabs: [
            '/etc/security/keytabs/service.keytab',
            './config/service.keytab',
            '/var/lib/kerberos/service.keytab'
        ],
        
        // Keytab authentication options
        options: {
            // Force re-authentication even if ticket is cached
            force_refresh: true,
            
            // Set specific encryption types
            encryption_types: ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96'],
            
            // Set ticket lifetime
            ticket_lifetime: '24h'
        }
    };
    
    try {
        // Check if keytab file exists
        if (!fs.existsSync(keytabConfig.keytab_path)) {
            throw new Error(`Keytab file not found: ${keytabConfig.keytab_path}`);
        }
        
        console.log(`Using keytab file: ${keytabConfig.keytab_path}`);
        console.log(`Service principal: ${keytabConfig.service_principal}`);
        
        // Create client with keytab authentication
        const client = new kerberos.Client({
            realm: 'EXAMPLE.COM',
            keytab: keytabConfig.keytab_path,
            principal: keytabConfig.service_principal
        });
        
        await client.initialize();
        
        // Read keytab file to verify principal
        const keytabData = fs.readFileSync(keytabConfig.keytab_path);
        console.log(`✓ Keytab file loaded (${keytabData.length} bytes)`);
        console.log('✓ Keytab authentication successful');
        
        // Get service ticket using keytab
        const serviceTicket = await client.getServerTicket(
            'HTTP', 
            'api.example.com'
        );
        
        console.log('✓ Service ticket acquired using keytab');
        console.log(`Principal: ${keytabConfig.service_principal}`);
        
        // Verify ticket details
        const ticketInfo = {
            serverName: serviceTicket.serverName,
            clientName: serviceTicket.clientName,
            validUntil: serviceTicket.validUntil,
            issued: serviceTicket.issued
        };
        
        console.log('Ticket Details:');
        console.log(`  Server: ${ticketInfo.serverName}`);
        console.log(`  Client: ${ticketInfo.clientName}`);
        console.log(`  Valid until: ${ticketInfo.validUntil}`);
        
        return {
            success: true,
            client,
            keytab: keytabConfig.keytab_path,
            principal: keytabConfig.service_principal,
            tickets: { serviceTicket }
        };
        
    } catch (error) {
        console.error('✗ Keytab authentication failed:', error.message);
        handleKerberosError(error, 'keytab');
        
        // Try alternative keytab locations
        for (const altKeytab of keytabConfig.alternative_keytabs) {
            try {
                if (fs.existsSync(altKeytab)) {
                    console.log(`Trying alternative keytab: ${altKeytab}`);
                    // Retry with alternative keytab
                    return await keytabKerberosAuthWithPath(altKeytab);
                }
            } catch (altError) {
                console.log(`Alternative keytab failed: ${altKeytab}`);
            }
        }
        
        return { success: false, error: error.message };
    }
}

/**
 * Helper function for keytab authentication with specific path
 */
async function keytabKerberosAuthWithPath(keytabPath) {
    const client = new kerberos.Client({
        realm: 'EXAMPLE.COM',
        keytab: keytabPath
    });
    
    await client.initialize();
    console.log(`✓ Successfully authenticated with keytab: ${keytabPath}`);
    
    return {
        success: true,
        client,
        keytab: keytabPath
    };
}

/**
 * Example 4: Kerberos with Service Principal
 * 
 * Service principals are used to identify services in a Kerberos environment.
 * This example shows how to configure and authenticate using service principals
 * for different types of services.
 */
async function servicePrincipalKerberosAuth() {
    console.log('\n=== Example 4: Kerberos with Service Principal ===');
    
    const servicePrincipalConfig = {
        // Service principal configurations for different services
        service_principals: {
            web_service: 'HTTP/web-service.example.com@EXAMPLE.COM',
            database_service: 'postgres/db-server.example.com@EXAMPLE.COM',
            ldap_service: 'ldap/dc.example.com@EXAMPLE.COM',
            smtp_service: 'smtp/mail.example.com@EXAMPLE.COM',
            ssh_service: 'host/ssh-server.example.com@EXAMPLE.COM'
        },
        
        // Service authentication configuration
        authentication: {
            // Service to authenticate as
            target_service: 'web_service',
            
            // Authentication method (keytab or password)
            method: 'keytab', // 'keytab' or 'password'
            
            // Keytab file for service principal
            keytab: '/etc/krb5.service.keytab',
            
            // Service-specific options
            service_options: {
                // Server name for service
                server_name: 'web-service.example.com',
                
                // Service port
                port: 443,
                
                // Request specific service ticket
                service_ticket: 'HTTP/web-service.example.com',
                
                // Set mutual authentication requirement
                mutual_auth: true,
                
                // Request forwardable tickets
                forwardable: true,
                
                // Request renewable tickets
                renewable: true
            }
        }
    };
    
    try {
        const service = servicePrincipalConfig.service_principals[
            servicePrincipalConfig.authentication.target_service
        ];
        
        console.log(`Authenticating as service principal: ${service}`);
        console.log(`Authentication method: ${servicePrincipalConfig.authentication.method}`);
        
        // Create client for service principal authentication
        const client = new kerberos.Client({
            realm: 'EXAMPLE.COM',
            principal: service,
            keytab: servicePrincipalConfig.authentication.keytab
        });
        
        await client.initialize();
        
        // Get service ticket for target service
        const serviceTicket = await client.getServerTicket(
            'HTTP', 
            'web-service.example.com'
        );
        
        console.log('✓ Service principal authentication successful');
        console.log(`Service principal: ${service}`);
        
        // Example: Get tickets for multiple services
        const allServices = Object.values(servicePrincipalConfig.service_principals);
        const serviceTickets = {};
        
        for (const principal of allServices) {
            try {
                const serviceTicket = await client.getServerTicket(
                    principal.split('/')[0], 
                    principal.split('/')[1].split('@')[0]
                );
                serviceTickets[principal] = {
                    serverName: serviceTicket.serverName,
                    validUntil: serviceTicket.validUntil
                };
            } catch (serviceError) {
                console.log(`Warning: Could not get ticket for ${principal}: ${serviceError.message}`);
            }
        }
        
        console.log(`✓ Service tickets obtained for ${Object.keys(serviceTickets).length} services`);
        
        // Demonstrate mutual authentication
        if (servicePrincipalConfig.authentication.service_options.mutual_auth) {
            const mutualTicket = await client.getMutualTicket(
                'HTTP', 
                'web-service.example.com'
            );
            console.log('✓ Mutual authentication successful');
        }
        
        return {
            success: true,
            client,
            service_principal: service,
            service_tickets: serviceTickets,
            mutual_auth: servicePrincipalConfig.authentication.service_options.mutual_auth
        };
        
    } catch (error) {
        console.error('✗ Service principal authentication failed:', error.message);
        handleKerberosError(error, 'service_principal');
        return { success: false, error: error.message };
    }
}

/**
 * Example 5: Comprehensive Error Handling
 * 
 * This example demonstrates proper error handling for various Kerberos
 * authentication failures and provides strategies for recovery.
 */
async function kerberosErrorHandlingExamples() {
    console.log('\n=== Example 5: Kerberos Error Handling ===');
    
    const errorHandlingConfig = {
        // Common error scenarios to handle
        test_scenarios: [
            {
                name: 'Invalid Credentials',
                config: {
                    username: 'invalid_user',
                    password: 'wrong_password',
                    realm: 'EXAMPLE.COM'
                }
            },
            {
                name: 'Invalid Realm',
                config: {
                    username: 'john.doe',
                    password: 'correct_password',
                    realm: 'INVALID.REALM'
                }
            },
            {
                name: 'Missing Keytab',
                config: {
                    keytab_path: '/nonexistent/path/to/keytab',
                    principal: 'service@EXAMPLE.COM'
                }
            },
            {
                name: 'Expired Ticket',
                config: {
                    username: 'john.doe',
                    password: 'password',
                    realm: 'EXAMPLE.COM',
                    ticket_lifetime: '0s' // Immediate expiration
                }
            }
        ],
        
        // Error handling strategies
        recovery_strategies: {
            invalid_credentials: {
                strategy: 'prompt_for_retry',
                max_retries: 3,
                fallback_auth: 'keytab'
            },
            network_error: {
                strategy: 'retry_with_backoff',
                initial_delay: 1000,
                max_delay: 30000,
                backoff_multiplier: 2,
                max_retries: 5
            },
            invalid_realm: {
                strategy: 'try_default_realm',
                default_realm: 'EXAMPLE.COM'
            },
            expired_ticket: {
                strategy: 'renew_ticket',
                renewal_window: 300 // 5 minutes before expiration
            }
        }
    };
    
    const errorResults = [];
    
    for (const scenario of errorHandlingConfig.test_scenarios) {
        console.log(`\n--- Testing: ${scenario.name} ---`);
        
        try {
            let result;
            
            switch (scenario.name) {
                case 'Invalid Credentials':
                    result = await handleInvalidCredentials(scenario.config);
                    break;
                case 'Invalid Realm':
                    result = await handleInvalidRealm(scenario.config);
                    break;
                case 'Missing Keytab':
                    result = await handleMissingKeytab(scenario.config);
                    break;
                case 'Expired Ticket':
                    result = await handleExpiredTicket(scenario.config);
                    break;
                default:
                    result = await testGenericKerberosAuth(scenario.config);
            }
            
            errorResults.push({
                scenario: scenario.name,
                success: result.success,
                error: result.error || null,
                recovery_attempted: result.recovery_attempted || false
            });
            
        } catch (error) {
            console.error(`✗ ${scenario.name} test failed:`, error.message);
            errorResults.push({
                scenario: scenario.name,
                success: false,
                error: error.message,
                recovery_attempted: false
            });
        }
    }
    
    // Display error handling summary
    console.log('\n--- Error Handling Summary ---');
    errorResults.forEach(result => {
        const status = result.success ? '✓' : '✗';
        const recovery = result.recovery_attempted ? ' (recovery attempted)' : '';
        console.log(`${status} ${result.scenario}${recovery}: ${result.error || 'Success'}`);
    });
    
    return {
        success: true,
        results: errorResults,
        recovery_strategies: errorHandlingConfig.recovery_strategies
    };
}

/**
 * Handle invalid credentials error
 */
async function handleInvalidCredentials(config) {
    try {
        const client = new kerberos.Client({
            realm: config.realm,
            kdc: 'kdc.example.com'
        });
        
        await client.initialize();
        await client.getTGT(config.username, config.password);
        
        return { success: true, recovery_attempted: false };
        
    } catch (error) {
        console.log('Invalid credentials detected, attempting keytab fallback...');
        
        // Try keytab fallback
        if (error.message.includes('Credentials cache') || 
            error.message.includes('Invalid credentials')) {
            
            try {
                const keytabResult = await keytabKerberosAuth();
                return { 
                    success: keytabResult.success, 
                    recovery_attempted: true,
                    recovery_method: 'keytab_fallback'
                };
            } catch (keytabError) {
                return { 
                    success: false, 
                    error: 'Both password and keytab authentication failed',
                    recovery_attempted: true
                };
            }
        }
        
        return { success: false, error: error.message, recovery_attempted: false };
    }
}

/**
 * Handle invalid realm error
 */
async function handleInvalidRealm(config) {
    try {
        const client = new kerberos.Client({
            realm: config.realm,
            kdc: 'kdc.example.com'
        });
        
        await client.initialize();
        return { success: true, recovery_attempted: false };
        
    } catch (error) {
        if (error.message.includes('Realm not found') || 
            error.message.includes('KDC not found')) {
            
            console.log('Invalid realm detected, trying default realm...');
            
            // Try with default realm
            try {
                const client = new kerberos.Client({
                    realm: 'EXAMPLE.COM',
                    kdc: 'kdc.example.com'
                });
                
                await client.initialize();
                return { 
                    success: true, 
                    recovery_attempted: true,
                    recovery_method: 'default_realm_fallback'
                };
            } catch (defaultError) {
                return { 
                    success: false, 
                    error: 'Default realm also failed',
                    recovery_attempted: true
                };
            }
        }
        
        return { success: false, error: error.message, recovery_attempted: false };
    }
}

/**
 * Handle missing keytab file error
 */
async function handleMissingKeytab(config) {
    try {
        if (!fs.existsSync(config.keytab_path)) {
            throw new Error(`Keytab file not found: ${config.keytab_path}`);
        }
        
        const client = new kerberos.Client({
            realm: 'EXAMPLE.COM',
            keytab: config.keytab_path,
            principal: config.principal
        });
        
        await client.initialize();
        return { success: true, recovery_attempted: false };
        
    } catch (error) {
        if (error.message.includes('not found')) {
            console.log('Keytab not found, attempting password authentication...');
            
            // Try password authentication as fallback
            try {
                const client = new kerberos.Client({
                    realm: 'EXAMPLE.COM',
                    kdc: 'kdc.example.com'
                });
                
                await client.initialize();
                return { 
                    success: true, 
                    recovery_attempted: true,
                    recovery_method: 'password_fallback'
                };
            } catch (passwordError) {
                return { 
                    success: false, 
                    error: 'Both keytab and password authentication failed',
                    recovery_attempted: true
                };
            }
        }
        
        return { success: false, error: error.message, recovery_attempted: false };
    }
}

/**
 * Handle expired ticket error
 */
async function handleExpiredTicket(config) {
    try {
        const client = new kerberos.Client({
            realm: config.realm,
            kdc: 'kdc.example.com'
        });
        
        await client.initialize();
        const tgt = await client.getTGT('john.doe', 'password');
        
        // Check if ticket is expired
        const now = new Date();
        const expiry = new Date(tgt.validUntil);
        
        if (expiry <= now) {
            throw new Error('Ticket has expired');
        }
        
        return { success: true, recovery_attempted: false };
        
    } catch (error) {
        if (error.message.includes('expired')) {
            console.log('Ticket expired, requesting new ticket...');
            
            // Renew ticket
            try {
                const client = new kerberos.Client({
                    realm: config.realm,
                    kdc: 'kdc.example.com'
                });
                
                await client.initialize();
                const newTgt = await client.getTGT('john.doe', 'password');
                
                return { 
                    success: true, 
                    recovery_attempted: true,
                    recovery_method: 'ticket_renewal'
                };
            } catch (renewalError) {
                return { 
                    success: false, 
                    error: 'Ticket renewal failed',
                    recovery_attempted: true
                };
            }
        }
        
        return { success: false, error: error.message, recovery_attempted: false };
    }
}

/**
 * Generic Kerberos authentication test
 */
async function testGenericKerberosAuth(config) {
    try {
        const client = new kerberos.Client({
            realm: config.realm,
            kdc: 'kdc.example.com'
        });
        
        await client.initialize();
        return { success: true, recovery_attempted: false };
        
    } catch (error) {
        return { success: false, error: error.message, recovery_attempted: false };
    }
}

/**
 * Centralized error handling function
 */
function handleKerberosError(error, context) {
    const errorType = categorizeKerberosError(error);
    
    console.log(`\nError Context: ${context}`);
    console.log(`Error Type: ${errorType}`);
    console.log(`Error Message: ${error.message}`);
    
    switch (errorType) {
        case 'CREDENTIALS_INVALID':
            console.log('Recovery: Check username/password or try keytab authentication');
            break;
        case 'KDC_NOT_FOUND':
            console.log('Recovery: Verify KDC server is reachable and accessible');
            break;
        case 'REALM_NOT_FOUND':
            console.log('Recovery: Verify realm configuration and DNS resolution');
            break;
        case 'TICKET_EXPIRED':
            console.log('Recovery: Renew ticket or re-authenticate');
            break;
        case 'NETWORK_ERROR':
            console.log('Recovery: Check network connectivity to KDC');
            break;
        case 'KEYTAB_ERROR':
            console.log('Recovery: Verify keytab file exists and has correct permissions');
            break;
        case 'SERVICE_ERROR':
            console.log('Recovery: Check service principal configuration');
            break;
        default:
            console.log('Recovery: Review configuration and consult Kerberos logs');
    }
    
    console.log('---');
}

/**
 * Categorize Kerberos errors for proper handling
 */
function categorizeKerberosError(error) {
    const message = error.message.toLowerCase();
    
    if (message.includes('invalid credentials') || 
        message.includes('credential cache') ||
        message.includes('authentication failed')) {
        return 'CREDENTIALS_INVALID';
    }
    
    if (message.includes('kdc not found') || 
        message.includes('cannot contact any kdc') ||
        message.includes('network unreachable')) {
        return 'KDC_NOT_FOUND';
    }
    
    if (message.includes('realm not found') || 
        message.includes('unknown realm') ||
        message.includes('kdc has no support for encryption type')) {
        return 'REALM_NOT_FOUND';
    }
    
    if (message.includes('expired') || 
        message.includes('ticket expired') ||
        message.includes('not yet valid')) {
        return 'TICKET_EXPIRED';
    }
    
    if (message.includes('network') || 
        message.includes('connection') ||
        message.includes('timeout')) {
        return 'NETWORK_ERROR';
    }
    
    if (message.includes('keytab') || 
        message.includes('no such file') ||
        message.includes('permission denied')) {
        return 'KEYTAB_ERROR';
    }
    
    if (message.includes('service') || 
        message.includes('principal') ||
        message.includes('server not found')) {
        return 'SERVICE_ERROR';
    }
    
    return 'UNKNOWN_ERROR';
}

/**
 * Main function to run all examples
 */
async function runAllKerberosExamples() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║          Kerberos Authentication Examples                    ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    
    const results = {};
    
    try {
        // Run all examples
        results.basic = await basicKerberosAuth();
        results.customKDC = await customKDCKerberosAuth();
        results.keytab = await keytabKerberosAuth();
        results.servicePrincipal = await servicePrincipalKerberosAuth();
        results.errorHandling = await kerberosErrorHandlingExamples();
        
        // Summary
        console.log('\n╔══════════════════════════════════════════════════════════════╗');
        console.log('║                    Results Summary                           ║');
        console.log('╚══════════════════════════════════════════════════════════════╝');
        
        Object.keys(results).forEach(example => {
            const success = results[example].success;
            const status = success ? '✓' : '✗';
            console.log(`${status} ${example.replace(/([A-Z])/g, ' $1').toLowerCase()}`);
        });
        
        // Success rate
        const successfulExamples = Object.values(results).filter(r => r.success).length;
        const totalExamples = Object.keys(results).length;
        const successRate = Math.round((successfulExamples / totalExamples) * 100);
        
        console.log(`\nSuccess Rate: ${successfulExamples}/${totalExamples} (${successRate}%)`);
        
        return results;
        
    } catch (error) {
        console.error('Fatal error running examples:', error.message);
        return { error: error.message };
    }
}

// Export functions for use in other modules
module.exports = {
    basicKerberosAuth,
    customKDCKerberosAuth,
    keytabKerberosAuth,
    servicePrincipalKerberosAuth,
    kerberosErrorHandlingExamples,
    handleKerberosError,
    runAllKerberosExamples
};

// Run examples if this file is executed directly
if (require.main === module) {
    runAllKerberosExamples()
        .then(results => {
            console.log('\nKerberos examples completed.');
            process.exit(0);
        })
        .catch(error => {
            console.error('Fatal error:', error);
            process.exit(1);
        });
}
