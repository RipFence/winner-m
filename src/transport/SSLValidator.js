const { WinRMSslError } = require('../utils/ErrorTypes');
const { logger } = require('../utils/Logging');
const tls = require('tls');

/**
 * SSL/TLS Certificate Validator for WinRM connections
 * Handles certificate validation, trust management, and security configuration
 */
class SSLValidator {
  constructor(options) {
    this.options = options;
    this.rejectedCerts = new Set();
    this.trustedCerts = new Map();
  }

  /**
   * Create HTTPS agent with proper SSL/TLS configuration
   */
  createHttpsAgent(options = {}) {
    const sslOptions = this.buildSSLOptions(options);
    
    return new tls.Agent({
      keepAlive: true,
      keepAliveMsecs: 60000,
      maxFreeSockets: 5,
      maxSockets: options.maxConnections || 10,
      timeout: options.connectTimeout || 30000,
      ...sslOptions
    });
  }

  /**
   * Build comprehensive SSL/TLS options
   */
  buildSSLOptions(options = {}) {
    const sslOptions = {
      rejectUnauthorized: options.rejectUnauthorized !== false,
      servername: options.servername
    };

    // Custom CA certificate
    if (options.ca) {
      if (typeof options.ca === 'string') {
        sslOptions.ca = this.loadCertificate(options.ca);
      } else {
        sslOptions.ca = options.ca;
      }
    }

    // Client certificate for mutual TLS
    if (options.cert && options.key) {
      sslOptions.cert = this.loadCertificate(options.cert);
      sslOptions.key = this.loadPrivateKey(options.key);
      sslOptions.passphrase = options.passphrase;
    }

    // Additional security options
    if (options.minimumVersion) {
      sslOptions.minVersion = options.minimumVersion;
    }

    if (options.maximumVersion) {
      sslOptions.maxVersion = options.maximumVersion;
    }

    if (options.ciphers) {
      sslOptions.ciphers = options.ciphers;
    }

    return sslOptions;
  }

  /**
   * Load certificate from file or string
   */
  loadCertificate(certData) {
    if (typeof certData === 'string') {
      try {
        // Try to detect if it's a file path or certificate data
        if (certData.includes('-----BEGIN CERTIFICATE-----')) {
          return certData;
        } else {
          // Assume it's a file path
          const fs = require('fs');
          return fs.readFileSync(certData);
        }
      } catch (error) {
        throw new WinRMSslError(
          `Failed to load certificate: ${error.message}`,
          'CERTIFICATE_LOAD_ERROR'
        );
      }
    }
    return certData;
  }

  /**
   * Load private key from file or string
   */
  loadPrivateKey(keyData) {
    if (typeof keyData === 'string') {
      try {
        // Try to detect if it's a file path or key data
        if (keyData.includes('-----BEGIN')) {
          return keyData;
        } else {
          // Assume it's a file path
          const fs = require('fs');
          return fs.readFileSync(keyData);
        }
      } catch (error) {
        throw new WinRMSslError(
          `Failed to load private key: ${error.message}`,
          'KEY_LOAD_ERROR'
        );
      }
    }
    return keyData;
  }

  /**
   * Validate server certificate during connection
   */
  validateCertificate(host, port, cert) {
    const certKey = `${host}:${port}`;
    
    logger.debug('Validating server certificate', {
      host,
      port,
      subject: cert.subject,
      issuer: cert.issuer,
      validFrom: cert.valid_from,
      validTo: cert.valid_to,
      serialNumber: cert.serialNumber
    });

    // Check if certificate is already rejected
    if (this.rejectedCerts.has(certKey)) {
      throw new WinRMSslError(
        'Certificate previously rejected',
        'CERTIFICATE_REJECTED',
        { host, port, subject: cert.subject }
      );
    }

    // Check certificate validity period
    this.validateCertificateValidity(cert);

    // Check hostname matches certificate
    this.validateHostnameMatch(host, cert);

    // Store certificate for future reference
    this.trustedCerts.set(certKey, cert);

    return true;
  }

  /**
   * Validate certificate validity period
   */
  validateCertificateValidity(cert) {
    const now = new Date();
    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);

    if (now < validFrom) {
      throw new WinRMSslError(
        'Certificate is not yet valid',
        'CERTIFICATE_NOT_YET_VALID',
        { validFrom: validFrom.toISOString() }
      );
    }

    if (now > validTo) {
      throw new WinRMSslError(
        'Certificate has expired',
        'CERTIFICATE_EXPIRED',
        { validTo: validTo.toISOString() }
      );
    }
  }

  /**
   * Validate hostname matches certificate
   */
  validateHostnameMatch(host, cert) {
    const hostnames = this.extractHostnamesFromCert(cert);
    const matched = hostnames.some(certHost => this.matchHostname(host, certHost));

    if (!matched) {
      throw new WinRMSslError(
        'Hostname does not match certificate',
        'HOSTNAME_MISMATCH',
        { host, certificateHostnames: hostnames }
      );
    }
  }

  /**
   * Extract hostnames from certificate
   */
  extractHostnamesFromCert(cert) {
    const hostnames = [];

    // Check Subject Alternative Name (SAN) extension
    if (cert.subjectaltname) {
      const sanEntries = cert.subjectaltname.split(',');
      for (const entry of sanEntries) {
        const trimmed = entry.trim();
        if (trimmed.startsWith('DNS:')) {
          hostnames.push(trimmed.substring(4).toLowerCase());
        }
      }
    }

    // Fallback to common name in subject
    if (hostnames.length === 0 && cert.subject) {
      const cnMatch = cert.subject.match(/CN=([^,]+)/);
      if (cnMatch) {
        hostnames.push(cnMatch[1].toLowerCase());
      }
    }

    return hostnames;
  }

  /**
   * Match hostname against certificate hostname pattern
   */
  matchHostname(host, certHost) {
    const hostLower = host.toLowerCase();
    const certHostLower = certHost.toLowerCase();

    // Exact match
    if (hostLower === certHostLower) {
      return true;
    }

    // Wildcard match (for domains only)
    if (certHostLower.startsWith('*.')) {
      const domainPattern = certHostLower.substring(2);
      const hostParts = hostLower.split('.');
      const patternParts = domainPattern.split('.');

      // Must have at least 2 parts (e.g., *.example.com)
      if (hostParts.length < 2 || patternParts.length < 2) {
        return false;
      }

      // Compare the last parts
      for (let i = patternParts.length; i > 0; i--) {
        const hostPart = hostParts[hostParts.length - i];
        const patternPart = patternParts[patternParts.length - i];
        
        if (hostPart !== patternPart) {
          return false;
        }
      }
      
      return true;
    }

    return false;
  }

  /**
   * Trust a certificate permanently
   */
  trustCertificate(host, port, cert) {
    const certKey = `${host}:${port}`;
    this.trustedCerts.set(certKey, cert);
    this.rejectedCerts.delete(certKey);
    
    logger.info('Certificate trusted', {
      host,
      port,
      subject: cert.subject
    });
  }

  /**
   * Reject a certificate permanently
   */
  rejectCertificate(host, port, cert) {
    const certKey = `${host}:${port}`;
    this.rejectedCerts.add(certKey);
    this.trustedCerts.delete(certKey);
    
    logger.warn('Certificate rejected', {
      host,
      port,
      subject: cert.subject
    });
  }

  /**
   * Get trusted certificates
   */
  getTrustedCertificates() {
    return Array.from(this.trustedCerts.entries()).map(([key, cert]) => ({
      key,
      subject: cert.subject,
      issuer: cert.issuer,
      validTo: cert.valid_to
    }));
  }

  /**
   * Get rejected certificates
   */
  getRejectedCertificates() {
    return Array.from(this.rejectedCerts);
  }

  /**
   * Clear trusted and rejected certificates
   */
  clearCertificates() {
    this.trustedCerts.clear();
    this.rejectedCerts.clear();
    logger.info('Certificate cache cleared');
  }

  /**
   * Get SSL configuration recommendations
   */
  getRecommendedConfig() {
    return {
      protocol: 'https',
      port: 5986,
      ssl: {
        rejectUnauthorized: true,  // Always validate certificates in production
        minVersion: 'TLSv1.2',     // Minimum TLS 1.2
        maxVersion: 'TLSv1.3',     // Maximum TLS 1.3
        ciphers: [
          'ECDHE+AESGCM',
          'ECDHE+CHACHA20',
          'DHE+AESGCM',
          'DHE+CHACHA20',
          '!aNULL',
          '!MD5'
        ].join(':'),
        // Security headers
        honorCipherOrder: true,
        sessionTimeout: 300        // 5 minutes
      }
    };
  }

  /**
   * Test SSL configuration
   */
  async testSSLConfig(host, port, config) {
    const testAgent = this.createHttpsAgent({
      ...config.ssl,
      servername: host
    });

    return new Promise((resolve) => {
      const socket = testAgent.connect({
        host,
        port
      }, () => {
        const cert = socket.getPeerCertificate();
        const isValid = socket.authorized;
        
        testAgent.destroy();
        
        resolve({
          valid: isValid,
          certificate: cert,
          error: socket.authorizationError
        });
      });

      socket.on('error', (error) => {
        testAgent.destroy();
        resolve({
          valid: false,
          error: error.message
        });
      });
    });
  }
}

module.exports = SSLValidator;