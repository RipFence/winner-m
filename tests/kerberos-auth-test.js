const KerberosAuth = require('../src/auth/KerberosAuth.js');
const { WinRMAuthenticationError } = require('../src/utils/ErrorTypes.js');

/**
 * Comprehensive test suite for Kerberos Authentication
 * Tests all aspects of the KerberosAuth class including:
 * - Class instantiation with various configurations
 * - Service principal generation and validation
 * - Kerberos authentication flow simulation
 * - Configuration validation for all Kerberos options
 * - Error handling for common Kerberos scenarios
 */
describe('KerberosAuth', () => {
  let mockHttpClient;
  let mockLogger;
  let mockKerberos;

  beforeEach(() => {
    // Create mock HTTP client
    mockHttpClient = {
      request: jest.fn(),
    };

    // Create mock logger
    mockLogger = {
      logAuthEvent: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };

    // Mock the kerberos module
    mockKerberos = {
      initializeClient: jest.fn(),
    };

    jest.mock('kerberos', () => mockKerberos);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('KerberosAuth class instantiation', () => {
    test('should create instance with valid service principal', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        domain: 'DOMAIN',
        hostname: 'test.example.com',
      });

      expect(kerberosAuth.servicePrincipal).toBe('HTTP/test.example.com@DOMAIN');
      expect(kerberosAuth.username).toBe('testuser');
      expect(kerberosAuth.password).toBe('testpass');
      expect(kerberosAuth.domain).toBe('DOMAIN');
      expect(kerberosAuth.hostname).toBe('test.example.com');
      expect(kerberosAuth.getAuthMethod()).toBe('kerberos');
    });

    test('should create instance with auto-generated service principal from hostname and domain', () => {
      const kerberosAuth = new KerberosAuth({
        hostname: 'server1',
        domain: 'CORP.EXAMPLE.COM',
        username: 'testuser',
        password: 'testpass',
      });

      expect(kerberosAuth.servicePrincipal).toBe('HTTP/server1@CORP.EXAMPLE.COM');
      expect(kerberosAuth.hostname).toBe('server1');
      expect(kerberosAuth.domain).toBe('CORP.EXAMPLE.COM');
    });

    test('should create instance with minimal required parameters', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/minimal@DOMAIN',
      });

      expect(kerberosAuth.servicePrincipal).toBe('HTTP/minimal@DOMAIN');
      expect(kerberosAuth.hostname).toBe('localhost');
      expect(kerberosAuth.domain).toBe('');
      expect(kerberosAuth.maxRetries).toBe(3);
      expect(kerberosAuth.mutualAuthentication).toBe(true);
    });

    test('should create instance with custom KDC options', () => {
      const kdcOptions = {
        kdcHost: 'kdc.corp.example.com',
        kdcPort: 88,
        timeout: 30000,
        encryptionTypes: ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96'],
      };

      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        kdcOptions,
      });

      expect(kerberosAuth.kdcOptions).toEqual(kdcOptions);
    });

    test('should create instance with custom retry count', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        maxRetries: 5,
      });

      expect(kerberosAuth.maxRetries).toBe(5);
    });

    test('should create instance with mutual authentication disabled', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        mutualAuthentication: false,
      });

      expect(kerberosAuth.mutualAuthentication).toBe(false);
    });

    test('should use default logger when none provided', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      expect(kerberosAuth.logger).toBeDefined();
      expect(typeof kerberosAuth.logger.logAuthEvent).toBe('function');
    });

    test('should use provided logger when specified', () => {
      const customLogger = {
        logAuthEvent: jest.fn(),
        debug: jest.fn(),
      };

      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        logger: customLogger,
      });

      expect(kerberosAuth.logger).toBe(customLogger);
    });

    test('should throw error when service principal is null', () => {
      expect(() => {
        new KerberosAuth({
          servicePrincipal: null,
          username: 'testuser',
        });
      }).toThrow(WinRMAuthenticationError);
      expect(() => {
        new KerberosAuth({
          servicePrincipal: null,
          username: 'testuser',
        });
      }).toThrow('Service principal is required for Kerberos authentication');
    });

    test('should throw error when service principal is empty string', () => {
      expect(() => {
        new KerberosAuth({
          servicePrincipal: '',
          username: 'testuser',
        });
      }).toThrow(WinRMAuthenticationError);
      expect(() => {
        new KerberosAuth({
          servicePrincipal: '',
          username: 'testuser',
        });
      }).toThrow('Service principal is required for Kerberos authentication');
    });

    test('should generate default service principal when none provided and domain is empty', () => {
      const kerberosAuth = new KerberosAuth({
        hostname: 'localhost',
      });

      expect(kerberosAuth.servicePrincipal).toBe('HTTP/localhost');
    });

    test('should handle complex enterprise configuration', () => {
      const enterpriseConfig = {
        servicePrincipal: 'HTTP/complex.server.example.com@ENTERPRISE.CORP',
        username: 'complexuser@ENTERPRISE.CORP',
        password: 'complexpass123!',
        domain: 'ENTERPRISE.CORP',
        hostname: 'complex.server.example.com',
        kdcOptions: {
          kdcHost: 'kdc.enterprise.corp',
          kdcPort: 88,
          timeout: 45000,
          encryptionTypes: ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96'],
        },
        maxRetries: 5,
        mutualAuthentication: false,
        logger: mockLogger,
      };

      const kerberosAuth = new KerberosAuth(enterpriseConfig);

      expect(kerberosAuth.servicePrincipal).toBe('HTTP/complex.server.example.com@ENTERPRISE.CORP');
      expect(kerberosAuth.username).toBe('complexuser@ENTERPRISE.CORP');
      expect(kerberosAuth.domain).toBe('ENTERPRISE.CORP');
      expect(kerberosAuth.hostname).toBe('complex.server.example.com');
      expect(kerberosAuth.kdcOptions.encryptionTypes).toContain('aes256-cts-hmac-sha1-96');
      expect(kerberosAuth.maxRetries).toBe(5);
      expect(kerberosAuth.mutualAuthentication).toBe(false);
    });

    test('should handle very long service principal names', () => {
      const longSPN = `HTTP/${'a'.repeat(100)}@${'b'.repeat(100)}`;

      const kerberosAuth = new KerberosAuth({
        servicePrincipal: longSPN,
      });

      expect(kerberosAuth.servicePrincipal).toBe(longSPN);
    });

    test('should handle special characters in hostname', () => {
      const kerberosAuth = new KerberosAuth({
        hostname: 'test-server-01',
        domain: 'DOMAIN.COM',
      });

      expect(kerberosAuth.servicePrincipal).toBe('HTTP/test-server-01@DOMAIN.COM');
    });

    test('should handle FQDN correctly', () => {
      const kerberosAuth = new KerberosAuth({
        hostname: 'server.domain.com',
        domain: 'PARENT.DOMAIN.COM',
      });

      expect(kerberosAuth.servicePrincipal).toBe('HTTP/server.domain.com@PARENT.DOMAIN.COM');
    });
  });

  describe('Service principal generation and validation', () => {
    test('should generate service principal with domain', () => {
      const spn = KerberosAuth.generateServicePrincipal('server1', 'DOMAIN.COM');
      expect(spn).toBe('HTTP/server1@DOMAIN.COM');
    });

    test('should generate service principal without domain', () => {
      const spn = KerberosAuth.generateServicePrincipal('server1');
      expect(spn).toBe('HTTP/server1');
    });

    test('should convert domain to uppercase', () => {
      const spn = KerberosAuth.generateServicePrincipal('server1', 'domain.com');
      expect(spn).toBe('HTTP/server1@DOMAIN.COM');
    });

    test('should throw error for empty hostname', () => {
      expect(() => {
        KerberosAuth.generateServicePrincipal('');
      }).toThrow('Hostname is required for service principal generation');
    });

    test('should throw error for null hostname', () => {
      expect(() => {
        KerberosAuth.generateServicePrincipal(null);
      }).toThrow('Hostname is required for service principal generation');
    });

    test('should handle underscore in hostname', () => {
      const spn = KerberosAuth.generateServicePrincipal('web_server_01', 'DOMAIN.COM');
      expect(spn).toBe('HTTP/web_server_01@DOMAIN.COM');
    });

    test('should handle numbers in hostname', () => {
      const spn = KerberosAuth.generateServicePrincipal('server123', 'DOMAIN.COM');
      expect(spn).toBe('HTTP/server123@DOMAIN.COM');
    });

    test('should handle dash in hostname', () => {
      const spn = KerberosAuth.generateServicePrincipal('web-server', 'DOMAIN.COM');
      expect(spn).toBe('HTTP/web-server@DOMAIN.COM');
    });

    test('getServicePrincipal should return configured SPN', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      expect(kerberosAuth.getServicePrincipal()).toBe('HTTP/test.example.com@DOMAIN');
    });

    test('getServicePrincipal should work with auto-generated SPN', () => {
      const kerberosAuth = new KerberosAuth({
        hostname: 'server1',
        domain: 'DOMAIN',
      });

      expect(kerberosAuth.getServicePrincipal()).toBe('HTTP/server1@DOMAIN');
    });
  });

  describe('Configuration validation', () => {
    test('should return valid configuration for correct setup', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        hostname: 'test.example.com',
        domain: 'DOMAIN',
      });

      const validation = kerberosAuth.validateConfig();
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    test('should return invalid configuration for missing service principal', () => {
      const kerberosAuth = new KerberosAuth({
        hostname: 'test.example.com',
        domain: 'DOMAIN',
      });

      // Manually set invalid value to test validation
      kerberosAuth.servicePrincipal = '';

      const validation = kerberosAuth.validateConfig();
      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('Service principal is required');
    });

    test('should return invalid configuration for missing hostname', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        domain: 'DOMAIN',
      });

      // Manually set invalid value to test validation
      kerberosAuth.hostname = '';

      const validation = kerberosAuth.validateConfig();
      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('Hostname is required');
    });

    test('should detect domain mismatch in service principal', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@WRONG-DOMAIN',
        hostname: 'test.example.com',
        domain: 'CORRECT-DOMAIN',
      });

      const validation = kerberosAuth.validateConfig();
      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('Service principal domain does not match provided domain');
    });

    test('should not detect mismatch when service principal has no domain part', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com',
        hostname: 'test.example.com',
        domain: 'DOMAIN',
      });

      const validation = kerberosAuth.validateConfig();
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    test('should handle domain mismatch case-insensitively', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@domain.com',
        hostname: 'test.example.com',
        domain: 'DOMAIN.COM',
      });

      const validation = kerberosAuth.validateConfig();
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    test('should validate complex enterprise configuration', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/complex.server.example.com@ENTERPRISE.CORP',
        hostname: 'complex.server.example.com',
        domain: 'ENTERPRISE.CORP',
        kdcOptions: { timeout: 30000 },
        maxRetries: 5,
        mutualAuthentication: false,
      });

      const validation = kerberosAuth.validateConfig();
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    test('should detect multiple configuration issues', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: '',
        hostname: '',
      });

      const validation = kerberosAuth.validateConfig();
      expect(validation.isValid).toBe(false);
      expect(validation.errors.length).toBeGreaterThan(1);
    });
  });

  describe('Kerberos authentication flow simulation', () => {
    test('should successfully authenticate with valid credentials', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      // Mock successful GSS client initialization
      const mockGssClient = {
        step: jest.fn((token, callback) => {
          callback(null, 'completed-token');
        }),
      };

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(null, mockGssClient);
      });

      // Mock successful server response
      mockHttpClient.request.mockResolvedValue({
        success: true,
        response: 'success',
      });

      const result = await kerberosAuth.authenticate(mockHttpClient);

      expect(result.success).toBe(true);
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'Starting Kerberos authentication',
        expect.objectContaining({
          servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        }),
      );
    });

    test('should handle multi-step Kerberos challenge-response', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      const mockGssClient = {
        step: jest.fn()
          .mockImplementationOnce((token, callback) => {
            callback(null, 'step1-response');
          })
          .mockImplementationOnce((token, callback) => {
            callback(null, 'step2-response');
          })
          .mockImplementationOnce((token, callback) => {
            callback(null, 'final-complete-response');
          }),
      };

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(null, mockGssClient);
      });

      // Mock server responses
      let step = 0;
      mockHttpClient.request.mockImplementation(() => {
        step++;
        if (step < 3) {
          return Promise.resolve({
            success: false,
            challenge: `step${step}-challenge`,
          });
        }
        return Promise.resolve({
          success: true,
          response: 'complete',
        });
      });

      const result = await kerberosAuth.authenticate(mockHttpClient);

      expect(result.success).toBe(true);
      expect(mockGssClient.step).toHaveBeenCalledTimes(3);
    });

    test('should extract Kerberos challenge from response body', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      const responseBody = `
        HTTP/1.1 401 Unauthorized
        WWW-Authenticate: Negotiate YIIE...challenge-token
        Content-Type: text/html
      `;

      const challenge = kerberosAuth.extractKerberosChallenge(responseBody);
      expect(challenge).toBe('YIIE...challenge-token');
    });

    test('should handle response body without Kerberos challenge', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      const responseBody = `
        HTTP/1.1 401 Unauthorized
        WWW-Authenticate: NTLM
        Content-Type: text/html
      `;

      const challenge = kerberosAuth.extractKerberosChallenge(responseBody);
      expect(challenge).toBeNull();
    });

    test('should parse Kerberos response correctly', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      const response = 'test-token';
      const parsed = kerberosAuth.parseKerberosResponse(response);

      expect(parsed.challenge).toBe('test-token');
      expect(parsed.isComplete).toBe(true);
    });

    test('should handle null response parsing', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      const parsed = kerberosAuth.parseKerberosResponse(null);

      expect(parsed.challenge).toBeNull();
      expect(parsed.isComplete).toBe(false);
    });

    test('should detect complete Kerberos response', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      expect(kerberosAuth.isCompleteKerberosResponse('valid-token')).toBe(true);
      expect(kerberosAuth.isCompleteKerberosResponse('')).toBe(false);
      expect(kerberosAuth.isCompleteKerberosResponse(null)).toBe(false);
      expect(kerberosAuth.isCompleteKerberosResponse('a')).toBe(true);
    });

    test('should log authentication steps', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      const mockGssClient = {
        step: jest.fn((token, callback) => {
          callback(null, 'completed-token');
        }),
      };

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(null, mockGssClient);
      });

      mockHttpClient.request.mockResolvedValue({
        success: true,
        response: 'success',
      });

      await kerberosAuth.authenticate(mockHttpClient);

      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'Starting Kerberos authentication',
        expect.objectContaining({
          servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        }),
      );

      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'Kerberos authentication completed successfully',
      );
    });

    test('should track authentication duration', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      const mockGssClient = {
        step: jest.fn((token, callback) => {
          callback(null, 'completed-token');
        }),
      };

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(null, mockGssClient);
      });

      mockHttpClient.request.mockResolvedValue({
        success: true,
        response: 'success',
      });

      const startTime = Date.now();
      const result = await kerberosAuth.authenticate(mockHttpClient);
      const endTime = Date.now();

      expect(result.duration).toBeGreaterThanOrEqual(0);
      expect(result.duration).toBeLessThanOrEqual(endTime - startTime + 1000);
    });
  });

  describe('Configuration validation for all Kerberos options', () => {
    test('should validate all KDC options', () => {
      const kdcOptions = {
        kdcHost: 'kdc.example.com',
        kdcPort: 88,
        timeout: 30000,
        encryptionTypes: ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96'],
      };

      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        kdcOptions,
      });

      expect(kerberosAuth.kdcOptions).toEqual(kdcOptions);
    });

    test('should validate empty KDC options', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        kdcOptions: {},
      });

      expect(kerberosAuth.kdcOptions).toEqual({});
    });

    test('should handle undefined KDC options', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      expect(kerberosAuth.kdcOptions).toEqual({});
    });

    test('should validate maxRetries configuration', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        maxRetries: 10,
      });

      expect(kerberosAuth.maxRetries).toBe(10);
    });

    test('should validate mutualAuthentication configuration', () => {
      const kerberosAuth1 = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        mutualAuthentication: true,
      });

      const kerberosAuth2 = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        mutualAuthentication: false,
      });

      expect(kerberosAuth1.mutualAuthentication).toBe(true);
      expect(kerberosAuth2.mutualAuthentication).toBe(false);
    });

    test('should use default mutualAuthentication when not specified', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      expect(kerberosAuth.mutualAuthentication).toBe(true);
    });

    test('should validate hostname extraction from service principal', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      expect(kerberosAuth.hostname).toBe('test.example.com');
    });

    test('should validate domain extraction from service principal', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      expect(kerberosAuth.domain).toBe('DOMAIN');
    });

    test('should handle service principal without domain', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com',
      });

      expect(kerberosAuth.hostname).toBe('test.example.com');
      expect(kerberosAuth.domain).toBe('');
    });

    test('should validate all credential types', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'user@DOMAIN',
        password: 'password123!',
        domain: 'DOMAIN',
      });

      expect(kerberosAuth.username).toBe('user@DOMAIN');
      expect(kerberosAuth.password).toBe('password123!');
      expect(kerberosAuth.domain).toBe('DOMAIN');
    });

    test('should handle special characters in credentials', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'user@domain.com',
        password: 'p@$$w0rd!123',
      });

      expect(kerberosAuth.username).toBe('user@domain.com');
      expect(kerberosAuth.password).toBe('p@$$w0rd!123');
    });

    test('should handle Unicode characters in credentials', () => {
      const unicodeUsername = '用户';
      const unicodePassword = '密码123';

      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: unicodeUsername,
        password: unicodePassword,
      });

      expect(kerberosAuth.username).toBe(unicodeUsername);
      expect(kerberosAuth.password).toBe(unicodePassword);
    });

    test('should handle very long hostname and domain', () => {
      const longHostname = 'a'.repeat(100);
      const longDomain = 'b'.repeat(100);

      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        hostname: longHostname,
        domain: longDomain,
      });

      expect(kerberosAuth.hostname).toBe(longHostname);
      expect(kerberosAuth.domain).toBe(longDomain);
    });
  });

  describe('Error handling for common Kerberos scenarios', () => {
    test('should handle GSS client initialization failure', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      // Mock GSS client initialization failure
      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(new Error('GSS client initialization failed'), null);
      });

      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'Kerberos authentication failed',
        expect.objectContaining({
          error: expect.stringContaining('Failed to initialize Kerberos client'),
        }),
      );
    });

    test('should handle service principal not found error', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/nonexistent.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      const mockGssClient = {
        step: jest.fn((token, callback) => {
          callback(new Error('Principal not found in Kerberos database'), null);
        }),
      };

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(null, mockGssClient);
      });

      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow(
        'Service principal not found: HTTP/nonexistent.example.com@DOMAIN',
      );
    });

    test('should handle missing Kerberos credentials error', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      const mockGssClient = {
        step: jest.fn((token, callback) => {
          callback(new Error('No credentials cache found'), null);
        }),
      };

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(null, mockGssClient);
      });

      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow(
        'No valid Kerberos credentials found',
      );
    });

    test('should handle authentication timeout', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      const mockGssClient = {
        step: jest.fn((token, callback) => {
          // Simulate continuing challenge that never completes
          callback(null, 'partial-response');
        }),
      };

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(null, mockGssClient);
      });

      // Mock server to always return partial response
      mockHttpClient.request.mockResolvedValue({
        success: false,
        challenge: 'continuing-challenge',
      });

      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow(
        'Authentication did not complete within 5 steps',
      );
    });

    test('should handle HTTP client errors', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      const mockGssClient = {
        step: jest.fn((token, callback) => {
          callback(null, 'test-response');
        }),
      };

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(null, mockGssClient);
      });

      // Mock HTTP client failure
      mockHttpClient.request.mockRejectedValue(new Error('Connection failed'));

      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'Kerberos authentication failed',
        expect.objectContaining({
          error: expect.stringContaining('Connection failed'),
        }),
      );
    });

    test('should handle token processing errors', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      const mockGssClient = {
        step: jest.fn((token, callback) => {
          callback(new Error('Token processing failed'), null);
        }),
      };

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(null, mockGssClient);
      });

      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
    });

    test('should wrap non-WinRMAuthenticationError errors', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      const mockGssClient = {
        step: jest.fn((token, callback) => {
          callback(new Error('Generic error'), null);
        }),
      };

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(null, mockGssClient);
      });

      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow('Kerberos authentication failed: Generic error');
    });

    test('should preserve original WinRMAuthenticationError', async () => {
      const originalError = new WinRMAuthenticationError('Original error', 'kerberos', { test: true });

      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(originalError, null);
      });

      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow('Original error');
    });

    test('should handle challenge extraction errors gracefully', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      // Should not throw, just return null
      const challenge = kerberosAuth.extractKerberosChallenge(null);
      expect(challenge).toBeNull();

      const challenge2 = kerberosAuth.extractKerberosChallenge({ invalid: 'data' });
      expect(challenge2).toBeNull();
    });

    test('should handle parse response errors', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      // Should handle various input types gracefully
      expect(() => {
        kerberosAuth.parseKerberosResponse('');
      }).not.toThrow();

      expect(() => {
        kerberosAuth.parseKerberosResponse(0);
      }).not.toThrow();

      expect(() => {
        kerberosAuth.parseKerberosResponse(false);
      }).not.toThrow();
    });

    test('should handle initialization exceptions', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      // Mock synchronous error in initialization
      mockKerberos.initializeClient.mockImplementation(() => {
        throw new Error('Initialization exception');
      });

      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
    });

    test('should handle step exceptions', async () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger,
      });

      const mockGssClient = {
        step: jest.fn((token, callback) => {
          throw new Error('Step exception');
        }),
      };

      mockKerberos.initializeClient.mockImplementation((spn, options, callback) => {
        callback(null, mockGssClient);
      });

      await expect(kerberosAuth.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
    });
  });

  describe('Edge cases and boundary conditions', () => {
    test('should handle empty string values', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: '',
        hostname: '',
        domain: '',
      });

      expect(kerberosAuth.servicePrincipal).toBe('HTTP/localhost');
      expect(kerberosAuth.hostname).toBe('localhost');
      expect(kerberosAuth.domain).toBe('');
    });

    test('should handle zero retry count', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        maxRetries: 0,
      });

      expect(kerberosAuth.maxRetries).toBe(0);
    });

    test('should handle negative retry count', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        maxRetries: -1,
      });

      expect(kerberosAuth.maxRetries).toBe(-1);
    });

    test('should handle very high retry count', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        maxRetries: 1000,
      });

      expect(kerberosAuth.maxRetries).toBe(1000);
    });

    test('should handle null username and password', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: null,
        password: null,
      });

      expect(kerberosAuth.username).toBeNull();
      expect(kerberosAuth.password).toBeNull();
    });

    test('should handle undefined username and password', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        username: undefined,
        password: undefined,
      });

      expect(kerberosAuth.username).toBeUndefined();
      expect(kerberosAuth.password).toBeUndefined();
    });

    test('should handle non-string service principal', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 12345,
      });

      expect(kerberosAuth.servicePrincipal).toBe(12345);
    });

    test('should handle complex KDC options', () => {
      const complexKdcOptions = {
        kdcHost: 'kdc.example.com',
        kdcPort: 88,
        timeout: 30000,
        encryptionTypes: ['aes256-cts-hmac-sha1-96'],
        preferredEncTypes: [16, 18],
        allowWeakCrypto: false,
        canonicalize: true,
      };

      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        kdcOptions: complexKdcOptions,
      });

      expect(kerberosAuth.kdcOptions).toEqual(complexKdcOptions);
    });

    test('should handle deeply nested KDC options', () => {
      const nestedKdcOptions = {
        kdcHost: 'kdc.example.com',
        timeout: 30000,
        custom: {
          deeply: {
            nested: {
              value: 'test',
            },
          },
        },
      };

      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        kdcOptions: nestedKdcOptions,
      });

      expect(kerberosAuth.kdcOptions.custom.deeply.nested.value).toBe('test');
    });

    test('should preserve exact service principal format', () => {
      const customSPN = 'HTTP/custom-format@DOMAIN';

      const kerberosAuth = new KerberosAuth({
        servicePrincipal: customSPN,
      });

      expect(kerberosAuth.servicePrincipal).toBe(customSPN);
    });

    test('should handle numeric domain', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@12345',
      });

      expect(kerberosAuth.domain).toBe('12345');
    });
  });

  describe('Utility methods and getters', () => {
    test('should return correct auth method', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      expect(kerberosAuth.getAuthMethod()).toBe('kerberos');
    });

    test('should return correct service principal via getter', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
      });

      expect(kerberosAuth.getServicePrincipal()).toBe('HTTP/test.example.com@DOMAIN');
    });

    test('should validate configuration with no errors for valid config', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: 'HTTP/test.example.com@DOMAIN',
        hostname: 'test.example.com',
        domain: 'DOMAIN',
      });

      const validation = kerberosAuth.validateConfig();
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    test('should validate configuration with errors for invalid config', () => {
      const kerberosAuth = new KerberosAuth({
        servicePrincipal: '',
        hostname: '',
      });

      const validation = kerberosAuth.validateConfig();
      expect(validation.isValid).toBe(false);
      expect(validation.errors.length).toBeGreaterThan(0);
    });
  });
});
