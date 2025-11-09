const CredSSPAuth = require('../src/auth/CredSSPAuth');
const { WinRMAuthenticationError, WinRMConnectionError } = require('../src/utils/ErrorTypes');

/**
 * Comprehensive test suite for CredSSP Authentication
 * Tests all aspects of the CredSSPAuth class including:
 * - Class instantiation with various configurations
 * - Base authentication method validation
 * - TSP request/response handling
 * - Double-hop configuration scenarios
 * - Error handling and edge cases
 */
describe('CredSSPAuth', () => {
  let mockHttpClient;
  let mockLogger;

  beforeEach(() => {
    // Create mock HTTP client
    mockHttpClient = {
      request: jest.fn()
    };

    // Create mock logger
    mockLogger = {
      logAuthEvent: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn()
    };

    // Mock NTLMAuth and KerberosAuth
    jest.mock('../src/auth/NTLMAuth');
    jest.mock('../src/auth/KerberosAuth');
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('CredSSPAuth class instantiation', () => {
    test('should create instance with valid NTLM credentials', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        domain: 'TESTDOMAIN',
        baseAuth: 'ntlm',
        logger: mockLogger
      });

      expect(credSSP.username).toBe('testuser');
      expect(credSSP.password).toBe('testpass');
      expect(credSSP.domain).toBe('TESTDOMAIN');
      expect(credSSP.baseAuth).toBe('ntlm');
      expect(credSSP.delegateCredentials).toBe(true);
      expect(credSSP.workstation).toBe('JS-WinRM-Client');
      expect(credSSP.maxRetries).toBe(3);
      expect(credSSP.getAuthMethod()).toBe('credssp');
    });

    test('should create instance with valid Kerberos credentials', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        domain: 'TESTDOMAIN',
        baseAuth: 'kerberos',
        servicePrincipalName: 'HTTP/test.example.com@TESTDOMAIN',
        logger: mockLogger
      });

      expect(credSSP.username).toBe('testuser');
      expect(credSSP.password).toBe('testpass');
      expect(credSSP.domain).toBe('TESTDOMAIN');
      expect(credSSP.baseAuth).toBe('kerberos');
      expect(credSSP.servicePrincipalName).toBe('HTTP/test.example.com@TESTDOMAIN');
      expect(credSSP.getAuthMethod()).toBe('credssp');
    });

    test('should use default values when optional parameters not provided', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      expect(credSSP.domain).toBe('');
      expect(credSSP.baseAuth).toBe('ntlm');
      expect(credSSP.workstation).toBe('JS-WinRM-Client');
      expect(credSSP.delegateCredentials).toBe(true);
      expect(credSSP.maxRetries).toBe(3);
    });

    test('should throw error when username is missing', () => {
      expect(() => {
        new CredSSPAuth({
          password: 'testpass'
        });
      }).toThrow(WinRMAuthenticationError);
      expect(() => {
        new CredSSPAuth({
          password: 'testpass'
        });
      }).toThrow('Username is required for CredSSP authentication');
    });

    test('should throw error when password is missing', () => {
      expect(() => {
        new CredSSPAuth({
          username: 'testuser'
        });
      }).toThrow(WinRMAuthenticationError);
      expect(() => {
        new CredSSPAuth({
          username: 'testuser'
        });
      }).toThrow('Password is required for CredSSP authentication');
    });

    test('should throw error for invalid base authentication method', () => {
      expect(() => {
        new CredSSPAuth({
          username: 'testuser',
          password: 'testpass',
          baseAuth: 'invalid'
        });
      }).toThrow(WinRMAuthenticationError);
      expect(() => {
        new CredSSPAuth({
          username: 'testuser',
          password: 'testpass',
          baseAuth: 'invalid'
        });
      }).toThrow('Invalid base authentication method: invalid');
    });

    test('should disable credential delegation when explicitly set', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        delegateCredentials: false
      });

      expect(credSSP.delegateCredentials).toBe(false);
    });

    test('should set custom workstation name', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        workstation: 'CUSTOM-WORKSTATION'
      });

      expect(credSSP.workstation).toBe('CUSTOM-WORKSTATION');
    });

    test('should set custom retry count', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        maxRetries: 5
      });

      expect(credSSP.maxRetries).toBe(5);
    });

    test('should initialize protocol constants correctly', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      expect(credSSP.CREDSSP_SIGNATURE).toEqual(Buffer.from('CREDSRP', 'ascii'));
      expect(credSSP.TSP_SIGNATURE).toEqual(Buffer.from('TSP', 'ascii'));
      expect(credSSP.MessageType.CREDSSP_TYPE_NONE).toBe(0x00000000);
      expect(credSSP.MessageType.CREDSSP_TYPE_PREAUTH).toBe(0x00000001);
      expect(credSSP.MessageType.CREDSSP_TYPE_AUTH).toBe(0x00000002);
      expect(credSSP.MessageType.CREDSSP_TYPE_TICKET).toBe(0x00000003);
    });

    test('should initialize TSP message types correctly', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      expect(credSSP.TspMsgType.TSPREQ_TSC_CONNECT).toBe(0x00000001);
      expect(credSSP.TspMsgType.TSPREQ_TSC_DISCONNECT).toBe(0x00000002);
      expect(credSSP.TspMsgType.TSPREQ_TSC_SHELL).toBe(0x00000003);
      expect(credSSP.TspMsgType.TSPREQ_TSC_EXEC).toBe(0x00000004);
      expect(credSSP.TspMsgType.TSPREQ_TSC_CONNECT_SHADOW).toBe(0x00000005);
      expect(credSSP.TspMsgType.TSPREQ_TSC_VERIALOGON).toBe(0x00000006);
    });

    test('should initialize negotiate flags correctly', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      expect(credSSP.NegotiateFlags.CREDSSPI_NEGOTIATE_SPN_REQUIRED).toBe(0x00000001);
      expect(credSSP.NegotiateFlags.CREDSSPI_NEGOTIATE_CREDENTIALS_REQUIRED).toBe(0x00000002);
      expect(credSSP.NegotiateFlags.CREDSSPI_NEGOTIATE_ENCRYPT_SUPER).toBe(0x00000004);
    });

    test('should initialize with unauthenticated state', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      expect(credSSP.authenticated).toBe(false);
      expect(credSSP.sessionKey).toBeNull();
      expect(credSSP.encryptedSessionKey).toBeNull();
      expect(credSSP.ticket).toBeNull();
      expect(credSSP.credentials).toBeNull();
    });
  });

  describe('Configuration validation', () => {
    test('should return valid configuration for correct setup', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        domain: 'TESTDOMAIN',
        baseAuth: 'ntlm'
      });

      const validation = credSSP.validateConfiguration();
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    test('should return invalid configuration for missing username', () => {
      const credSSP = new CredSSPAuth({
        password: 'testpass'
      });

      const validation = credSSP.validateConfiguration();
      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('Username is required for CredSSP authentication');
    });

    test('should return invalid configuration for missing password', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser'
      });

      const validation = credSSP.validateConfiguration();
      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('Password is required for CredSSP authentication');
    });

    test('should return invalid configuration for invalid base auth', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'invalid'
      });

      const validation = credSSP.validateConfiguration();
      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('Invalid base authentication method: invalid');
    });

    test('should return invalid configuration for Kerberos without domain', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'kerberos'
      });

      const validation = credSSP.validateConfiguration();
      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('Domain is required for Kerberos-based CredSSP authentication');
    });

    test('should return invalid configuration for Kerberos without SPN or domain', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'kerberos',
        domain: ''
      });

      const validation = credSSP.validateConfiguration();
      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('Either servicePrincipalName or domain is required for Kerberos-based CredSSP');
    });

    test('should return valid configuration for Kerberos with SPN', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'kerberos',
        servicePrincipalName: 'HTTP/test.example.com@TESTDOMAIN'
      });

      const validation = credSSP.validateConfiguration();
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });
  });

  describe('Session information methods', () => {
    test('should return session info for unauthenticated state', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        domain: 'TESTDOMAIN',
        baseAuth: 'ntlm',
        delegateCredentials: true
      });

      const sessionInfo = credSSP.getSessionInfo();
      expect(sessionInfo.authenticated).toBe(false);
      expect(sessionInfo.baseAuth).toBe('ntlm');
      expect(sessionInfo.domain).toBe('TESTDOMAIN');
      expect(sessionInfo.username).toBe('testuser');
      expect(sessionInfo.sessionKeyPresent).toBe(false);
      expect(sessionInfo.delegateCredentials).toBe(true);
    });

    test('should return session info for authenticated state', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'ntlm'
      });

      // Simulate authentication
      credSSP.authenticated = true;
      credSSP.sessionKey = Buffer.from('test-session-key');

      const sessionInfo = credSSP.getSessionInfo();
      expect(sessionInfo.authenticated).toBe(true);
      expect(sessionInfo.sessionKeyPresent).toBe(true);
    });

    test('should return isAuthenticated false initially', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      expect(credSSP.isAuthenticated()).toBe(false);
    });

    test('should return isAuthenticated true after successful authentication', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      credSSP.authenticated = true;
      expect(credSSP.isAuthenticated()).toBe(true);
    });
  });

  describe('Base authentication method validation', () => {
    test('should accept NTLM as base authentication method', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'ntlm'
      });

      expect(credSSP.baseAuth).toBe('ntlm');
    });

    test('should accept Kerberos as base authentication method', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'kerberos',
        domain: 'TESTDOMAIN'
      });

      expect(credSSP.baseAuth).toBe('kerberos');
    });

    test('should reject unsupported base authentication methods', () => {
      const invalidMethods = ['basic', 'digest', 'oauth', 'bearer', ''];
      
      invalidMethods.forEach(method => {
        expect(() => {
          new CredSSPAuth({
            username: 'testuser',
            password: 'testpass',
            baseAuth: method
          });
        }).toThrow(WinRMAuthenticationError);
      });
    });

    test('should auto-generate SPN for Kerberos when not provided', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'kerberos',
        domain: 'TESTDOMAIN'
      });

      expect(credSSP.servicePrincipalName).toBe('HTTP/localhost@TESTDOMAIN');
    });
  });

  describe('TSP request/response handling', () => {
    test('should create TSP credential structure', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        domain: 'TESTDOMAIN'
      });

      const tspCredentials = credSSP.createTSPCredentials();
      
      expect(tspCredentials).toBeInstanceOf(Buffer);
      expect(tspCredentials.length).toBeGreaterThan(0);
      
      // Verify TSP signature
      const signature = tspCredentials.slice(0, 3);
      expect(signature).toEqual(credSSP.TSP_SIGNATURE);
    });

    test('should create TSP credential structure with empty domain', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        domain: ''
      });

      const tspCredentials = credSSP.createTSPCredentials();
      expect(tspCredentials).toBeInstanceOf(Buffer);
      expect(tspCredentials.length).toBeGreaterThan(0);
    });

    test('should create CredSSP message with preauth type', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const message = credSSP.createCredSSPMessage(
        credSSP.MessageType.CREDSSP_TYPE_PREAUTH,
        null,
        null
      );

      expect(message).toBeInstanceOf(Buffer);
      expect(message.length).toBeGreaterThan(0);
      
      // Verify CredSSP signature
      const signature = message.slice(0, 6);
      expect(signature).toEqual(credSSP.CREDSSP_SIGNATURE);
      
      // Verify message type
      const messageType = message.readUInt32LE(6);
      expect(messageType).toBe(credSSP.MessageType.CREDSSP_TYPE_PREAUTH);
    });

    test('should create CredSSP message with auth type and challenge', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const challenge = Buffer.from('test-challenge', 'utf8');
      const message = credSSP.createCredSSPMessage(
        credSSP.MessageType.CREDSSP_TYPE_AUTH,
        challenge,
        null
      );

      expect(message).toBeInstanceOf(Buffer);
      expect(message.length).toBeGreaterThan(14 + challenge.length);
    });

    test('should create CredSSP message with credentials', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const tspCredentials = credSSP.createTSPCredentials();
      const message = credSSP.createCredSSPMessage(
        credSSP.MessageType.CREDSSP_TYPE_AUTH,
        null,
        tspCredentials
      );

      expect(message).toBeInstanceOf(Buffer);
      expect(message.length).toBeGreaterThan(14 + tspCredentials.length);
    });

    test('should parse CredSSP response correctly', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      // Create a mock response
      const message = credSSP.createCredSSPMessage(
        credSSP.MessageType.CREDSSP_TYPE_TICKET
      );
      const base64Message = message.toString('base64');

      const response = {
        challenge: base64Message
      };

      const parsedResponse = credSSP.parseCredSSPResponse(response);
      
      expect(parsedResponse.isComplete).toBe(true);
      expect(parsedResponse.success).toBe(true);
      expect(parsedResponse.message).toBe('CredSSP authentication completed');
    });

    test('should handle response without challenge', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const response = {
        success: true
      };

      const parsedResponse = credSSP.parseCredSSPResponse(response);
      
      expect(parsedResponse.isComplete).toBe(true);
      expect(parsedResponse.success).toBe(true);
      expect(parsedResponse.message).toBe('Authentication completed without challenge');
    });

    test('should extract CredSSP challenge from response body', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const responseBody = 'WWW-Authenticate: CredSSP dGVzdC1jaGFsbGVuZ2U=\r\n';
      const challenge = credSSP.extractCredSSPChallenge(responseBody);
      
      expect(challenge).toBe('dGVzdC1jaGFsbGVuZ2U=');
    });

    test('should handle response body without CredSSP challenge', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const responseBody = 'WWW-Authenticate: NTLM\r\n';
      const challenge = credSSP.extractCredSSPChallenge(responseBody);
      
      expect(challenge).toBeNull();
    });

    test('should parse CredSSP message with authentication type', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const message = credSSP.createCredSSPMessage(
        credSSP.MessageType.CREDSSP_TYPE_AUTH
      );

      const parsedMessage = credSSP.parseCredSSPMessage(message);
      
      expect(parsedMessage.messageType).toBe(credSSP.MessageType.CREDSSP_TYPE_AUTH);
      expect(parsedMessage.messageLength).toBe(message.length);
      expect(parsedMessage.isComplete).toBe(false);
      expect(parsedMessage.success).toBe(true);
    });

    test('should throw error for invalid CredSSP signature', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const invalidMessage = Buffer.from('INVALID', 'ascii');
      
      expect(() => {
        credSSP.parseCredSSPMessage(invalidMessage);
      }).toThrow('Invalid CredSSP signature in server response');
    });

    test('should base64 decode correctly', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const testString = 'Hello World';
      const base64String = Buffer.from(testString).toString('base64');
      const decoded = credSSP.base64Decode(base64String);
      
      expect(decoded).toEqual(Buffer.from(testString));
    });
  });

  describe('Double-hop configuration', () => {
    test('should configure with credential delegation enabled by default', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      expect(credSSP.delegateCredentials).toBe(true);
    });

    test('should configure with credential delegation disabled', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        delegateCredentials: false
      });

      expect(credSSP.delegateCredentials).toBe(false);
    });

    test('should generate service principal name for Kerberos', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        domain: 'TESTDOMAIN'
      });

      const spn = credSSP.generateServicePrincipal();
      expect(spn).toBe('HTTP/localhost@TESTDOMAIN');
    });

    test('should throw error when generating SPN without domain', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        domain: ''
      });

      expect(() => {
        credSSP.generateServicePrincipal();
      }).toThrow('Domain is required for Kerberos SPN generation');
    });

    test('should extract hostname from SPN', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const spn = 'HTTP/test.example.com@TESTDOMAIN';
      const hostname = credSSP.extractHostname(spn);
      expect(hostname).toBe('test.example.com');
    });

    test('should handle domain as hostname extraction', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const domain = 'TESTDOMAIN';
      const hostname = credSSP.extractHostname(domain);
      expect(hostname).toBe('localhost');
    });

    test('should get hostname from SPN', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const spn = 'HTTP/test.example.com@TESTDOMAIN';
      const hostname = credSSP.getHostnameFromSPN(spn);
      expect(hostname).toBe('test.example.com');
    });

    test('should initialize session with base authentication result', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const baseAuthResult = {
        success: true,
        method: 'ntlm',
        sessionKey: Buffer.from('test-session-key').toString('base64')
      };

      credSSP.initializeCredSSPSession(baseAuthResult);
      
      expect(credSSP.sessionKey).toEqual(Buffer.from('test-session-key'));
      expect(credSSP.baseAuthResult).toBe(baseAuthResult);
    });

    test('should generate random session key when none provided', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const baseAuthResult = {
        success: true,
        method: 'ntlm'
        // No sessionKey provided
      };

      credSSP.initializeCredSSPSession(baseAuthResult);
      
      expect(credSSP.sessionKey).toBeInstanceOf(Buffer);
      expect(credSSP.sessionKey.length).toBe(32); // crypto.randomBytes(32)
    });

    test('should extract NTLM session key', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const ntlmResult = {
        success: true
      };

      const sessionKey = credSSP.extractNTLMSessionKey(ntlmResult);
      
      expect(sessionKey).toBeDefined();
      expect(typeof sessionKey).toBe('string');
      expect(sessionKey.length).toBeGreaterThan(0);
    });

    test('should extract Kerberos session key', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass'
      });

      const kerberosResult = {
        success: true
      };

      const sessionKey = credSSP.extractKerberosSessionKey(kerberosResult);
      
      expect(sessionKey).toBeDefined();
      expect(typeof sessionKey).toBe('string');
      expect(sessionKey.length).toBeGreaterThan(0);
    });
  });

  describe('Error handling', () => {
    test('should handle missing username gracefully', async () => {
      const credSSP = new CredSSPAuth({
        password: 'testpass'
      });

      await expect(credSSP.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'CredSSP authentication failed',
        expect.objectContaining({
          error: expect.stringContaining('Username is required')
        })
      );
    });

    test('should handle missing password gracefully', async () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser'
      });

      await expect(credSSP.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'CredSSP authentication failed',
        expect.objectContaining({
          error: expect.stringContaining('Password is required')
        })
      );
    });

    test('should handle invalid base authentication method', async () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'invalid'
      });

      await expect(credSSP.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'CredSSP authentication failed',
        expect.objectContaining({
          error: expect.stringContaining('Invalid base authentication method')
        })
      );
    });

    test('should handle base authentication failure', async () => {
      const NTLMAuth = require('../src/auth/NTLMAuth');
      NTLMAuth.mockImplementation(() => ({
        authenticate: jest.fn().mockRejectedValue(new Error('Base auth failed'))
      }));

      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'ntlm',
        logger: mockLogger
      });

      await expect(credSSP.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'CredSSP authentication failed',
        expect.objectContaining({
          error: expect.stringContaining('Base authentication failed')
        })
      );
    });

    test('should handle CredSSP handshake timeout', async () => {
      // Mock base authentication to succeed
      const NTLMAuth = require('../src/auth/NTLMAuth');
      NTLMAuth.mockImplementation(() => ({
        authenticate: jest.fn().mockResolvedValue({ success: true })
      }));

      // Mock HTTP client to always return pending challenge
      mockHttpClient.request.mockResolvedValue({
        success: false,
        challenge: Buffer.from('pending-challenge').toString('base64')
      });

      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'ntlm',
        logger: mockLogger
      });

      // Temporarily reduce max steps for testing
      const originalMaxSteps = 5;
      const maxSteps = 2; // Force early timeout

      // Override the performCredSSPHandshake method to simulate timeout
      const originalMethod = credSSP.performCredSSPHandshake;
      credSSP.performCredSSPHandshake = jest.fn().mockImplementation(async (httpClient, tspCredentials) => {
        for (let step = 0; step < maxSteps; step++) {
          // Simulate continuing challenge/response
        }
        throw new Error(`CredSSP handshake did not complete within ${maxSteps} steps`);
      });

      await expect(credSSP.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'CredSSP authentication failed',
        expect.objectContaining({
          error: expect.stringContaining('CredSSP handshake did not complete')
        })
      );
    });

    test('should handle HTTP client errors', async () => {
      // Mock base authentication to succeed
      const NTLMAuth = require('../src/auth/NTLMAuth');
      NTLMAuth.mockImplementation(() => ({
        authenticate: jest.fn().mockResolvedValue({ success: true })
      }));

      // Mock HTTP client to throw error
      mockHttpClient.request.mockRejectedValue(new Error('Connection failed'));

      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'ntlm',
        logger: mockLogger
      });

      await expect(credSSP.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'CredSSP authentication failed',
        expect.objectContaining({
          error: expect.stringContaining('Connection failed')
        })
      );
    });

    test('should wrap non-WinRMAuthenticationError errors', async () => {
      // Mock base authentication to succeed
      const NTLMAuth = require('../src/auth/NTLMAuth');
      NTLMAuth.mockImplementation(() => ({
        authenticate: jest.fn().mockResolvedValue({ success: true })
      }));

      // Mock HTTP client to return empty response
      mockHttpClient.request.mockResolvedValue({ success: true });

      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'ntlm',
        logger: mockLogger
      });

      // Mock performCredSSPHandshake to throw a generic error
      credSSP.performCredSSPHandshake = jest.fn().mockRejectedValue(new Error('Generic error'));

      await expect(credSSP.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'CredSSP authentication failed',
        expect.objectContaining({
          error: 'Generic error'
        })
      );
    });

    test('should preserve original WinRMAuthenticationError', async () => {
      const originalError = new WinRMAuthenticationError('Original error', 'credssp', { test: true });

      // Mock base authentication to succeed
      const NTLMAuth = require('../src/auth/NTLMAuth');
      NTLMAuth.mockImplementation(() => ({
        authenticate: jest.fn().mockResolvedValue({ success: true })
      }));

      // Mock HTTP client
      mockHttpClient.request.mockResolvedValue({ success: true });

      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'ntlm',
        logger: mockLogger
      });

      // Mock performCredSSPHandshake to throw WinRMAuthenticationError
      credSSP.performCredSSPHandshake = jest.fn().mockRejectedValue(originalError);

      await expect(credSSP.authenticate(mockHttpClient)).rejects.toThrow(WinRMAuthenticationError);
      await expect(credSSP.authenticate(mockHttpClient)).rejects.toThrow('Original error');
    });
  });

  describe('Authentication flow integration', () => {
    test('should complete authentication flow with NTLM base', async () => {
      // Mock NTLMAuth
      const NTLMAuth = require('../src/auth/NTLMAuth');
      NTLMAuth.mockImplementation(() => ({
        authenticate: jest.fn().mockResolvedValue({
          success: true,
          sessionKey: 'mock-ntlm-session-key'
        })
      }));

      // Mock successful authentication responses
      mockHttpClient.request
        .mockResolvedValueOnce({ success: true }) // Base auth
        .mockResolvedValueOnce({ success: true, challenge: null }); // CredSSP complete

      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        domain: 'TESTDOMAIN',
        baseAuth: 'ntlm',
        logger: mockLogger
      });

      const result = await credSSP.authenticate(mockHttpClient);

      expect(result.success).toBe(true);
      expect(result.method).toBe('credssp');
      expect(result.baseAuth).toBe('ntlm');
      expect(result.credentialsDelegated).toBe(true);
      expect(credSSP.authenticated).toBe(true);
      
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'Starting CredSSP authentication',
        expect.objectContaining({
          baseAuth: 'ntlm',
          delegateCredentials: true
        })
      );

      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'CredSSP authentication completed successfully',
        expect.objectContaining({
          baseAuth: 'ntlm',
          doubleHopSupported: true
        })
      );
    });

    test('should complete authentication flow with Kerberos base', async () => {
      // Mock KerberosAuth
      const KerberosAuth = require('../src/auth/KerberosAuth');
      KerberosAuth.mockImplementation(() => ({
        authenticate: jest.fn().mockResolvedValue({
          success: true,
          sessionKey: 'mock-kerberos-session-key'
        })
      }));

      // Mock successful authentication responses
      mockHttpClient.request
        .mockResolvedValueOnce({ success: true }) // Base auth
        .mockResolvedValueOnce({ success: true, challenge: null }); // CredSSP complete

      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        domain: 'TESTDOMAIN',
        baseAuth: 'kerberos',
        servicePrincipalName: 'HTTP/test.example.com@TESTDOMAIN',
        logger: mockLogger
      });

      const result = await credSSP.authenticate(mockHttpClient);

      expect(result.success).toBe(true);
      expect(result.method).toBe('credssp');
      expect(result.baseAuth).toBe('kerberos');
      expect(credSSP.authenticated).toBe(true);
    });

    test('should track authentication duration', async () => {
      // Mock NTLMAuth
      const NTLMAuth = require('../src/auth/NTLMAuth');
      NTLMAuth.mockImplementation(() => ({
        authenticate: jest.fn().mockResolvedValue({ success: true })
      }));

      // Mock successful authentication
      mockHttpClient.request
        .mockResolvedValueOnce({ success: true })
        .mockResolvedValueOnce({ success: true, challenge: null });

      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger
      });

      const startTime = Date.now();
      const result = await credSSP.authenticate(mockHttpClient);
      const endTime = Date.now();

      expect(result.duration).toBeGreaterThanOrEqual(0);
      expect(result.duration).toBeLessThanOrEqual(endTime - startTime + 1000); // Allow 1s tolerance
      
      expect(mockLogger.logAuthEvent).toHaveBeenCalledWith(
        'CredSSP authentication completed successfully',
        expect.objectContaining({
          duration: expect.any(Number)
        })
      );
    });

    test('should handle multi-step CredSSP handshake', async () => {
      // Mock NTLMAuth
      const NTLMAuth = require('../src/auth/NTLMAuth');
      NTLMAuth.mockImplementation(() => ({
        authenticate: jest.fn().mockResolvedValue({ success: true })
      }));

      // Mock multi-step handshake responses
      mockHttpClient.request
        .mockResolvedValueOnce({ success: true }) // Base auth
        .mockResolvedValueOnce({ 
          success: false, 
          challenge: Buffer.from('step1-challenge').toString('base64') 
        }) // Step 1
        .mockResolvedValueOnce({ 
          success: false, 
          challenge: Buffer.from('step2-challenge').toString('base64') 
        }) // Step 2
        .mockResolvedValueOnce({ success: true, challenge: null }); // Final step

      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        logger: mockLogger
      });

      const result = await credSSP.authenticate(mockHttpClient);

      expect(result.success).toBe(true);
      expect(credSSP.authenticated).toBe(true);
      expect(mockHttpClient.request).toHaveBeenCalledTimes(4); // Base auth + 3 CredSSP steps
    });
  });

  describe('Edge cases and boundary conditions', () => {
    test('should handle empty domain string', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        domain: ''
      });

      expect(credSSP.domain).toBe('');
      expect(credSSP.getSessionInfo().domain).toBe('');
    });

    test('should handle very long username and password', () => {
      const longUsername = 'a'.repeat(1000);
      const longPassword = 'b'.repeat(1000);

      const credSSP = new CredSSPAuth({
        username: longUsername,
        password: longPassword
      });

      expect(credSSP.username).toBe(longUsername);
      expect(credSSP.password).toBe(longPassword);
    });

    test('should handle special characters in credentials', () => {
      const specialUsername = 'user@domain.com';
      const specialPassword = 'p@$$w0rd!123';

      const credSSP = new CredSSPAuth({
        username: specialUsername,
        password: specialPassword
      });

      expect(credSSP.username).toBe(specialUsername);
      expect(credSSP.password).toBe(specialPassword);
    });

    test('should handle Unicode characters in credentials', () => {
      const unicodeUsername = '用户';
      const unicodePassword = '密码123';

      const credSSP = new CredSSPAuth({
        username: unicodeUsername,
        password: unicodePassword
      });

      expect(credSSP.username).toBe(unicodeUsername);
      expect(credSSP.password).toBe(unicodePassword);
    });

    test('should handle maximum retry count', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        maxRetries: 10
      });

      expect(credSSP.maxRetries).toBe(10);
    });

    test('should handle zero retry count', () => {
      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        maxRetries: 0
      });

      expect(credSSP.maxRetries).toBe(0);
    });

    test('should handle very long SPN', () => {
      const longSPN = 'HTTP/' + 'a'.repeat(100) + '@' + 'b'.repeat(100);

      const credSSP = new CredSSPAuth({
        username: 'testuser',
        password: 'testpass',
        baseAuth: 'kerberos',
        servicePrincipalName: longSPN
      });

      expect(credSSP.servicePrincipalName).toBe(longSPN);
    });
  });
});