/**
 * TypeScript type definitions for JS-WinRM
 */

export interface WinRMConfig {
  host: string;
  port?: number;
  protocol?: 'http' | 'https';
  path?: string;
  auth: WinRMAuthConfig;
  ssl?: WinRMSSLConfig;
  timeouts?: WinRMTimeouts;
  retries?: WinRMRetries;
  workingDirectory?: string;
  environmentVars?: Record<string, string>;
  maxShellTime?: number;
  maxConnections?: number;
}

export interface KerberosOptions {
  ticketCache?: string;
  realm?: string;
  kdc?: string;
  keytabFile?: string;
  servicePrincipal?: string;
  hostnameCanonicalization?: boolean;
  clockSkew?: number;
  debug?: boolean;
  useKeytab?: boolean;
  mutualAuth?: boolean;
  delegate?: boolean;
  credentialsCache?: string;
  configFile?: string;
  libraries?: string[];
  timeout?: number;
  maxRetries?: number;
  retryDelay?: number;
}

export interface KerberosConfig extends KerberosOptions {
  principal: string;
  password?: string; // Optional if using keytab
  domain?: string; // AD domain for the principal
  realm?: string; // Kerberos realm (usually same as domain, but can be different)
  servicePrincipal?: string; // SPN for the target service
  useKeytab?: boolean; // Whether to use keytab file instead of password
  keytabFile?: string; // Path to keytab file
  validateCert?: boolean; // For HTTPS connections
  caCert?: string; // CA certificate for validation
}

export interface WinRMAuthConfig {
  type: 'ntlm' | 'basic' | 'kerberos' | 'credssp';
  username: string;
  password: string;
  domain?: string;
  workstation?: string;
  kerberos?: KerberosConfig; // Kerberos-specific configuration
  credssp?: CredSSPConfig; // CredSSP-specific configuration
}

export interface WinRMSSLConfig {
  rejectUnauthorized?: boolean;
  ca?: string | Buffer;
  cert?: string | Buffer;
  key?: string | Buffer;
  passphrase?: string;
}

export interface WinRMTimeouts {
  connectTimeout?: number;
  readTimeout?: number;
  operationTimeout?: number;
}

export interface WinRMRetries {
  maxRetries?: number;
  retryDelay?: number;
}

export interface WinRMResult {
  statusCode: number;
  stdout: string;
  stderr: string;
  exitCode?: number;
  startTime?: Date;
  endTime?: Date;
  duration?: number;
  success?: boolean;
}

export interface WinRMCommandResult extends WinRMResult {
  commandId?: string;
  shellId?: string;
}

export interface WinRMSystemInfo {
  hostname: string;
  osVersion: string;
  currentUser: string;
  connected: boolean;
}

export interface WinRMStatus {
  connected: boolean;
  authenticated: boolean;
  shellId: string | null;
  options: {
    host: string;
    port: number;
    protocol: 'http' | 'https';
  };
  auth: {
    method: string;
    availableMethods: string[];
    username: string;
    domain: string;
    workstation: string;
    kerberos?: KerberosStatus; // Kerberos-specific status information
    credssp?: CredSSPStatus; // CredSSP-specific status information
  };
  httpClient: {
    activeConnections: number;
    maxConnections: number;
    keepAlive: boolean;
  };
}

export interface WinRMLogOptions {
  level?: 'error' | 'warn' | 'info' | 'debug' | 'trace';
}

export interface KerberosStatus {
  authenticated: boolean;
  principal: string;
  realm: string;
  ticketGrantingTicket?: {
    validUntil: Date;
    renewUntil?: Date;
    cacheLocation?: string;
  };
  serviceTickets: Array<{
    servicePrincipal: string;
    validUntil: Date;
    renewUntil?: Date;
  }>;
  config: {
    kdc?: string;
    realm: string;
    ticketCache?: string;
    keytabFile?: string;
  };
  error?: string;
}

export interface KerberosDiagnosticInfo {
  principal: string;
  realm: string;
  availableKDCs: string[];
  krb5Config: {
    defaultRealm?: string;
    dnsLookupKDC?: boolean;
    dnsLookupRealm?: boolean;
    ticketLifetime?: string;
    renewableLifetime?: string;
  };
  credentialCache?: {
    location?: string;
    tickets: Array<{
      principal: string;
      realm: string;
      validUntil: Date;
      renewableUntil?: Date;
    }>;
  };
  keytabInfo?: {
    file?: string;
    principals: string[];
    lastModified?: Date;
  };
}

/**
 * WinRM Error classes
 */
export class WinRMError extends Error {
  code: string;
  details: Record<string, any>;
  timestamp: string;
}

export class WinRMAuthenticationError extends WinRMError {
  authMethod: string;
}

export class WinRMConnectionError extends WinRMError {
  cause?: string;
}

export class WinRMCommandError extends WinRMError {
  command: string;
  exitCode: number;
  stdout: string;
  stderr: string;
}

export class WinRMConfigurationError extends WinRMError {
  parameter: string;
}

export class WinRMProtocolError extends WinRMError {
  operation: string;
}

export class WinRMTimeoutError extends WinRMError {
  timeoutType: string;
}

export class WinRMSslError extends WinRMError {
  certificate: string;
}

export class WinRMKerberosError extends WinRMAuthenticationError {
  kerberosError: string;
  principal?: string;
  servicePrincipal?: string;
  realm?: string;
  kdc?: string;
}

export class WinRMCredSSPError extends WinRMAuthenticationError {
  credsspError: string;
  authenticationLevel?: CredSSPAuthenticationLevel;
  protocolVersion?: CredSSPProtocolVersion;
  serverSPN?: string;
  certificateValidation?: boolean;
  delegationFailed?: boolean;
  hopNumber?: number;
  targetServer?: string;
  securityError?: string;
}

/**
 * Main WinRM class interface
 */
export interface WinRMInterface {
  createSession(options: WinRMConfig): Session;
  createProtocol(options: WinRMConfig): Protocol;
  connect(options: WinRMConfig): Promise<Session>;
  runCommand(options: WinRMConfig, command: string): Promise<WinRMResult>;
  runPowerShell(options: WinRMConfig, script: string): Promise<WinRMResult>;
}

/**
 * Session class interface
 */
export interface SessionInterface {
  run(command: string, options?: WinRMSessionOptions): Promise<WinRMResult>;
  runPS(powerShellScript: string, options?: WinRMSessionOptions): Promise<WinRMResult>;
  runBatch(commands: WinRMBatchCommand[]): Promise<WinRMResult[]>;
  isConnected(): boolean;
  getStatus(): WinRMStatus;
  ping(): Promise<boolean>;
  test(): Promise<boolean>;
  getSystemInfo(): Promise<WinRMSystemInfo>;
  close(): Promise<void>;
}

export interface WinRMSessionOptions extends Omit<WinRMConfig, 'host' | 'auth' | 'protocol'> {
  workingDirectory?: string;
  environmentVars?: Record<string, string>;
  operationTimeout?: number;
  readTimeout?: number;
}

export interface WinRMBatchCommand {
  command: string;
  continueOnError?: boolean;
  options?: WinRMSessionOptions;
}

/**
 * Protocol class interface
 */
export interface ProtocolInterface {
  openShell(): Promise<void>;
  closeShell(): Promise<void>;
  runCommand(command: string, args?: string): Promise<string>;
  getCommandOutput(commandId: string): Promise<WinRMCommandResult>;
  cleanupCommand(commandId: string): Promise<void>;
  waitForCommand(commandId: string, pollInterval?: number): Promise<WinRMCommandResult>;
  runCommandAndWait(command: string, args?: string, pollInterval?: number): Promise<WinRMCommandResult>;
  authenticate(): Promise<void>;
  isShellOpen(): boolean;
  getStatus(): WinRMStatus;
  ping(): Promise<boolean>;
  close(): Promise<void>;
}

// Kerberos-specific types and interfaces
export interface KerberosTestOptions {
  principal: string;
  password?: string;
  realm?: string;
  kdc?: string;
  timeout?: number;
}

export interface KerberosConfiguration {
  realm: string;
  kdc: string[];
  adminServer?: string;
  kpasswdServer?: string;
  defaultDomain?: string;
  dnsLookupKDC?: boolean;
  dnsLookupRealm?: boolean;
  ticketLifetime?: string;
  renewableLifetime?: string;
  forwardable?: boolean;
  proxiable?: boolean;
  ticketPolicy?: string;
}

export interface KerberosTicketInfo {
  principal: string;
  realm: string;
  validFrom: Date;
  validTo: Date;
  renewableUntil?: Date;
  ticketFlags: string[];
  clientAddresses?: string[];
  encryptedPart?: {
    keyType: number;
    keyVersion: number;
  };
}

export interface WinRMAuthValidationResult {
  valid: boolean;
  method: 'ntlm' | 'basic' | 'kerberos' | 'credssp';
  errors: string[];
  warnings: string[];
  kerberosSpecific?: {
    configValid: boolean;
    kdcReachable: boolean;
    principalExists: boolean;
    credentialsValid: boolean;
    ticketCacheValid?: boolean;
    keytabValid?: boolean;
  };
  credsspSpecific?: {
    serverAuthenticationLevel: CredSSPAuthenticationLevel;
    delegateCredentials: boolean;
    servicePrincipalName?: string;
    mutualAuth: boolean;
    protocolVersion: CredSSPProtocolVersion;
  };
}

// CredSSP-specific types and interfaces
export interface CredSSPOptions {
  serverAuthenticationLevel?: CredSSPAuthenticationLevel;
  credentialEncryption?: CredSSPCredentialEncryption;
  protocolVersion?: CredSSPProtocolVersion;
  servicePrincipalName?: string;
  mutualAuth?: boolean;
  delegateCredentials?: boolean;
  workStationName?: string;
  tlsProviderName?: string;
  certificateValidation?: CredSSPCertificateValidation;
  timeout?: number;
  maxRetries?: number;
  retryDelay?: number;
  logActivity?: boolean;
  diagnosticLevel?: 'none' | 'basic' | 'detailed' | 'verbose';
  useNativeCredSSPLibrary?: boolean;
  preferNativeOverSChannel?: boolean;
  sessionEncryptionLevel?: CredSSPSessionEncryption;
  allowBasicAuthFallback?: boolean;
  enforceFIPSCompliance?: boolean;
  customEncryptionSuite?: CredSPCustomEncryptionSuite;
  proxySettings?: CredSSPProxySettings;
  advancedOptions?: Record<string, any>;
}

export interface CredSSPConfig extends CredSSPOptions {
  username: string;
  password: string;
  domain?: string;
  workstation?: string;
  // Double-hop specific options
  enableDoubleHop?: boolean;
  targetServicePrincipalName?: string;
  delegateToTarget?: boolean;
  authenticationChain?: string[];
  // Security options
  serverValidationRequired?: boolean;
  allowSelfSignedCertificates?: boolean;
  certificateThumbprint?: string;
  caCertificatePath?: string;
  // Advanced delegation options
  allowUnconstrainedDelegation?: boolean;
  allowConstrainedDelegation?: boolean;
  constrainedDelegationTargets?: string[];
  resourceBasedConstrainedDelegation?: boolean;
  // Session management
  persistentSession?: boolean;
  sessionTimeout?: number;
  sessionReauthentication?: boolean;
  // Performance tuning
  connectionPooling?: boolean;
  maxConcurrentSessions?: number;
  sessionKeepAliveInterval?: number;
}

export interface CredSSPStatus {
  authenticated: boolean;
  principal: string;
  domain: string;
  authenticationLevel: CredSSPAuthenticationLevel;
  protocolVersion: CredSSPProtocolVersion;
  serverSPN?: string;
  clientSPN?: string;
  sessionEncryption: {
    enabled: boolean;
    algorithm: string;
    keySize: number;
    active: boolean;
  };
  delegation: {
    enabled: boolean;
    type: 'none' | 'constrained' | 'unconstrained' | 'resource-based';
    targetSPN?: string;
    validUntil?: Date;
  };
  certificateInfo?: {
    subject: string;
    issuer: string;
    thumbprint: string;
    validFrom: Date;
    validTo: Date;
  };
  connectionState: 'disconnected' | 'connecting' | 'authenticating' | 'connected' | 'disconnecting';
  lastActivity?: Date;
  error?: string;
}

export interface CredSSPHopConfiguration {
  hopNumber: number;
  targetHost: string;
  targetPort?: number;
  servicePrincipalName: string;
  authenticationMethod: 'kerberos' | 'ntlm';
  enableDelegation: boolean;
  credentialScope: 'local' | 'domain' | 'enterprise';
  trustLevel: 'low' | 'medium' | 'high' | 'critical';
  encryptionRequired: boolean;
  certificateValidation: CredSSPCertificateValidation;
  timeout?: number;
  maxRetries?: number;
  allowedUsers?: string[];
  allowedGroups?: string[];
  deniedUsers?: string[];
  deniedGroups?: string[];
  customAttributes?: Record<string, any>;
}

export interface CredSSPDoubleHopConfiguration {
  enabled: boolean;
  hops: CredSSPHopConfiguration[];
  finalDestination: {
    host: string;
    port?: number;
    servicePrincipalName: string;
    authenticationRequired: boolean;
  };
  // Security and validation settings
  requireAllHopsAuthentication: boolean;
  failOnAnyHopFailure: boolean;
  strictSPNValidation: boolean;
  allowKerberosFallback: boolean;
  // Performance settings
  parallelHopExecution: boolean;
  connectionTimeout: number;
  hopTimeout: number;
  maxConcurrentHops: number;
  // Audit and logging
  auditAllHops: boolean;
  logHopResults: boolean;
  auditLevel: 'none' | 'basic' | 'detailed' | 'verbose';
  // Advanced settings
  customDelegateCredentials?: string;
  resourceBasedDelegationEnabled: boolean;
  constrainedDelegationSPNs?: string[];
  protocolTransitionEnabled: boolean;
}

export interface CredSSPDiagnosticInfo {
  protocolVersion: CredSSPProtocolVersion;
  serverCapabilities: string[];
  clientCapabilities: string[];
  negotiatedFeatures: string[];
  encryptionSuite: {
    algorithm: string;
    keySize: number;
    mode: string;
    strength: 'weak' | 'medium' | 'strong' | 'very-strong';
  };
  authenticationChain: Array<{
    hop: number;
    server: string;
    authenticationMethod: 'kerberos' | 'ntlm' | 'basic';
    authenticated: boolean;
    spn?: string;
    certificateThumbprint?: string;
  }>;
  certificateChain: Array<{
    subject: string;
    issuer: string;
    thumbprint: string;
    valid: boolean;
    validationErrors: string[];
  }>;
  networkConnectivity: Array<{
    host: string;
    port: number;
    reachable: boolean;
    latency?: number;
    lastCheck: Date;
  }>;
  securitySettings: {
    fipsCompliance: boolean;
    tlsVersion: string;
    cipherSuite: string;
    certificateValidation: boolean;
    credentialEncryption: CredSSPCredentialEncryption;
  };
  performanceMetrics: {
    connectionTime: number;
    authenticationTime: number;
    totalHops: number;
    successfulHops: number;
    failedHops: number;
  };
  warnings: string[];
  errors: string[];
}

// Enums for CredSSP options
export enum CredSSPAuthenticationLevel {
  NO_AUTHENTICATION = 0,
  NO_ENCRYPTION = 1,
  ENCRYPTED = 2
}

export enum CredSSPCredentialEncryption {
  NONE = 'none',
  BASIC = 'basic',
  STRONG = 'strong',
  MAXIMUM = 'maximum'
}

export enum CredSSPProtocolVersion {
  V1 = 1,
  V2 = 2,
  V3 = 3,
  V4 = 4
}

export enum CredSSPCertificateValidation {
  NONE = 'none',
  BASIC = 'basic',
  STRICT = 'strict',
  CUSTOM = 'custom'
}

export enum CredSSPSessionEncryption {
  NONE = 'none',
  STANDARD = 'standard',
  HIGH = 'high',
  MAXIMUM = 'maximum'
}

export interface CredSPCustomEncryptionSuite {
  algorithms: string[];
  keyExchangeAlgorithms: string[];
  minimumKeySize: number;
  maximumKeySize: number;
  preferredOrder: number;
  allowedCipherSuites?: string[];
  forbiddenCipherSuites?: string[];
}

export interface CredSSPProxySettings {
  enabled: boolean;
  proxyType: 'http' | 'https' | 'socks4' | 'socks5';
  proxyHost: string;
  proxyPort: number;
  username?: string;
  password?: string;
  bypassList?: string[];
  autoDetection: boolean;
}

// Legacy exports for backward compatibility
export const validateConfig: (options: WinRMConfig) => string[];
export const testConnection: (options: WinRMConfig) => Promise<boolean>;
export const VERSION: string;