# WinRM Installation and Configuration - Detailed Technical Reference

**Source:** Microsoft Learn Documentation  
**URL:** https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management  
**Date Extracted:** 2025-11-09  
**Author:** MiniMax Agent

## Executive Summary

This document provides comprehensive technical details about Windows Remote Management (WinRM) installation and configuration, focusing on setup requirements, endpoint configuration, URI structure, HTTP/HTTPS transport setup, and port configurations. WinRM is automatically installed with all supported Windows operating systems but requires proper configuration to function as a remote management solution.

---

## 1. Setup Requirements and Prerequisites

### System Requirements
- **Operating System:** All currently-supported Windows operating systems
- **WinRM Service:** Automatically installed with Windows
- **Service Startup:** 
  - Windows Server 2008 and later: Service starts automatically
  - Earlier Windows versions: Manual start required
- **Required DLL:** WinHTTP.dll must be registered
- **Dependencies:** WMI service integration

### Default Installation State
- **Service Status:** WinRM service is installed but **no listener is configured by default**
- **Firewall Status:** Internet Connection Firewall (ICF) blocks WinRM ports by default
- **Message Handling:** WS-Management protocol messages cannot be received or sent until a listener is configured

### Administrative Requirements
- **Privilege Level:** All configuration commands must be run as a local computer Administrator
- **Group Membership:** Users needing WMI plug-in access must be added to `WinRMRemoteWMIUsers__` group

---

## 2. Quick Configuration Process

### The `winrm quickconfig` Command

**Basic Command:**
```cmd
winrm quickconfig
```

**Operations performed by quickconfig:**
1. **Starts the WinRM service** and sets it to auto-start
2. **Configures a listener** for HTTP/HTTPS on any IP address
3. **Defines ICF exceptions** to open ports for the current user profile

**HTTPS Configuration:**
```cmd
winrm quickconfig -transport:https
```

### Important Configuration Notes
- **Profile Dependency:** The quickconfig command creates firewall exceptions only for the current user profile
- **Profile Changes:** If the firewall profile changes, `winrm quickconfig` must be rerun
- **Certificate Requirement:** For HTTPS, an appropriate Server Authentication certificate is required
- **Security Warning:** If no certificate is available, `winrm quickconfig` can run but data will not be encrypted

---

## 3. Endpoint Configuration and Listener Setup

### Listener Architecture
- **Definition:** Listeners are defined by transport type (HTTP or HTTPS) and IPv4/IPv6 address
- **Multiple Listeners:** Multiple listeners can be configured on the same system
- **URL Conflicts:** If two listeners have the same port and computer name on different IP addresses, only one will listen due to identical URL prefixes

### Key Listener Configuration Settings

#### Address Configuration
- **Address:** Specifies the address for which the listener is created
- **ListeningOn:** Lists IPv4 and IPv6 addresses the listener uses
- **IP Filtering:** Support for IPv4Filter and IPv6Filter to restrict allowed addresses

#### Transport Configuration
- **Transport:** HTTP (default) or HTTPS
- **Port:** Configurable per listener

#### Hostname and URL Configuration
- **Hostname:** FQDN, IPv4/IPv6 literal, or wildcard
- **URLPrefix:** String to accept HTTP/HTTPS requests
  - **Default:** `wsman`
  - **Example:** `https://SampleMachine/wsman`

#### Security Configuration
- **Enabled:** Specifies if the listener is active (default: True)
- **CertificateThumbprint:** Required for HTTPS - SHA-1 hash of the service certificate

### Listener Configuration Commands

**View Current Configuration:**
```cmd
winrm enumerate winrm/config/listener
```

**View All WinRM Configuration:**
```cmd
winrm get winrm/config
```

**Get Configuration Help:**
```cmd
winrm help config
```

### Manual Listener Creation
Listeners can be manually configured with specific parameters for custom deployments, including:
- Specific IP address bindings
- Custom port assignments
- Hostname verification
- Certificate绑定

---

## 4. URI Structure and Resource URI Formats

### Resource URI Definition
A **resource URI** is an identifier for a distinct type of management operation or value used by management services implementing the WS-Management protocol.

### Basic URI Format
```
prefix + path_to_resource
```

**Example Components:**
- **Prefix:** `schemas.microsoft.com/wbem/wsman/1/wmi`
- **Path:** `root/cimv2/Win32_LogicalDisk`
- **Complete URI:** `http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_LogicalDisk`

### Types of Resource URIs

#### 1. WMI URIs
- **Purpose:** Represent Common Information Model (CIM) class paths
- **Format:** Namespace and class path
- **Used With:** Session, IWSManSession, WSMan.CreateResourceLocator methods
- **Example:** `http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process`

#### 2. IPMI URIs
- **Purpose:** Industry-standard URIs based on CIM version 2.9
- **Used With:** Session methods (Get, Put, Enumerate, Invoke)
- **Example:** `https://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_NumericSensor.xsd`

#### 3. WinRM Configuration URIs
- **Purpose:** Configuration operations of the WinRM listener
- **Used With:** Session methods (Get, Put, Create, Delete, Enumerate)
- **Example:** `https://schemas.microsoft.com/wbem/wsman/1/config/listener`

#### 4. System Event Log (SEL) URIs
- **Purpose:** Subscribe to Event Collector events from the BMC
- **Used With:** Wevtutil command

### URI Case Sensitivity Rules
- **Main URI:** Case sensitivity enforcement varies
- **Fragment XML:** Requires exact case matching for properties
- **XPath Standards:** Case-sensitive
- **WMI Resources:** Class, property, and method names must exactly match WMI repository case
- **Recommendation:** Use correct case for interoperability

### Default URL Prefix
- **Default:** `wsman`
- **Complete Example:** `https://servername/wsman`
- **Customization:** Can be modified for specific deployment requirements

---

## 5. HTTP/HTTPS Transport Setup

### HTTP Transport Configuration

#### Default HTTP Settings
- **Port:** 5985 (WinRM 2.0)
- **Transport:** HTTP
- **Listener Setup:** Automatically configured by `winrm quickconfig`
- **Firewall Exception:** Added automatically for the current profile

#### HTTP Configuration Commands
```cmd
# Configure HTTP listener
winrm quickconfig -transport:http

# View HTTP listener configuration
winrm enumerate winrm/config/listener
```

### HTTPS Transport Configuration

#### Certificate Requirements
For HTTPS configuration, a **local computer Server Authentication certificate** is required with:
- **Common Name (CN):** Must match the hostname
- **Validity:** Must not be expired, revoked, or self-signed
- **Enhanced Key Usage:** Must include 'Server authentication'
- **Certification Path:** Must show 'This certificate is OK'
- **Certificate Size:** Maximum 16KB usable by WinRM

#### HTTPS Configuration Process

**Step 1: Certificate Installation**
```cmd
# Request certificate from Microsoft Certificate Server (if available)
# URL: https://<MyDomainCertificateServer>/certsrv

# Or use MMC Certificates snap-in
# Path: Certificates (Local computer) > Personal > Certificates
```

**Step 2: HTTPS Listener Setup**
```cmd
# Configure HTTPS listener
winrm quickconfig -transport:https

# Verify HTTPS listener
winrm enumerate winrm/config/listener
```

#### HTTPS Default Settings
- **Port:** 5986 (WinRM 2.0)
- **On Windows 7 and later:** HTTP uses 5985, HTTPS uses 5986
- **On earlier Windows:** HTTP uses port 80, HTTPS uses port 443

#### Certificate Verification
```cmd
# Verify certificate installation
Winrm get http://schemas.microsoft.com/wbem/wsman/1/config
```

#### HTTPS Troubleshooting
**Common Error 0x80338115:** "Cannot create a WinRM listener on HTTPS because this machine does not have an appropriate certificate"

**Resolution Steps:**
1. Verify certificate validity dates
2. Ensure 'Issued to:' name matches host name or Subject Alternative Name
3. Check 'Server authentication' under Enhanced Key Usage
4. Confirm Certification Path shows 'This certificate is OK'
5. Verify certificate thumbprint matches intended certificate

### Transport Security Features
- **Encryption:** HTTPS provides data encryption complementing WinRM's default Kerberos authentication
- **Authentication Methods:** Multiple authentication methods supported per transport
- **Channel Binding:** Policy for channel-binding token (CbtHardeningLevel: Relaxed by default)

---

## 6. Port Configurations and Firewall Requirements

### Default Port Assignments

#### WinRM 2.0 Ports (Windows 7 and Later)
- **HTTP:** Port 5985
- **HTTPS:** Port 5986

#### Legacy Ports (Earlier Windows Versions)
- **HTTP:** Port 80
- **HTTPS:** Port 443

### Compatibility Listeners
For backward compatibility, additional listeners can be enabled:
```cmd
# Enable compatibility HTTP listener (port 80)
winrm set winrm/config/service @{EnableCompatibilityHttpListener="True"}

# Enable compatibility HTTPS listener (port 443)
winrm set winrm/config/service @{EnableCompatibilityHttpsListener="True"}
```

### Firewall Configuration

#### Automatic Firewall Exceptions
- **Quickconfig:** Automatically adds Windows Firewall exceptions for configured ports
- **Profile Scope:** Exceptions added only for the current user profile
- **Profile Change Impact:** Rerun `winrm quickconfig` if firewall profile changes

#### Manual Firewall Configuration
If manual configuration is required:
```cmd
# Add firewall rule for HTTP (port 5985)
netsh advfirewall firewall add rule name="Windows Remote Management (HTTP-In)" dir=in action=allow protocol=TCP localport=5985

# Add firewall rule for HTTPS (port 5986)
netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=5986
```

### Port Conflict Considerations
- **Multiple Listeners:** If two listeners use the same port and computer name on different IPs, only one will listen
- **URL Prefix Matching:** Identical URL prefixes prevent multiple listeners on same port
- **IP Address Binding:** Listeners must bind to specific IP addresses to avoid conflicts

---

## 7. Security Settings and Authentication Configuration

### WinRM Client Authentication Settings (Defaults)

#### Default Client Configuration
- **AllowUnencrypted:** `False` (requires encryption)
- **Basic:** `True` (least secure, plaintext credentials)
- **Digest:** `True` (challenge-response, client-initiated only)
- **Certificate:** `True` (X509 certificate-based)
- **Kerberos:** `True` (mutual authentication, domains only)
- **Negotiate:** `True` (Kerberos for domain, NTLM for local accounts)
- **CredSSP:** `False` (delegates user credentials)

#### Trusted Hosts Configuration
**Purpose:** List of remote computers for which mutual authentication is not established
**Use Case:** Workgroups or different domains
**Security Warning:** Client may send credentials to these hosts - restrict as much as possible
**Configuration:**
```cmd
# Add trusted host
winrm set winrm/config/client @{TrustedHosts="ComputerName"}

# Add multiple trusted hosts
winrm set winrm/config/client @{TrustedHosts="Computer1,Computer2"}

# Add IPv6 trusted host
winrm set winrm/config/client @{TrustedHosts="[0:0:0:0:0:0:0:0]"}
```

### WinRM Service Authentication Settings (Defaults)

#### Default Service Configuration
- **RootSDDL:** Security descriptor controlling remote access
- **AllowUnencrypted:** `False`
- **Basic:** `False`
- **Certificate:** `False`
- **Kerberos:** `True`
- **Negotiate:** `True`
- **CredSSP:** `False`
- **CbtHardeningLevel:** `Relaxed` (policy for channel-binding token)

### Authentication Method Configuration

#### Basic Authentication
```cmd
# Enable on client
winrm set winrm/config/client/auth @{Basic="true"}

# Enable on service
winrm set winrm/config/service/auth @{Basic="true"}
```

#### Certificate Authentication
```cmd
# Enable client certificate authentication
winrm set winrm/config/client/auth @{Certificate="true"}

# Enable service certificate authentication
winrm set winrm/config/service/auth @{Certificate="true"}
```

#### Kerberos Configuration
- **Domain Requirement:** Both client and server must be joined to a domain
- **IP Address Limitation:** Cannot use IP addresses in CreateSession calls
- **Default Method:** Kerberos is default for domain clients (not localhost/127.0.0.1/::1)

#### Negotiate Authentication
- **User Account Control Impact:** In workgroups, only built-in Administrator can access
- **Registry Override:** Set `LocalAccountTokenPolicy` to `1` to allow all Administrators group access in workgroups

### WMI Plug-in Security Configuration

#### Group Membership
**Add User to WinRMRemoteWMIUsers__ Group:**
```cmd
# Using net command
net localgroup WinRMRemoteWMIUsers__ /add <domain>\<username>

# Using Group Policy
# Navigate to: Computer Configuration > Windows Settings > Restricted Groups
```

#### WMI Namespace Security
```cmd
# Configure security descriptor for WMI plug-ins
winrm configSDDL http://schemas.microsoft.com/wbem/wsman/1/wmi/WmiNamespace

# Or use WMI Management console
# Run: wmimgmt.msc
```

---

## 8. WinRS (Windows Remote Shell) Configuration

### Default WinRS Configuration Settings
- **AllowRemoteShellAccess:** `True` (enables access)
- **IdleTimeout:** `180000 ms` (maximum idle time for shell)
- **MaxConcurrentUsers:** `5`
- **MaxProcessesPerShell:** `15` (0 for unlimited)
- **MaxMemoryPerShellMB:** `150 MB`
- **MaxShellsPerUser:** `5`

### WinRS Configuration Commands
```cmd
# View WinRS configuration
winrm get winrm/config/winrs

# Modify WinRS settings
winrm set winrm/config/winrs @{IdleTimeout="120000"}
```

---

## 9. Configuration Management and Group Policy

### Group Policy Configuration
WinRM can be configured using Group Policy under:
- `Computer Configuration\Administrative Templates\Windows Components\Windows Remote Management`
- `Computer Configuration\Administrative Templates\Windows Components\Windows Remote Shell`

**Access Group Policy Editor:**
```cmd
gpedit.msc
```

### Configuration Import/Export
```cmd
# Export current configuration
winrm get winrm/config > winrm-config.xml

# Import configuration
winrm set winrm/config @winrm-config.xml
```

### Configuration Validation Commands
```cmd
# Validate current configuration
winrm get winrm/config

# Test connection to remote system
winrm identify -r:https://remote-server -u:username -p:password
```

---

## 10. Installation and Configuration Notes

### IPMI Driver and Provider Notes
- **Auto-Detection:** IPMI provider automatically loads when BMC is detected
- **Manual Installation:** If not auto-detected, use:
```cmd
Rundll32 ipmisetp.dll, AddTheDevice
```

### WMI Plug-in Access Notes
- **Security Requirements:** Non-administrator users need explicit access grants
- **Namespace Permissions:** Must configure specific WMI namespace security
- **Group Membership:** Use `WinRMRemoteWMIUsers__` group for simplified management

### Migration and Upgrade Notes
- **Listener Migration:** Previously configured listeners are migrated upon upgrade
- **Port Changes:** Default ports changed in WinRM 2.0 (5985/5986 instead of 80/443)
- **Compatibility:** Legacy ports can be re-enabled if needed

### Event Handling and Monitoring
- **Event Collection:** Use Wevtutil.exe for viewing Event Collector events
- **Event Tracing:** WinRM activity traceable through WMI using Event Tracing (ETW)
- **Event Viewer:** Events accessible via Event Viewer UI from Windows Vista onwards

---

## Conclusion

Proper WinRM installation and configuration requires careful attention to:
1. **Initial setup** using `winrm quickconfig` with appropriate transport selection
2. **Certificate management** for HTTPS transport security
3. **Firewall configuration** to allow required ports
4. **Authentication setup** based on security requirements and network topology
5. **Endpoint configuration** with proper resource URIs and listener settings

The modular approach to transport configuration, authentication methods, and security settings allows WinRM to adapt to various enterprise environments while maintaining robust security controls.