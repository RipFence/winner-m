// winrm-transport.js
// This module handles HTTP/HTTPS communication and integrates NTLM authentication.
// It uses Axios for requests and node-client-ntlm for the NTLM handshake.

import axios from 'axios';
import { NtlmClient } from 'node-client-ntlm';

export class WinRmTransport {
  /**
   * @param {string} host - The hostname or IP address of the Windows server.
   * @param {number} port - The port for WinRM (5985 for HTTP, 5986 for HTTPS).
   * @param {string} username - The username for NTLM authentication.
   * @param {string} password - The password for NTLM authentication.
   * @param {object} options - Configuration options for the transport.
   * @param {boolean} [options.https=true] - Whether to use HTTPS. Defaults to true for security.
   * @param {number} [options.timeout=60000] - Request timeout in milliseconds.
   * @param {boolean} [options.rejectUnauthorized=true] - For HTTPS, whether to reject self-signed certs.
   */
  constructor(host, port, username, password, options = {}) {
    this.host = host;
    this.port = port;
    this.username = username;
    this.password = password;
    this.options = {
      https: true,
      timeout: 60000, // Default to 60 seconds
      rejectUnauthorized: true, // For HTTPS, reject self-signed certificates by default
      ...options
    };

    this.baseUrl = `${this.options.https ? 'https' : 'http'}://${host}:${port}/wsman`;
    this.axiosInstance = axios.create({
      baseURL: this.baseUrl,
      timeout: this.options.timeout,
      headers: {
        'Content-Type': 'application/soap+xml;charset=UTF-8',
        'User-Agent': 'Winner-M/1.0'
      },
      // Ensure response is treated as a string, not parsed as JSON
      transformResponse: [data => data],
      // For Node.js HTTPS, configure certificate rejection
      ...(this.options.https && {
        httpsAgent: new (require('https').Agent)({
          rejectUnauthorized: this.options.rejectUnauthorized
        })
      })
    });

    this.ntlmClient = new NtlmClient(this.username, this.password, this.host);
    this._setupNtlmInterceptor();
  }

  /**
   * Sets up an Axios interceptor to handle the NTLM challenge-response handshake.
   * This intercepts 401 Unauthorized responses and injects NTLM authorization headers.
   * The NTLM handshake involves three steps:
   * 1. Client sends Type 1 (Negotiate) message.
   * 2. Server responds with 401 and WWW-Authenticate containing Type 2 (Challenge) message.
   * 3. Client sends Type 3 (Authenticate) message with Authorization header.
   */
  _setupNtlmInterceptor() {
    this.axiosInstance.interceptors.request.use(async (config) => {
      // Check if NTLM negotiation has already started or completed
      if (this.ntlmClient.isNegotiating || this.ntlmClient.isAuthenticated) {
        return config;
      }

      // Start NTLM negotiation by sending Type 1 message
      this.ntlmClient.startNegotiation();
      const type1Msg = this.ntlmClient.createType1Message();
      config.headers['Authorization'] = `NTLM ${type1Msg}`;
      return config;
    }, (error) => {
      return Promise.reject(error);
    });

    this.axiosInstance.interceptors.response.use(
      (response) => {
        // If NTLM negotiation was in progress and we got a successful response,
        // it means authentication finished, or it was not NTLM auth.
        if (this.ntlmClient.isNegotiating) {
          this.ntlmClient.markAuthenticated();
        }
        return response;
      },
      async (error) => {
        const originalRequest = error.config;
        // If it's a 401 Unauthorized and NTLM negotiation is ongoing or can start
        if (error.response && error.response.status === 401 &&
          error.response.headers['www-authenticate'] &&
          error.response.headers['www-authenticate'].includes('NTLM') &&
          !originalRequest._retry) { // Ensure we don't get into an infinite retry loop

          originalRequest._retry = true; // Mark request as retried

          const wwwAuthenticateHeader = error.response.headers['www-authenticate'];
          const ntlmChallengeMatch = wwwAuthenticateHeader.match(/NTLM\s+([a-zA-Z0-9\/+=]+)/);

          if (ntlmChallengeMatch && ntlmChallengeMatch[1]) {
            const type2Msg = ntlmChallengeMatch[1];
            try {
              // Process Type 2 (Challenge) and create Type 3 (Authenticate) message
              const type3Msg = this.ntlmClient.createType3Message(type2Msg);

              // Update the Authorization header for the original request and retry
              originalRequest.headers['Authorization'] = `NTLM ${type3Msg}`;
              this.ntlmClient.markAuthenticated(); // Assume success if Type 3 generated
              return this.axiosInstance(originalRequest);
            } catch (ntlmError) {
              console.error('NTLM authentication error:', ntlmError.message);
              return Promise.reject(new Error(`NTLM authentication failed: ${ntlmError.message}`));
            }
          }
        }
        // For any other error or if NTLM already failed
        return Promise.reject(error);
      }
    );
  }

  /**
   * Sends a WinRM SOAP request.
   * @param {string} xmlBody - The XML string representing the SOAP request body.
   * @returns {Promise<string>} A promise that resolves with the XML response body.
   */
  async sendRequest(xmlBody) {
    try {
      const response = await this.axiosInstance.post('', xmlBody);
      return response.data;
    } catch (error) {
      let errorMessage = 'An unknown error occurred during WinRM request.';
      if (error.response) {
        // The request was made and the server responded with a status code
        // that falls out of the range of 2xx
        errorMessage = `WinRM HTTP Error: ${error.response.status} ${error.response.statusText}. Response: ${error.response.data}`;
      } else if (error.request) {
        // The request was made but no response was received
        errorMessage = `WinRM Network Error: No response received. ${error.message}`;
      } else {
        // Something happened in setting up the request that triggered an Error
        errorMessage = `WinRM Request Setup Error: ${error.message}`;
      }
      console.error('WinRM Transport Error:', errorMessage);
      throw new Error(errorMessage);
    }
  }
}
