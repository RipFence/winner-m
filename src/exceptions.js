// This file contains custom error classes for handling various WinRM-related errors.
// It includes a generic WinRM error, WSMan fault error, transport error, operation timeout error,
// and authentication errors. Each class extends the built-in Error class and provides additional
// properties and methods to capture relevant information about the error.

export class WinRMError extends Error {
    constructor(message = '"Generic WinRM error"', code = 500) {
        super(message);
        this.name = this.constructor.name;
        this.code = code;
        Error.captureStackTrace(this, this.constructor);
    }
}

export class WSManFaultError extends WinRMError {
    /**
     * @param {number} code - The HTTP status code of the response.
     * @param {string} message - The error message.
     * @param {string} response - The raw WSMan response text.
     * @param {string} reason - The WSMan fault reason.
     * @param {string|null} fault_code - The WSMan fault code.
     * @param {string|null} fault_subcode - The WSMan fault subcode.
     * @param {number|null} wsman_fault_code - The MS WSManFault specific code.
     * @param {number|null} wmierror_code - The MS WMI error code.
     */
    constructor(
        code,
        message,
        response,
        reason,
        fault_code = null,
        fault_subcode = null,
        wsman_fault_code = null,
        wmierror_code = null
    ) {
        const fault_data = {
            transport_message: message,
            http_status_code: code,
        };
        if (wsman_fault_code !== null) fault_data.wsmanfault_code = wsman_fault_code;
        if (fault_code !== null) fault_data.fault_code = fault_code;
        if (fault_subcode !== null) fault_data.fault_subcode = fault_subcode;

        super(`${reason} (extended fault data: ${JSON.stringify(fault_data)})`, code);
        this.response = response;
        this.fault_code = fault_code;
        this.fault_subcode = fault_subcode;
        this.reason = reason;
        this.wsman_fault_code = wsman_fault_code;
        this.wmierror_code = wmierror_code;
    }
}

export class WinRMTransportError extends Error {
    /**
     * @param {string} protocol
     * @param {number} code
     * @param {string} responseText
     */
    constructor(protocol, code, responseText) {
        super(`Bad HTTP response returned from server. Code ${code}`);
        this.name = this.constructor.name;
        this.protocol = protocol;
        this.code = code;
        this.responseText = responseText;
        Error.captureStackTrace(this, this.constructor);
    }
}

export class WinRMOperationTimeoutError extends Error {
    constructor(message = 'WinRM operation timeout', code = 500) {
        super(message);
        this.name = this.constructor.name;
        this.code = code;
        Error.captureStackTrace(this, this.constructor);
    }
}

export class AuthenticationError extends WinRMError {
    constructor(message = 'Authorization Error', code = 401) {
        super(message, code);
        this.name = this.constructor.name;
    }
}

export class BasicAuthDisabledError extends AuthenticationError {
    constructor() {
        super('WinRM/HTTP Basic authentication is not enabled on remote host');
        this.name = this.constructor.name;
    }
}

export class InvalidCredentialsError extends AuthenticationError {
    constructor(message = 'Invalid credentials') {
        super(message);
        this.name = this.constructor.name;
    }
}
