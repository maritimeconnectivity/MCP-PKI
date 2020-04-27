package net.maritimeconnectivity.pki.exception;

public class PKIRuntimeException extends RuntimeException {

    public PKIRuntimeException(String message) {
        super(message);
    }

    public PKIRuntimeException(Throwable cause) {
        super(cause);
    }

    public PKIRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }
}
