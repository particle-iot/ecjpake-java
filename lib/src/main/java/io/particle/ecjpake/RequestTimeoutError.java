package io.particle.ecjpake;

public class RequestTimeoutError extends RequestError {
    public RequestTimeoutError(String message) {
        super(message);
    }

    public RequestTimeoutError(String message, Throwable cause) {
        super(message, cause);
    }
}
