package io.particle.ecjpake;

public class RequestError extends Exception {
    public RequestError(String message) {
        super(message);
    }

    public RequestError(String message, Throwable cause) {
        super(message, cause);
    }
}
