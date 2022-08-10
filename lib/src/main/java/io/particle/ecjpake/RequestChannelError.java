package io.particle.ecjpake;

public class RequestChannelError extends RuntimeException {
    public RequestChannelError(String message) {
        super(message);
    }

    public RequestChannelError(String message, Throwable cause) {
        super(message, cause);
    }
}
