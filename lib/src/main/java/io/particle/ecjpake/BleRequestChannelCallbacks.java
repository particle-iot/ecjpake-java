package io.particle.ecjpake;

public interface BleRequestChannelCallbacks {
    void onChannelOpen();
    void onChannelWrite(byte[] data);
    void onRequestResponse(int requestId, int result, byte[] data);
    void onRequestError(int requestId, RequestError error);
}
