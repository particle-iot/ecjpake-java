package io.particle.device.control.test;

import io.particle.device.control.BleRequestChannel;
import io.particle.device.control.BleRequestChannelCallback;
import io.particle.device.control.RequestError;

import org.junit.Test;
import static org.junit.Assert.*;

class Callback implements BleRequestChannelCallback {
    @Override
    public void onChannelOpen() {
    }

    @Override
    public void onChannelWrite(byte[] data) {
    }

    @Override
    public void onRequestResponse(int requestId, int result, byte[] data) {
    }

    @Override
    public void onRequestError(int requestId, RequestError error) {
    }
}

public class BleRequestChannelTest {
    @Test
    public void itWorks() {
        Callback callback = new Callback();
        BleRequestChannel channel = new BleRequestChannel("passw0rd".getBytes(), callback);
    }
}
