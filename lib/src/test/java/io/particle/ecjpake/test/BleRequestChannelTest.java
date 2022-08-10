package io.particle.ecjpake.test;

import io.particle.ecjpake.BleRequestChannel;
import io.particle.ecjpake.BleRequestChannelCallbacks;
import io.particle.ecjpake.RequestError;

import java.nio.ByteBuffer;

import org.junit.Test;
import static org.junit.Assert.*;

class Callbacks implements BleRequestChannelCallbacks {
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
        Callbacks callbacks = new Callbacks();
        BleRequestChannel channel = BleRequestChannel.newBuilder()
                .setSecret("passw0rd".getBytes())
                .setCallbacks(callbacks)
                .build();
    }
}
