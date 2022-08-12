package io.particle.test;

import java.security.SecureRandom;
import java.nio.ByteBuffer;

import static org.junit.Assert.*;

public class SecureRandomMock extends SecureRandom {
    private byte[] bytes;
    private int offs;

    public SecureRandomMock(byte[] bytes) {
        this.bytes = bytes;
        this.offs = 0;
    }

    public void nextBytes(byte[] bytes) {
        assertTrue(this.bytes.length - this.offs >= bytes.length);
        System.arraycopy(this.bytes, this.offs, bytes, 0, bytes.length);
        this.offs += bytes.length;
    }
}
