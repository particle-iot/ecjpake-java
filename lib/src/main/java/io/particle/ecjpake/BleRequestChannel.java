package io.particle.ecjpake;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.ScheduledExecutorService;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Arrays;

public class BleRequestChannel {
    public static final int DEFAULT_REQUEST_TIMEOUT = 60000;
    public static final int DEFAULT_HANDSHAKE_TIMEOUT = 10000;
    public static final int DEFAULT_MAX_CONCURRENT_REQUESTS = 1;

    private static final int AES_CCM_NONCE_SIZE = 12;
    private static final int AES_CCM_TAG_SIZE = 8;
    private static final int REQUEST_PACKET_OVERHEAD = AES_CCM_TAG_SIZE + 8;
    private static final int RESPONSE_PACKET_OVERHEAD = AES_CCM_TAG_SIZE + 8;
    private static final int HANDSHAKE_PACKET_OVERHEAD = 2;
    private static final int MAX_REQUEST_PAYLOAD_SIZE = 65535;
    private static final int MAX_HANDSHAKE_PAYLOAD_SIZE = 65535;
    private static final int MAX_REQUEST_ID = 65535;
    private static final byte[] EC_JPAKE_CLIENT_ID = "client".getBytes();
    private static final byte[] EC_JPAKE_SERVER_ID = "server".getBytes();

    public enum State {
        NEW,
        OPENING,
        OPEN,
        CLOSED
    }

    private static class Handshake {
        enum State {
            ROUND_1,
            ROUND_2,
            CONFIRM
        }

        EcJpake jpake;
        MessageDigest cliHash;
        MessageDigest servHash;
        State state;
        byte[] secret;

        Handshake(byte[] secret) {
            this.jpake = new EcJpake(EcJpake.Role.CLIENT, secret);
            try {
                this.cliHash = MessageDigest.getInstance("SHA-256");
                this.servHash = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new UnsupportedOperationException("Unsupported hash type", e);
            }
            this.state = Handshake.State.ROUND_1;
        }
    }

    private static class Request {
        int id;
    }

    private BleRequestChannelCallbacks callbacks = null;
    private ScheduledExecutorService executor = null;
    private int maxConcurReqCount = DEFAULT_MAX_CONCURRENT_REQUESTS;
    private int defaultReqTimeout = DEFAULT_REQUEST_TIMEOUT;
    private int handshakeTimeout = DEFAULT_HANDSHAKE_TIMEOUT;

    private HashMap<Integer, Request> sentReqs = new HashMap<>();
    private LinkedList<Request> queuedReqs = new LinkedList<>();
    private Handshake handshake = null;
    private ByteBuffer inBuf = ByteBuffer.allocate(1024);
    private State state = State.NEW;
    private int lastReqId = 0;

    public class Builder {
        public Builder setSecret(byte[] secret) {
            BleRequestChannel.this.handshake = new Handshake(secret);
            return this;
        }

        public Builder setCallbacks(BleRequestChannelCallbacks callbacks) {
            if (callbacks == null) {
                throw new IllegalArgumentException("Callbacks instance cannot be null");
            }
            BleRequestChannel.this.callbacks = callbacks;
            return this;
        }

        public Builder setExecutorService(ScheduledExecutorService executor) {
            BleRequestChannel.this.executor = executor;
            return this;
        }

        public Builder setMaxConcurrentRequests(int count) {
            if (count <= 0) {
                throw new IllegalArgumentException("Invalid number of concurrent requests");
            }
            BleRequestChannel.this.maxConcurReqCount = count;
            return this;
        }

        public Builder setHandshakeTimeout(int ms) {
            if (ms <= 0) {
                throw new IllegalArgumentException("Invalid handshake timeout");
            }
            BleRequestChannel.this.handshakeTimeout = ms;
            return this;
        }

        public Builder setDefaultRequestTimeout(int ms) {
            if (ms <= 0) {
                throw new IllegalArgumentException("Invalid request timeout");
            }
            BleRequestChannel.this.defaultReqTimeout = ms;
            return this;
        }

        public BleRequestChannel build() {
            if (BleRequestChannel.this.handshake == null) {
                throw new IllegalStateException("Secret is not set");
            }
            if (BleRequestChannel.this.callbacks == null) {
                throw new IllegalStateException("Callbacks instance is not set");
            }
            return BleRequestChannel.this;
        }

        // Use BleRequestChannel.newBuilder() to create instances of this class
        private Builder() {
        }
    }

    public void open() throws RequestChannelError {
        if (this.state != State.NEW) {
            throw new IllegalStateException("Invalid channel state");
        }
        try {
            this.state = State.OPENING;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try {
                this.handshake.jpake.writeRound1(out);
            } catch (Exception e) {
                throw new RequestChannelError("Failed to serialize handshake message");
            }
            byte[] cliRound1 = out.toByteArray();
            this.handshake.cliHash.update(cliRound1);
            this.handshake.servHash.update(cliRound1);
            this.writeHandshake(cliRound1);
        } catch (Exception e) {
            this.error(new RequestError("Channel error", e));
            throw e;
        }
    }

    public void close() {
        if (this.state == State.CLOSED) {
            return;
        }
        RequestError err = new RequestError("Channel closed");
        this.error(err);
    }

    public void readResponse(ByteBuffer packet) {
    }

    public void readHandshake(ByteBuffer packet) {
        switch (this.handshake.state) {
        case ROUND_1: {
            packet.position(packet.position() + 2);
            byte[] servRound1 = new byte[packet.remaining()];
            packet.get(servRound1);
            ByteArrayInputStream in = new ByteArrayInputStream(servRound1);
            try {
                this.handshake.jpake.readRound1(in);
            } catch (Exception e) {
                throw new RequestChannelError("Failed to parse handshake message", e);
            }
            this.handshake.cliHash.update(servRound1);
            this.handshake.servHash.update(servRound1);
            this.handshake.state = Handshake.State.ROUND_2;
            break;
        }
        case ROUND_2: {
            packet.position(packet.position() + 2);
            byte[] servRound2 = new byte[packet.remaining()];
            packet.get(servRound2);
            ByteArrayInputStream in = new ByteArrayInputStream(servRound2);
            try {
                this.handshake.jpake.readRound2(in);
            } catch (Exception e) {
                throw new RequestChannelError("Failed to parse handshake message", e);
            }
            this.handshake.cliHash.update(servRound2);
            this.handshake.servHash.update(servRound2);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try {
                this.handshake.jpake.writeRound2(out);
            } catch (Exception e) {
                throw new RequestChannelError("Failed to serialize handshake message");
            }
            byte[] cliRound2 = out.toByteArray();
            this.writeHandshake(cliRound2);
            this.handshake.cliHash.update(cliRound2);
            this.handshake.servHash.update(cliRound2);
            this.handshake.secret = this.handshake.jpake.deriveSecret();
            byte[] cliConfirm = genConfirm(this.handshake.secret, EC_JPAKE_CLIENT_ID, EC_JPAKE_SERVER_ID,
                    this.handshake.cliHash.digest());
            this.writeHandshake(cliConfirm);
            this.handshake.servHash.update(cliConfirm);
            this.handshake.state = Handshake.State.CONFIRM;
            break;
        }
        case CONFIRM: {
            packet.position(packet.position() + 2);
            byte[] servConfirm = new byte[packet.remaining()];
            packet.get(servConfirm);
            byte[] expectedConfirm = genConfirm(this.handshake.secret, EC_JPAKE_SERVER_ID, EC_JPAKE_CLIENT_ID,
                    this.handshake.servHash.digest());
            if (!Arrays.equals(servConfirm, expectedConfirm)) {
                throw new RequestChannelError("Confirmation failed");
            }
            this.handshake = null;
            this.state = State.OPEN;
            break;
        }
        }
    }

    public void read(byte[] data) {
        if (this.state != State.OPEN && this.state != State.OPENING) {
            throw new IllegalStateException("Invalid channel state");
        }
        try {
            this.appendToBuf(data);
            for (;;) {
                this.inBuf.mark();
                int payloadLen = this.inBuf.getShort() & 0xffff;
                this.inBuf.reset();
                boolean isResp = (this.state == State.OPEN);
                int packetLen = payloadLen + (isResp ? RESPONSE_PACKET_OVERHEAD : HANDSHAKE_PACKET_OVERHEAD);
                if (this.inBuf.remaining() < packetLen) {
                    break;
                }
                ByteBuffer packet = this.inBuf.slice();
                packet.limit(packetLen);
                if (isResp) {
                    this.readResponse(packet);
                } else {
                    this.readHandshake(packet);
                }
                this.inBuf.position(this.inBuf.position() + packetLen);
                this.compactBuf();
            }
        } catch (Exception e) {
            this.error(new RequestError("Channel error", e));
            throw e;
        }
    }

    public int sendRequest(int type, byte[] data) {
        return 0;
    }

    public State getState() {
        return this.state;
    }

    public static Builder newBuilder() {
        return new BleRequestChannel().new Builder();
    }

    private void writeHandshake(byte[] data) {
        if (data.length > MAX_HANDSHAKE_PAYLOAD_SIZE) {
            throw new RuntimeException("Handshake packet is too long"); // Internal error
        }
        ByteBuffer b = ByteBuffer.allocate(data.length + HANDSHAKE_PACKET_OVERHEAD);
        b.order(ByteOrder.LITTLE_ENDIAN);
        b.putShort((short)data.length);
        b.put(data);
        this.callbacks.onChannelWrite(b.array());
    }

    private void error(RequestError err) {
        if (this.state == State.CLOSED) {
            return;
        }
        for (Request req: sentReqs.values()) {
            this.callbacks.onRequestError(req.id, err);
        }
        sentReqs.clear();
        for (Request req: queuedReqs) {
            this.callbacks.onRequestError(req.id, err);
        }
        queuedReqs.clear();
        this.state = State.CLOSED;
    }

    private void appendToBuf(byte[] data) {
        if (this.inBuf.capacity() - this.inBuf.limit() < data.length) {
            int minNewSize = this.inBuf.remaining() + data.length;
            int newSize = this.inBuf.capacity() * 3 / 2;
            if (newSize < minNewSize) {
                newSize = minNewSize * 3 / 2;
            }
            ByteBuffer buf = ByteBuffer.allocate(newSize);
            buf.order(this.inBuf.order());
            buf.put(this.inBuf);
            buf.limit(buf.position());
            buf.position(0);
        }
        int pos = this.inBuf.position();
        this.inBuf.position(this.inBuf.limit());
        this.inBuf.limit(this.inBuf.limit() + data.length);
        this.inBuf.put(data);
        this.inBuf.position(pos);
    }

    private void compactBuf() {
        this.inBuf.compact();
        this.inBuf.limit(this.inBuf.position());
        this.inBuf.position(0);
    }

    // Use a Builder to create instances of this class
    private BleRequestChannel() {
        this.inBuf.order(ByteOrder.LITTLE_ENDIAN);
        this.inBuf.limit(0);
    }

    private static byte[] genConfirm(byte[] secret, byte[] localId, byte[] remoteId, byte[] packetsHash) {
        MessageDigest keyMd = null;
        try {
            keyMd = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Unsupported hash type", e);
        }
        keyMd.update(secret);
        keyMd.update("JPAKE_KC".getBytes());
        Mac confirmMac = null;
        try {
            SecretKeySpec keySpec = new SecretKeySpec(keyMd.digest(), "HmacSHA256");
            confirmMac = Mac.getInstance("HmacSHA256");
            confirmMac.init(keySpec);
        } catch (Exception e) {
            throw new UnsupportedOperationException("Unsupported hash type", e);
        }
        confirmMac.update("KC_1_U".getBytes());
        confirmMac.update(localId);
        confirmMac.update(remoteId);
        confirmMac.update(packetsHash);
        return confirmMac.doFinal();
    }
}
