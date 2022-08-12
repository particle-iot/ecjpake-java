package io.particle.device.control;

import io.particle.crypto.EcJpake;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.InvalidCipherTextException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ThreadLocalRandom;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.Arrays;
import java.util.Iterator;

public class BleRequestChannel {
    public static final int DEFAULT_MAX_CONCURRENT_REQUESTS = 1;

    private static final String HASH_NAME = "SHA-256";
    private static final String MAC_NAME = "HmacSHA256";
    private static final byte[] CLIENT_ID = "client".getBytes();
    private static final byte[] SERVER_ID = "server".getBytes();
    private static final int NONCE_SIZE = 12;
    private static final int TAG_SIZE = 8;

    private static final int REQUEST_PACKET_OVERHEAD = TAG_SIZE + 8;
    private static final int RESPONSE_PACKET_OVERHEAD = TAG_SIZE + 8;
    private static final int HANDSHAKE_PACKET_OVERHEAD = 2;
    private static final int MAX_REQUEST_PAYLOAD_SIZE = 65535;
    private static final int MAX_HANDSHAKE_PAYLOAD_SIZE = 65535;
    private static final int MAX_REQUEST_ID = 65535;

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
    }

    private static class Request {
        int type;
        byte[] data;
    }

    private BleRequestChannelCallbacks callbacks;
    private byte[] preSecret;
    private int maxConcurReqCount;

    private HashSet<Integer> sentReqs;
    private LinkedHashMap<Integer, Request> queuedReqs;
    private CCMBlockCipher cipher;
    private KeyParameter cipherKey;
    private Handshake handshake;
    private ByteBuffer buf;
    private State state;
    private byte[] cliNonce;
    private byte[] servNonce;
    private int lastCliCtr;
    private int lastServCtr;
    private int nextReqId;
    private boolean reading;
    private boolean sending;

    public BleRequestChannel(byte[] secret, BleRequestChannelCallbacks callbacks) {
        this(secret, callbacks, DEFAULT_MAX_CONCURRENT_REQUESTS);
    }

    public BleRequestChannel(byte[] secret, BleRequestChannelCallbacks callbacks, int maxConcurrentRequests) {
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("Secret cannot be empty");
        }
        this.preSecret = secret;
        if (callbacks == null) {
            throw new IllegalArgumentException("Callbacks instance cannot be null");
        }
        this.callbacks = callbacks;
        if (maxConcurrentRequests <= 0) {
            throw new IllegalArgumentException("Invalid number of requests");
        }
        this.maxConcurReqCount = maxConcurrentRequests;
        this.sentReqs = new HashSet<>();
        this.queuedReqs = new LinkedHashMap<>();
        this.buf = ByteBuffer.allocate(0);
        this.buf.order(ByteOrder.LITTLE_ENDIAN);
        this.lastCliCtr = 0;
        this.lastServCtr = 0;
        this.nextReqId = ThreadLocalRandom.current().nextInt(0, MAX_REQUEST_ID + 1);
        this.reading = false;
        this.sending = false;
        this.state = State.NEW;
    }

    public void open() throws RequestChannelError {
        if (this.state != State.NEW) {
            throw new IllegalStateException("Invalid channel state");
        }
        try {
            this.handshake = new Handshake();
            this.handshake.state = Handshake.State.ROUND_1;
            this.handshake.jpake = new EcJpake(EcJpake.Role.CLIENT, this.preSecret);
            this.preSecret = null;
            try {
                this.handshake.cliHash = MessageDigest.getInstance(HASH_NAME);
                this.handshake.servHash = MessageDigest.getInstance(HASH_NAME);
            } catch (NoSuchAlgorithmException e) {
                throw new UnsupportedOperationException("Unsupported hash algorithm", e);
            }
            byte[] cliRound1 = this.handshake.jpake.getRound1();
            this.handshake.cliHash.update(cliRound1);
            this.handshake.servHash.update(cliRound1);
            this.state = State.OPENING;
            this.writeHandshake(cliRound1);
        } catch (Exception e) {
            this.closeWithError(new RequestError("Channel error", e));
            throw e;
        }
    }

    public void close() {
        if (this.state == State.CLOSED) {
            return;
        }
        this.closeWithError(new RequestError("Channel closed"));
    }

    public void read(byte[] data) {
        if (this.state != State.OPEN && this.state != State.OPENING) {
            throw new IllegalStateException("Invalid channel state");
        }
        try {
            this.appendToInputBuf(data);
            if (this.reading) {
                return;
            }
            this.reading = true;
            for (;;) {
                if (this.buf.remaining() < 2) {
                    break;
                }
                this.buf.mark();
                int payloadLen = this.buf.getShort() & 0xffff;
                this.buf.reset();
                boolean isOpen = (this.state == State.OPEN);
                int packetLen = payloadLen + (isOpen ? RESPONSE_PACKET_OVERHEAD : HANDSHAKE_PACKET_OVERHEAD);
                if (this.buf.remaining() < packetLen) {
                    break;
                }
                ByteBuffer packet = this.buf.slice();
                packet.limit(packetLen);
                if (isOpen) {
                    this.readResponse(packet);
                } else {
                    this.readHandshake(packet);
                }
                this.buf.position(this.buf.position() + packetLen);
                this.buf.compact();
                this.buf.limit(this.buf.position());
                this.buf.rewind();
            }
            this.reading = false;
        } catch (Exception e) {
            this.closeWithError(new RequestError("Channel error", e));
            throw e;
        }
    }

    public int sendRequest(int type) {
        return this.sendRequest(type, null);
    }

    public int sendRequest(int type, byte[] data) {
        if (data != null && data.length > MAX_REQUEST_PAYLOAD_SIZE) {
            throw new IllegalArgumentException("Payload data is too long");
        }
        if (this.state != State.OPEN && this.state != State.OPENING) {
            throw new IllegalStateException("Invalid channel state");
        }
        try {
            int reqId = this.nextReqId;
            if (++this.nextReqId > MAX_REQUEST_ID) {
                this.nextReqId = 0;
            }
            Request req = new Request();
            req.type = type;
            req.data = (data != null) ? data : new byte[0];
            this.queuedReqs.put(reqId, req);
            if (this.state == State.OPEN) {
                this.sendNextRequest();
            }
            return reqId;
        } catch (Exception e) {
            this.closeWithError(new RequestError("Channel error", e));
            throw e;
        }
    }

    public boolean cancelRequest(int id) {
        if (this.state != State.OPEN && this.state != State.OPENING) {
            return false;
        }
        if (this.sentReqs.remove(id) || this.queuedReqs.remove(id) != null) {
            this.sendNextRequest();
            return true;
        }
        return false;
    }

    public State state() {
        return this.state;
    }

    private void sendNextRequest() {
        if (this.state != State.OPEN || this.sending) {
            return;
        }
        this.sending = true;
        while (!this.queuedReqs.isEmpty() && this.sentReqs.size() < this.maxConcurReqCount) {
            Iterator<Map.Entry<Integer, Request>> it = this.queuedReqs.entrySet().iterator();
            Map.Entry<Integer, Request> entry = it.next();
            int reqId = entry.getKey();
            Request req = entry.getValue();
            it.remove();
            this.writeRequest(reqId, req.type, req.data);
            this.sentReqs.add(reqId);
        }
        this.sending = false;
    }

    private void readResponse(ByteBuffer packet) {
        byte[] aad = new byte[2];
        packet.get(aad);
        byte[] data = new byte[packet.remaining()];
        packet.get(data);
        byte[] nonce = genNonce(this.servNonce, ++this.lastServCtr, true /* isResp */);
        data = this.runCipher(false /* encrypt */, data, nonce, aad);
        ByteBuffer b = ByteBuffer.wrap(data);
        b.order(ByteOrder.LITTLE_ENDIAN);
        int reqId = b.getShort() & 0xffff;
        if (this.sentReqs.contains(reqId)) {
            int result = b.getInt();
            data = new byte[b.remaining()];
            b.get(data);
            this.sentReqs.remove(reqId);
            this.callbacks.onRequestResponse(reqId, result, data);
            this.sendNextRequest();
        }
    }

    private void writeRequest(int id, int type, byte[] data) {
        ByteBuffer b = ByteBuffer.allocate(data.length + REQUEST_PACKET_OVERHEAD);
        b.order(ByteOrder.LITTLE_ENDIAN);
        b.putShort((short)(data.length & 0xffff));
        b.mark();
        b.putShort((short)(id & 0xffff));
        b.putShort((short)(type & 0xffff));
        b.putShort((short)0); // Reserved
        b.put(data);
        data = b.array();
        byte[] plain = Arrays.copyOfRange(data, 2, data.length - TAG_SIZE);
        byte[] aad = Arrays.copyOfRange(data, 0, 2);
        byte[] nonce = genNonce(this.cliNonce, ++this.lastCliCtr, false /* isResp */);
        data = this.runCipher(true /* encrypt */, plain, nonce, aad);
        b.reset();
        b.put(data);
        this.callbacks.onChannelWrite(b.array());
    }

    private void readHandshake(ByteBuffer packet) {
        switch (this.handshake.state) {
        case ROUND_1: {
            packet.position(packet.position() + 2);
            byte[] servRound1 = new byte[packet.remaining()];
            packet.get(servRound1);
            this.handshake.jpake.readRound1(servRound1);
            this.handshake.cliHash.update(servRound1);
            this.handshake.servHash.update(servRound1);
            this.handshake.state = Handshake.State.ROUND_2;
            break;
        }
        case ROUND_2: {
            packet.position(packet.position() + 2);
            byte[] servRound2 = new byte[packet.remaining()];
            packet.get(servRound2);
            this.handshake.jpake.readRound2(servRound2);
            this.handshake.cliHash.update(servRound2);
            this.handshake.servHash.update(servRound2);
            byte[] cliRound2 = this.handshake.jpake.getRound2();
            this.writeHandshake(cliRound2);
            this.handshake.cliHash.update(cliRound2);
            this.handshake.servHash.update(cliRound2);
            this.handshake.secret = this.handshake.jpake.deriveSecret();
            byte[] cliConfirm = genConfirm(this.handshake.secret, CLIENT_ID, SERVER_ID, this.handshake.cliHash.digest());
            this.writeHandshake(cliConfirm);
            this.handshake.servHash.update(cliConfirm);
            this.handshake.state = Handshake.State.CONFIRM;
            break;
        }
        case CONFIRM: {
            packet.position(packet.position() + 2);
            byte[] servConfirm = new byte[packet.remaining()];
            packet.get(servConfirm);
            byte[] expectedConfirm = genConfirm(this.handshake.secret, SERVER_ID, CLIENT_ID, this.handshake.servHash.digest());
            if (!Arrays.equals(servConfirm, expectedConfirm)) {
                throw new RequestChannelError("Key confirmation failed");
            }
            this.cipher = new CCMBlockCipher(new AESEngine());
            this.cipherKey = new KeyParameter(Arrays.copyOfRange(this.handshake.secret, 0, 16));
            this.cliNonce = Arrays.copyOfRange(this.handshake.secret, 16, 24);
            this.servNonce = Arrays.copyOfRange(this.handshake.secret, 24, 32);
            this.handshake = null;
            this.state = State.OPEN;
            this.callbacks.onChannelOpen();
            break;
        }
        default:
            break;
        }
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

    private byte[] runCipher(boolean encrypt, byte[] in, byte[] nonce, byte[] aad) {
        AEADParameters param = new AEADParameters(this.cipherKey, TAG_SIZE * 8, nonce, aad);
        this.cipher.init(encrypt, param);
        byte[] out;
        try {
            out = this.cipher.processPacket(in, 0, in.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException("Decryption error", e);
        }
        return out;
    }

    private void appendToInputBuf(byte[] data) {
        if (this.buf.capacity() - this.buf.limit() < data.length) {
            int minCapacity = Math.max(this.buf.remaining() + data.length, 128);
            int newCapacity = Math.max(this.buf.capacity() * 3 / 2, minCapacity);
            ByteBuffer newBuf = ByteBuffer.allocate(newCapacity);
            newBuf.order(this.buf.order());
            newBuf.put(this.buf);
            newBuf.limit(newBuf.position());
            newBuf.position(0);
            this.buf = newBuf;
        }
        this.buf.mark();
        this.buf.position(this.buf.limit());
        this.buf.limit(this.buf.limit() + data.length);
        this.buf.put(data);
        this.buf.reset();
    }

    private void closeWithError(RequestError err) {
        if (this.state == State.CLOSED) {
            return;
        }
        for (int reqId: this.sentReqs) {
            this.callbacks.onRequestError(reqId, err);
        }
        this.sentReqs.clear();
        for (int reqId: this.queuedReqs.keySet()) {
            this.callbacks.onRequestError(reqId, err);
        }
        this.queuedReqs.clear();
        this.state = State.CLOSED;
    }

    private static byte[] genNonce(byte[] fixed, int ctr, boolean isResp) {
        ByteBuffer b = ByteBuffer.allocate(fixed.length + 4);
        b.order(ByteOrder.LITTLE_ENDIAN);
        if (isResp) {
            ctr |= 0x80000000;
        }
        b.putInt(ctr);
        b.put(fixed);
        return b.array();
    }

    private static byte[] genConfirm(byte[] secret, byte[] ownId, byte[] peerId, byte[] packetsHash) {
        MessageDigest keyHash = null;
        try {
            keyHash = MessageDigest.getInstance(HASH_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Unsupported hash algorithm", e);
        }
        keyHash.update(secret);
        keyHash.update("JPAKE_KC".getBytes());
        Mac mac = null;
        try {
            SecretKeySpec keySpec = new SecretKeySpec(keyHash.digest(), MAC_NAME);
            mac = Mac.getInstance(MAC_NAME);
            mac.init(keySpec);
        } catch (Exception e) {
            throw new UnsupportedOperationException("Unsupported MAC algorithm", e);
        }
        mac.update("KC_1_U".getBytes());
        mac.update(ownId);
        mac.update(peerId);
        mac.update(packetsHash);
        return mac.doFinal();
    }
}
