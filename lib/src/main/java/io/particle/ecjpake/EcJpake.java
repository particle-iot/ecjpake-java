// This code is based on the implementation of EC J-PAKE from mbed TLS

/*
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.particle.ecjpake;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

public class EcJpake {
    public enum Role {
        CLIENT,
        SERVER
    }

    private class KkppRead {
        public ECPoint Xa;
        public ECPoint Xb;

        KkppRead(ECPoint Xa, ECPoint Xb) {
            this.Xa = Xa;
            this.Xb = Xb;
        }
    }

    private class KkppWrite {
        public BigInteger xm1;
        public ECPoint Xa;
        public BigInteger xm2;
        public ECPoint Xb;

        KkppWrite(BigInteger xm1, ECPoint Xa, BigInteger xm2, ECPoint Xb) {
            this.xm1 = xm1;
            this.Xa = Xa;
            this.xm2 = xm2;
            this.Xb = Xb;
        }
    }

    private class KkpRead {
        public ECPoint X;

        KkpRead(ECPoint X) {
            this.X = X;
        }
    }

    private class KkpWrite {
        public BigInteger x;
        public ECPoint X;

        KkpWrite(BigInteger x, ECPoint X) {
            this.x = x;
            this.X = X;
        }
    }

    private class KeyPair {
        public BigInteger priv;
        public ECPoint pub;

        KeyPair(BigInteger priv, ECPoint pub) {
            this.priv = priv;
            this.pub = pub;
        }
    }

    private BigInteger xm1;
    private ECPoint Xm1;
    private BigInteger xm2;
    private ECPoint Xm2;
    private ECPoint Xp1;
    private ECPoint Xp2;
    private ECPoint Xp;
    private BigInteger s;

    private byte[] round1;
    private byte[] round2;
    private byte[] secret;

    private Role role;
    private ECParameterSpec ec;
    private MessageDigest hash;
    private SecureRandom rand;

    private static final String CURVE_NAME = "P-256";
    private static final int CURVE_ID = 23; // RFC 4492, 5.1.1
    private static final String HASH_NAME = "SHA-256";
    private static final byte[] CLIENT_ID = "client".getBytes();
    private static final byte[] SERVER_ID = "server".getBytes();

    public EcJpake(Role role, byte[] secret) {
        this(role, secret, new SecureRandom());
    }

    public EcJpake(Role role, byte[] secret, SecureRandom random) {
        this.ec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        if (this.ec == null) {
            throw new UnsupportedOperationException("Unsupported curve type");
        }
        try {
            this.hash = MessageDigest.getInstance(HASH_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Unsupported hash type", e);
        }
        this.rand = random;
        this.role = role;
        this.s = new BigInteger(1, secret);
        this.xm1 = null;
        this.Xm1 = null;
        this.xm2 = null;
        this.Xm2 = null;
        this.Xp1 = null;
        this.Xp2 = null;
        this.Xp = null;
        this.round1 = null;
        this.round2 = null;
        this.secret = null;
    }

    public void readRound1(InputStream in) throws IOException {
        if (this.Xp1 != null || this.Xp2 != null) {
            throw new IllegalStateException("Invalid protocol state");
        }
        KkppRead kkpp = this.readKkpp(in, this.ec.getG(), this.remoteId());
        this.Xp1 = kkpp.Xa;
        this.Xp2 = kkpp.Xb;
    }

    public void writeRound1(OutputStream out) throws IOException {
        if (this.round1 == null) {
            ByteArrayOutputStream out2 = new ByteArrayOutputStream();
            KkppWrite kkpp = this.writeKkpp(out2, this.ec.getG(), this.localId());
            this.xm1 = kkpp.xm1;
            this.Xm1 = kkpp.Xa;
            this.xm2 = kkpp.xm2;
            this.Xm2 = kkpp.Xb;
            this.round1 = out2.toByteArray();
        }
        out.write(this.round1);
    }

    public void readRound2(InputStream in) throws IOException {
        if (this.Xp != null || this.Xm1 == null || this.Xm2 == null || this.Xp1 == null) {
            throw new IllegalStateException("Invalid protocol state");
        }
        if (this.role == Role.CLIENT) {
            this.readCurveId(in);
        }
        ECPoint G = this.Xm1.add(this.Xm2).add(this.Xp1);
        KkpRead kkp = this.readKkp(in, G, this.remoteId());
        this.Xp = kkp.X;
    }

    public void writeRound2(OutputStream out) throws IOException {
        if (this.round2 == null) {
            if (this.Xp1 == null || this.Xp2 == null || this.Xm1 == null || this.xm2 == null) {
                throw new IllegalStateException("Invalid protocol state");
            }
            ByteArrayOutputStream out2 = new ByteArrayOutputStream();
            ECPoint G = this.Xp1.add(this.Xp2).add(this.Xm1);
            BigInteger xm = this.mulSecret(this.xm2, this.s, false /* negate */);
            ECPoint Xm = G.multiply(xm);
            if (this.role == Role.SERVER) {
                this.writeCurveId(out2);
            }
            this.writePoint(out2, Xm);
            this.writeZkp(out2, G, xm, Xm, this.localId());
            this.round2 = out2.toByteArray();
        }
        out.write(this.round2);
    }

    public byte[] deriveSecret() {
        if (this.secret == null) {
            if (this.Xp == null || this.Xp2 == null || this.xm2 == null) {
                throw new IllegalStateException("Invalid protocol state");
            }
            BigInteger xm2s = this.mulSecret(this.xm2, this.s, true /* negate */);
            ECPoint K = this.Xp.add(this.Xp2.multiply(xm2s)).multiply(this.xm2);
            this.secret = this.hash.digest(BigIntegers.asUnsignedByteArray(K.normalize().getXCoord().toBigInteger()));
        }
        return this.secret;
    }

    private KkppRead readKkpp(InputStream in, ECPoint G, byte[] id) throws IOException {
        KkpRead kkp = this.readKkp(in, G, id);
        ECPoint Xa = kkp.X;
        kkp = this.readKkp(in, G, id);
        ECPoint Xb = kkp.X;
        return new KkppRead(Xa, Xb);
    }

    private KkppWrite writeKkpp(OutputStream out, ECPoint G, byte[] id) throws IOException {
        KkpWrite kkp = this.writeKkp(out, G, id);
        BigInteger xm1 = kkp.x;
        ECPoint Xa = kkp.X;
        kkp = this.writeKkp(out, G, id);
        BigInteger xm2 = kkp.x;
        ECPoint Xb = kkp.X;
        return new KkppWrite(xm1, Xa, xm2, Xb);
    }

    private KkpRead readKkp(InputStream in, ECPoint G, byte[] id) throws IOException {
        ECPoint X = this.readPoint(in);
        this.readZkp(in, G, X, id);
        return new KkpRead(X);
    }

    private KkpWrite writeKkp(OutputStream out, ECPoint G, byte[] id) throws IOException {
        KeyPair kp = this.genKeyPair(G);
        BigInteger x = kp.priv;
        ECPoint X = kp.pub;
        this.writePoint(out, X);
        this.writeZkp(out, G, x, X, id);
        return new KkpWrite(x, X);
    }

    private void readZkp(InputStream in, ECPoint G, ECPoint X, byte[] id) throws IOException {
        ECPoint V = this.readPoint(in);
        BigInteger r = this.readNum(in);
        BigInteger h = this.zkpHash(G, V, X, id);
        ECPoint VV = G.multiply(r).add(X.multiply(h.mod(this.ec.getN())));
        if (!VV.equals(V)) {
            throw new RuntimeException("Validation failed");
        }
    }

    private void writeZkp(OutputStream out, ECPoint G, BigInteger x, ECPoint X, byte[] id) throws IOException {
        KeyPair kp = this.genKeyPair(G);
        BigInteger v = kp.priv;
        ECPoint V = kp.pub;
        BigInteger h = this.zkpHash(G, V, X, id);
        BigInteger r = v.subtract(x.multiply(h)).mod(this.ec.getN());
        this.writePoint(out, V);
        this.writeNum(out, r);
    }

    private ECPoint readPoint(InputStream in) throws IOException {
        int len = this.readByte(in);
        byte[] encoded = this.read(in, len);
        return this.ec.getCurve().decodePoint(encoded);
    }

    private void writePoint(OutputStream out, ECPoint point) throws IOException {
        byte[] encoded = point.getEncoded(false /* compressed */);
        if (encoded.length > 255) {
            throw new RuntimeException("Encoded ECPoint is too long");
        }
        out.write(encoded.length);
        out.write(encoded);
    }

    private void writeLenPoint(OutputStream out, ECPoint point) throws IOException {
        byte[] encoded = point.getEncoded(false /* compressed */);
        this.writeUint32(out, encoded.length);
        out.write(encoded);
    }

    private BigInteger readNum(InputStream in) throws IOException {
        int len = this.readByte(in);
        byte[] encoded = this.read(in, len);
        return new BigInteger(1, encoded);
    }

    private void writeNum(OutputStream out, BigInteger val) throws IOException {
        byte[] encoded = BigIntegers.asUnsignedByteArray(val);
        if (encoded.length > 255) {
            throw new RuntimeException("Encoded BigInteger is too long");
        }
        out.write(encoded.length);
        out.write(encoded);
    }

    private void readCurveId(InputStream in) throws IOException {
        int type = this.readByte(in);
        if (type != 3) { // ECCurveType.named_curve
            throw new RuntimeException("Invalid message");
        }
        int id = this.readUint16(in);
        if (id != CURVE_ID) {
            throw new RuntimeException("Unexpected curve type");
        }
    }

    private void writeCurveId(OutputStream out) throws IOException {
        out.write(3); // ECCurveType.named_curve
        this.writeUint16(out, CURVE_ID);
    }

    private void writeUint32(OutputStream out, int val) throws IOException {
        byte[] b = new byte[4];
        b[0] = (byte)((val >>> 24) & 0xff);
        b[1] = (byte)((val >>> 16) & 0xff);
        b[2] = (byte)((val >>> 8) & 0xff);
        b[3] = (byte)(val & 0xff);
        out.write(b);
    }

    private int readUint16(InputStream in) throws IOException {
        byte[] b = this.read(in, 2);
        return ((int)b[0] << 8) | (int)b[1];
    }

    private void writeUint16(OutputStream out, int val) throws IOException {
        byte[] b = new byte[2];
        b[0] = (byte)((val >>> 8) & 0xff);
        b[1] = (byte)(val & 0xff);
        out.write(b);
    }

    private int readByte(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) {
            throw new RuntimeException("Unexpected end of stream");
        }
        return b;
    }

    private byte[] read(InputStream in, int bytes) throws IOException {
        byte[] b = new byte[bytes];
        int offs = 0;
        while (offs < bytes) {
            int r = in.read(b, offs, bytes - offs);
            if (r < 0) {
                throw new RuntimeException("Unexpected end of stream");
            }
            offs += r;
        }
        return b;
    }

    private BigInteger zkpHash(ECPoint G, ECPoint V, ECPoint X, byte[] id) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        this.writeLenPoint(out, G);
        this.writeLenPoint(out, V);
        this.writeLenPoint(out, X);
        this.writeUint32(out, id.length);
        out.write(id);
        byte[] hash = this.hash.digest(out.toByteArray());
        BigInteger h = new BigInteger(1, hash);
        return h.mod(this.ec.getN());
    }

    private BigInteger mulSecret(BigInteger X, BigInteger S, boolean negate) {
        BigInteger b = new BigInteger(1, this.randBytes(16));
        b = b.multiply(this.ec.getN()).add(S);
        BigInteger R = X.multiply(b);
        if (negate) {
            R = R.negate();
        }
        return R.mod(this.ec.getN());
    }

    private KeyPair genKeyPair(ECPoint G) {
        BigInteger priv = BigIntegers.createRandomInRange(BigInteger.ONE, this.ec.getN().subtract(BigInteger.ONE), this.rand);
        ECPoint pub = G.multiply(priv);
        return new KeyPair(priv, pub);
    }

    private byte[] randBytes(int bytes) {
        byte[] b = new byte[bytes];
        this.rand.nextBytes(b);
        return b;
    }

    private byte[] localId() {
        return (this.role == Role.CLIENT) ? CLIENT_ID : SERVER_ID;
    }

    private byte[] remoteId() {
        return (this.role == Role.CLIENT) ? SERVER_ID : CLIENT_ID;
    }
}
