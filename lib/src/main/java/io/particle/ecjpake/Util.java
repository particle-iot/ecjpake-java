package io.particle.ecjpake;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.io.EOFException;

public class Util {
    public static int readUint8(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) {
            throw new EOFException("Unexpected end of stream");
        }
        return b;
    }

    public static void writeUint8(OutputStream out, int val) throws IOException {
        out.write(val);
    }

    public static int readUint16Le(InputStream in) throws IOException {
        byte[] b = readAll(in, 2);
        return (int)(b[0] & 0xff) |
                ((int)(b[1] & 0xff) << 8);
    }

    public static void writeUint16Le(OutputStream out, int val) throws IOException {
        byte[] b = new byte[2];
        b[0] = (byte)(val & 0xff);
        b[1] = (byte)((val >>> 8) & 0xff);
        out.write(b);
    }

    public static int readUint16Be(InputStream in) throws IOException {
        byte[] b = readAll(in, 2);
        return ((int)(b[0] & 0xff) << 8) |
                (int)(b[1] & 0xff);
    }

    public static void writeUint16Be(OutputStream out, int val) throws IOException {
        byte[] b = new byte[2];
        b[0] = (byte)((val >>> 8) & 0xff);
        b[1] = (byte)(val & 0xff);
        out.write(b);
    }

    public static long readUint32Le(InputStream in) throws IOException {
        byte[] b = readAll(in, 4);
        return (long)(b[0] & 0xff) |
                ((long)(b[1] & 0xff) << 8) |
                ((long)(b[2] & 0xff) << 16) |
                ((long)(b[3] & 0xff) << 24);
    }

    public static void writeUint32Le(OutputStream out, long val) throws IOException {
        byte[] b = new byte[4];
        b[0] = (byte)(val & 0xff);
        b[1] = (byte)((val >>> 8) & 0xff);
        b[2] = (byte)((val >>> 16) & 0xff);
        b[3] = (byte)((val >>> 24) & 0xff);
        out.write(b);
    }

    public static long readUint32Be(InputStream in) throws IOException {
        byte[] b = readAll(in, 4);
        return ((long)(b[0] & 0xff) << 24) |
                ((long)(b[1] & 0xff) << 16) |
                ((long)(b[2] & 0xff) << 8) |
                (long)(b[3] & 0xff);
    }

    public static void writeUint32Be(OutputStream out, long val) throws IOException {
        byte[] b = new byte[4];
        b[0] = (byte)((val >>> 24) & 0xff);
        b[1] = (byte)((val >>> 16) & 0xff);
        b[2] = (byte)((val >>> 8) & 0xff);
        b[3] = (byte)(val & 0xff);
        out.write(b);
    }

    public static byte[] readAll(InputStream in, int len) throws IOException {
        byte[] b = new byte[len];
        int offs = 0;
        while (offs < len) {
            int r = in.read(b, offs, len - offs);
            if (r < 0) {
                throw new EOFException("Unexpected end of stream");
            }
            offs += r;
        }
        return b;
    }
}
