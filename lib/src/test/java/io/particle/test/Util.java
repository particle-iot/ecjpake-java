package io.particle.test;

public class Util {
    public static String toHex(byte[] bytes) {
        char[] c = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; ++i) {
            c[i * 2] = Character.forDigit((bytes[i] >>> 4) & 0x0f, 16);
            c[i * 2 + 1] = Character.forDigit(bytes[i] & 0x0f, 16);
        }
        return new String(c);
    }

    public static byte[] fromHex(String hex) {
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            int h = Character.digit(hex.charAt(i), 16);
            int l = Character.digit(hex.charAt(i + 1), 16);
            b[i / 2] = (byte)((h << 4) | l);
        }
        return b;
    }
}
