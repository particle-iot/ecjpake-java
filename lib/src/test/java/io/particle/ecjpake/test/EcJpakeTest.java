package io.particle.ecjpake.test;

import io.particle.ecjpake.EcJpake;

import java.security.SecureRandom;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.Random;

import org.junit.Test;
import static org.junit.Assert.*;

class Util {
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

class SecureRandomMock extends SecureRandom {
    private byte[] bytes;
    private int offs;

    SecureRandomMock(String hex) {
        this.bytes = Util.fromHex(hex);
        this.offs = 0;
    }

    public void nextBytes(byte[] bytes) {
        assertTrue(this.bytes.length - this.offs >= bytes.length);
        System.arraycopy(this.bytes, this.offs, bytes, 0, bytes.length);
        this.offs += bytes.length;
    }
}

public class EcJpakeTest {
    @Test
    public void clientRole() throws IOException {
        SecureRandomMock rand = new SecureRandomMock(
            // writeRound1()
            "0bb1b515aebb230d9d16ec3702d92738dc9cd0819bf37787c456fbe39c6bcacd" +
            "2613f01a23a6e679b97ba9ec5d4be5f2dbf14bbbb9ea7b9f6651d96ef4e31b68" +
            "69b1439020883249904ceb5b4a15c40e34176df0ff8bc27029da4147665dcb59" +
            "10873ba39ebbeacb24ab2695fcc35e14bca6e512bf42f08b8dd838bde922f847" +
            // writeRound2()
            "455d8e81bee36509d0f77860a0641312" +
            "e14648731067823471832c9f3dc9e48275f1041b0332f5447cad007341a5e3c3" +
            // deriveSecret()
            "fc55f787a26b3f5619c891a3cd34907b"
        );
        EcJpake cli = new EcJpake(EcJpake.Role.CLIENT, "passw0rd".getBytes(), rand);
        ByteArrayOutputStream cliRound1 = new ByteArrayOutputStream();
        cli.writeRound1(cliRound1);
        assertEquals(Util.toHex(cliRound1.toByteArray()), "4104e92f1a97685b86ea2e8a583724095e355955d1356942c2fa7a0da21f148690052607421562f9771fbcf70fdc33056b2f2596145d8c5cd7be986259e2918d9f554104854faebe27e2f81652f0e71b38410d704fc521965bd40005fa47de22d7de67c2ba301fe248f63b954891e5ba9237c4dace174b022dcc6d55cc977115e0e5e24a2062080ced0ce4c03ca7fb9c80e1374939956623bc951905ac6ed5c6a96ea647c34104580e59d4e2377620a0e2003a22cf5b603165676e48de7095c21f8c76afdef847bc976aa1f58ee050c757f9ccc2af19142a15714a27268886fc50ddf0f8b4573e41046b1d85ca2a6bf3e956269bac6529856ab73089e1522eba11b2b16f2e50908cd6ee7bb6b1f7ecefc424bebe177039e9e2c98da07c7f521388789d5bb37dc2830e209967d2ec8e533bb526645218a376bb3d318103e0aef96c300f30986ab3d0e027");
        ByteArrayInputStream servRound1 = new ByteArrayInputStream(Util.fromHex("4104e7c5d0684bb95148e935d86377befafeb346036808c8ce70f295ba471bafffeef40c462dd49716f13d2ff82f4365d4429d9280caf443dcd0ec79161b0d9ce4cd4104a3b138f08ac33bd583035bec94575073245eb08d7b3aebfb948d139fb8504b67167a9c6ff8dfca50787f5a3e31ed8ddb4af5d717456aa6f3ac8ddbbc9d1a2cba20459cdfbcaae4e8b1017df914f01848eb40149188a3cfc2a988e03d794df6ba1e41040f825be5af5c808c38e0e8878751b07d4bddd372df34a1c64ffeb5a1e8b97fad413c18bd62a55b02fad86b1cef68b6cce71daf3c932f3bf15c5e57dca9dd15b34104d057ea7f55f38a200966ff4ac8fddc1fd8a6021e6ee2f50739e61c6bfca0bcb28b92b964ca24f846327695d654ba1f363cbf8b9ba67b12c61d4c58e34e2176f4201e77da3bb44e301aac88dc3749ff33d1f78ce1a73afc7de414e584bca28c37ab"));
        cli.readRound1(servRound1);
        ByteArrayOutputStream cliRound2 = new ByteArrayOutputStream();
        cli.writeRound2(cliRound2);
        assertEquals(Util.toHex(cliRound2.toByteArray()), "410401cbf7400850b52ab66bc0633de63a83b2a0e8b679451bca80573a5ef5a4116f36c7ef60efae1a46df7988d63c58136adadcc52e6e1cec0641c99d494523d15c41040fbeb1bc502d7017aa8d15e20cc43f89c46270c4a3a101cb5cb7ea9b2075ad10753dd1a327f9bdf91121d5da5c8c3e1827fcd21951f9dd944faffdf6688fcf1120e636ca18769e80923b24d4636191aac2a7573d9a0c3898e690f735425d8702fd");
        ByteArrayInputStream servRound2 = new ByteArrayInputStream(Util.fromHex("0300174104a674d165d4b727d76954b810d90c8c549b38bacf9b322d32f8f5ed5d2bd00b0a93326843b9955024b84eb22c320d36350caa57ad4a0744e322d6dc98cec8635b4104474737716644c4813db988da1de8284ac59cc18f9e172da43db80e9e4ef70eae998857526e53a99156d4e137c1cdd3ab1033d343dda08c581085a71fc6478c4120c52706456c50213629b91a003078544dc6da201caed7d4f9a7189fa1e537259f"));
        cli.readRound2(servRound2);
        byte[] secret = cli.deriveSecret();
        assertEquals(Util.toHex(secret), "e734344901549417f6243f8e4a712f87ae9409476f8d022c347ff690249683aa");
    }

    @Test
    public void serverRole() throws IOException {
        SecureRandomMock rand = new SecureRandomMock(
            // writeRound1()
            "32984ad87e029ae0ed4c4dd40a66c2ae10f5394fbe5c627249ff9e75ce927800" +
            "da88d43fe3d5974edc2478f5028668fbeb57f9bf80478a3549050f1316087470" +
            "82dcdc69b214804d58282dc0eba0e3574f1ed8edfca95850008b6804a9c4b115" +
            "097e3e126cd4e560cb2014413908150616cc8b4ab1122f4a48825261744d380c" +
            // writeRound2()
            "ba38ce0fed6be44207a1c068c7fdb674" +
            "1fb9267a9d067725e9f8712c7dbd638948a075305dde53a544378d96b3a4da3c" +
            // deriveSecret()
            "f63b548a1e1608733c24592938482567"
        );
        EcJpake serv = new EcJpake(EcJpake.Role.SERVER, "passw0rd".getBytes(), rand);
        ByteArrayInputStream cliRound1 = new ByteArrayInputStream(Util.fromHex("41043953d78ce3ea08923167a79516ab77ae8844386c7cf10737f080a20fadb87346364caac7f91ea1e34069382a251ddb64b228099e7f7e786519840c9344f16044410414e78d8a8c9965c80d68b5d89bf3794efa7021898b4ff1e572e04c4076bf0db49177a21cbc27fa214887cb2790cd325c905c28f7fa05a323419cd56d0d7a28c920656b1f4ff79a49ea2f4257e29f7254dcf0071d68b467a1adea2eedb4c32c1d46410427a71d26c81572d25ee7d41cf5863d58fbba1d1c63be4fb341b95845078d3dcc6d5a79fd063204e5ed6ea1d6e500f0f4d647567c6eb2c4725ea23bc53adb269c41048bfd8a1bc46b372a8f74b09bee4519c4d800806eb3be98f29cce85beaaf0a811bb552bf0eaaef0e9c6b8d1ad134b254ac5ab2ac56b4a775d3222486521f65eb52031d8cfda0e47f85e8670b1266728c50985bb11ba096b9354d64c6ed055a2da05"));
        serv.readRound1(cliRound1);
        ByteArrayOutputStream servRound1 = new ByteArrayOutputStream();
        serv.writeRound1(servRound1);
        assertEquals(Util.toHex(servRound1.toByteArray()), "4104a934b89acb61d72d06d6063582fc4559e5739814f330c46f1e411b2bf719c2fb64d52e7a4521c5f7105c5deb57009548f7c64d84dd3cbb3ba0be947c6e0084f04104f18ca092e55e53abdb33b3f1c0ac621e511bd7d9371ad87c1a66fdb6462ec7bbd32e2de6c9f67ca0da40f980ebc4b9560abe50bf7badd5b8d1561f5840540aa1202547660f3ef937619020c4819903f90a439473ea0dfea22d9bb73423b87a8cc641043c9c9f482a84c5b6d3bd653a12b9af0f0abfaae327047b4fc45958f3eb7009465d6b5738238ce386d048c177c88bab6e7b512ebec8f0a05bfdfb4f6f898dc2b4410435344844e18529fae9a53685ca4c26fd80a8048b56f0c306b8d7cbb80423e7858813cd9e93b07576028abaa3127aaf01a8ce477b4666dff02e27bdfd52b21a8a202e729d0084b30e20fdbe9334e0213dd590bd6ca083dca12dadc1c9add9b58e74");
        ByteArrayInputStream cliRound2 = new ByteArrayInputStream(Util.fromHex("41045bd2bda65ca8471594947bd894a960727cf3b574d77cc3f469191b4e122a5ddab69a1d7e7f9d77206423cc213c71c9a603a6b7f4222ef6ec64b6e8e7d0b1c99d41043c05fbb91b28225907ce92689a7bda38e6db7718ca4d2da204827ae2d58d3a7f0a0ab1279ae4afa929935fe1c2ef6e712e78563d6e12f9d6df52db092f8fa109204f981d9a5e6feb8b878e0e28fd15271bcb7858d69c1cabee2739e474657febe0"));
        serv.readRound2(cliRound2);
        ByteArrayOutputStream servRound2 = new ByteArrayOutputStream();
        serv.writeRound2(servRound2);
        assertEquals(Util.toHex(servRound2.toByteArray()), "0300174104763e0ba7b6aa7e70b6a213ab8bd8ce64521b0a7a60e52dbb7c1c233272e437a752533d3d92456576b04423937e383daef670707f7614ea2a8f91265c24e8575841043326978847ee2427fcce7f370f7654108899d6960007f269cec0c6e38affa8fafbf6272d14d2057a46c3cea7738714f0d4c0f235cc5734fde874bb1aa83b348620eb612383f7577a231a6a61a4cc1183bb950a24ef54fb823f8ffb6f64ab76c5ad");
        byte[] secret = serv.deriveSecret();
        assertEquals(Util.toHex(secret), "245f98ed9e8951671ebf7e672c200342b213230f447c45d0fde9e98bb53a750b");
    }

    @Test
    public void selfTest() throws IOException {
        Random rand = new Random();
        SecureRandom secRand = new SecureRandom();
        for (int i = 0; i < 1000; ++i) {
            int pwdLen = rand.nextInt(100) + 1;
            byte[] pwd = new byte[pwdLen];
            secRand.nextBytes(pwd);
            EcJpake cli = new EcJpake(EcJpake.Role.CLIENT, pwd);
            EcJpake serv = new EcJpake(EcJpake.Role.SERVER, pwd);
            ByteArrayOutputStream cliRound1 = new ByteArrayOutputStream();
            cli.writeRound1(cliRound1);
            serv.readRound1(new ByteArrayInputStream(cliRound1.toByteArray()));
            ByteArrayOutputStream servRound1 = new ByteArrayOutputStream();
            serv.writeRound1(servRound1);
            cli.readRound1(new ByteArrayInputStream(servRound1.toByteArray()));
            ByteArrayOutputStream cliRound2 = new ByteArrayOutputStream();
            cli.writeRound2(cliRound2);
            serv.readRound2(new ByteArrayInputStream(cliRound2.toByteArray()));
            ByteArrayOutputStream servRound2 = new ByteArrayOutputStream();
            serv.writeRound2(servRound2);
            cli.readRound2(new ByteArrayInputStream(servRound2.toByteArray()));
            byte[] cliSecret = cli.deriveSecret();
            byte[] servSecret = serv.deriveSecret();
            assertArrayEquals(cliSecret, servSecret);
        }
    }

    @Test
    public void threePass() throws IOException {
        EcJpake cli = new EcJpake(EcJpake.Role.CLIENT, "passw0rd".getBytes());
        EcJpake serv = new EcJpake(EcJpake.Role.SERVER, "passw0rd".getBytes());
        ByteArrayOutputStream cliRound1 = new ByteArrayOutputStream();
        cli.writeRound1(cliRound1);
        serv.readRound1(new ByteArrayInputStream(cliRound1.toByteArray()));
        ByteArrayOutputStream servRound1 = new ByteArrayOutputStream();
        serv.writeRound1(servRound1);
        ByteArrayOutputStream servRound2 = new ByteArrayOutputStream();
        serv.writeRound2(servRound2);
        cli.readRound1(new ByteArrayInputStream(servRound1.toByteArray()));
        cli.readRound2(new ByteArrayInputStream(servRound2.toByteArray()));
        byte[] cliSecret = cli.deriveSecret();
        ByteArrayOutputStream cliRound2 = new ByteArrayOutputStream();
        cli.writeRound2(cliRound2);
        serv.readRound2(new ByteArrayInputStream(cliRound2.toByteArray()));
        byte[] servSecret = serv.deriveSecret();
        assertArrayEquals(cliSecret, servSecret);
    }
}
