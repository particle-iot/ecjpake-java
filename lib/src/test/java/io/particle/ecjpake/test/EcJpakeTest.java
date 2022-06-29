package io.particle.ecjpake.test;

import io.particle.ecjpake.EcJpake;

import java.security.NoSuchAlgorithmException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Test;
import static org.junit.Assert.*;

public class EcJpakeTest {
    @Test public void itWorks() throws IOException {
        byte[] secret = "passw0rd".getBytes();
        EcJpake cli = new EcJpake(EcJpake.Role.CLIENT, secret);
        EcJpake serv = new EcJpake(EcJpake.Role.SERVER, secret);
        ByteArrayOutputStream cliRound1 = new ByteArrayOutputStream();
        cli.writeRound1(cliRound1);
        serv.readRound1(new ByteArrayInputStream(cliRound1.toByteArray()));
    }
}
