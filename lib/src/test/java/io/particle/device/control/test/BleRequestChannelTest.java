package io.particle.device.control.test;

import io.particle.device.control.BleRequestChannel;
import io.particle.device.control.BleRequestChannelCallback;
import io.particle.device.control.RequestError;
import io.particle.test.SecureRandomMock;
import io.particle.test.Util;

import org.junit.Test;
import static org.junit.Assert.*;

class OpenAndSendEchoRequestCallback implements BleRequestChannelCallback {
    private enum State {
        ROUND_1,
        ROUND_2,
        CONFIRM,
        OPEN,
        REQUEST,
        RESPONSE,
        DONE
    }

    private BleRequestChannel channel;
    private State state;

    public OpenAndSendEchoRequestCallback() {
        this.state = State.ROUND_1;
    }

    public void channel(BleRequestChannel channel) {
        this.channel = channel;
    }

    public boolean isDone() {
        return this.state == State.DONE;
    }

    @Override
    public void onChannelOpen() {
        assertEquals(this.state, State.OPEN);
        this.state = State.REQUEST;
    }

    @Override
    public void onChannelWrite(byte[] data) {
        switch (this.state) {
        case ROUND_1: {
            // Client's round 1
            assertArrayEquals(data, Util.fromHex("4a01410405742889bd2518c365cba7fa68437a4046646c6979669a62cd0d2e0f8b666879ef47385b03f28060c47848464935395926f8fe4e6866d06da35162a8863c9d134104b61275f24a18c2b1229b87889ef033ee7cc13e968396cb4355553fbd4da3fe206b5497438dc3059a997b22a9e0ac6d5598b385a5529cda84657b8c009e65a78820f86305132101da9b53e0fbb3b5b823d934fad4fa8294b19fee5fc00345c00c3341041e98e9f367419e8a8574b92bbbd777e6bf9ba85c0ef47afada04d1d4386b1bfac7c6316feb750e1ff73977049c31febb15ba944f544c7b6916ffd580742e54d14104f79d7f6377272667042c9ac64a998eb4e6b1f135b5456ae0b4ce1e77c55513835743779ad381404a65a693f4922ad809a02c3de63bd5bdeef0928524409283af20d4d823e329c00e9439a9427a3b25286a597cb89f2ad314cbe3e12c2ff6a0093e"));
            // Server's round 1
            channel.read(Util.fromHex("4a01410416f3d326ee493e3fc4229c734f3e334a259550c79735d85104aa79d515e7e2d2a7d58fbc44aa406fb7342686d514a355447a7affaf4831834c4be4f7ed62908a4104776afb9762397e50fbead0e7783c38cb0032b12fb79977731cfecbd7587b83ff9aa0ef89eb1ce5d167da243c6e6fe50be73e1c2d31424fd059b6ef231d38b6632094400fde206e4374dcb9ff4ec28e99657b90223b4b04599c7650110d34fab0f74104c5170299344828a78694fa899d4060f8e6382d4c60830d89a30b0a6f267250f32762c4119acb937d15981e079a9aab3c58e765077af6722d7d0eb70040b3be694104a43d0fd37a1a04577db328be1d1bfd22b063ccebd6ba551e7a32863d8b30a0a49b0c615e1a7c080545f4d9dc222ab99abed271a6b856b810fdeebd9a70edf24f201556a6ceda37085f81e253e8e9a968375ae2aa892032ffc99f6feacf891bd1cc"));
            this.state = State.ROUND_2;
            // Server's round 2
            channel.read(Util.fromHex("a8000300174104eca2db704115e302c297c5880b44731930b0b26d149bffc6c1175c48155f668e36b75e356abfda8f13e061b9d7d9c5aaa6094d8e713d642dc80c69c3c4832cc44104983aeaa4fd6c34759d6a0b6ccbf0923f691edb200a5fd406868ff668f51af984788f67a98f0c3c2f88bd98d126246a492c23dc18e7d4a0d10133928a5231011820a4284c9244c2274a5f99385ad5ad28364de71ac2ee88f0f56bf28fc2d6f6f1a0"));
            break;
        }
        case ROUND_2: {
            // Client's round 2
            assertArrayEquals(data, Util.fromHex("a50041044b61e4cac0c3180395033ba820cfc9682f20bb342674373bbb0b87a8f939914e38136d3ec29e21dcdd0307100463b2cf2d94b4ab57b8473998c012cdb90a116141049a55d4b541e0c27c1456f70dedd68dfd46d3e085b3026f51bbf3fc129ac69e414e69b429041607349f52a67e758724d9dcff2798d7876f6bd839e49af3b1be70209e1fb5c74590ec6f2a5841488bd2ad4c82b1cde6e27e45fbe912b59579034512"));
            this.state = State.CONFIRM;
            break;
        }
        case CONFIRM: {
            // Client's confirmation
            assertArrayEquals(data, Util.fromHex("20007b1373b46992c857811bd941e0b985e6cf65a6bc6b99666fa1b12d2ffdd7b11f"));
            this.state = State.OPEN;
            // Server's confirmation
            channel.read(Util.fromHex("2000c609a9e3469284af3e4fd0291df207ccdbd784ec0ad2f25636757c5a94bf6716"));
            break;
        }
        case REQUEST: {
            // Client's request
            assertArrayEquals(data, Util.fromHex("c800f8e7374f6481280c94bc11763c8fe71f85046e1c7310e1d9b084773306999636c64db1551b8c4b1dad624f835ce9bae07a56f376dae696d4fd27cf1619e35e281e4fe0fa88519d82c9072100749d23e41e3a5afe9c5056eb1feac13fdcd5f4ec8b26f43d9300b42033eb517688289409a92d807bd28a354a9ff7c4ddc14ab0e170b2cd334c0aa270c53eb69a71e1b4002bb5d66e434e9b27b317d7a20ca5be88abc243ef6af8c78b2d7e89bc47ee3cc96dab673ae0282a306e073c5fbc69151c8e5b4344ef5277b2eebb635cc38cdc3fd55bee998a9e"));
            this.state = State.RESPONSE;
            // Server's response
            channel.read(Util.fromHex("c8006fe1656108c1db78dcf81e44984793d9e5e73bf150d7141bfa0b3cf75f8e3ba75f1f2a6fba9b09683c252b92cbfd0810149ee2baf86b238b638479c7eec37f44ae7adf2d69d86319fdd7e2eae0015d4fcdb94d2e58a726a8583972e0f54527be644be64513cbe25507aaf825069af7218ab7bb653f30ac09e45f298b58d32a3dce51b3a0ae8906dcd8111d4dd0d8611f94b09c33ba835187b2f5a33a786e8868024581778ccf9dd1b8cbfd7e1439912dd9244c38d8959df12b081ef7b4a3355b8cf7925533e065c464c396ff45a76f6d3a621de1d3a4"));
            break;
        }
        default:
            fail();
            break;
        }
    }

    @Override
    public void onRequestResponse(int requestId, int result, byte[] data) {
        assertEquals(this.state, State.RESPONSE);
        assertEquals(requestId, 41197);
        assertEquals(result, 0);
        assertArrayEquals(data, "cEKwSsDfedIvUPweSBJMlGRc6BKZE60PAMwcjrb2SLeoBEi90pjCEWts9rz3fZVKIcngDGPLoruvgFweiUyGJDMW3F5KBZYuQt0u2rkIL9OKepAj8HnzTUmaLobIKziJhlVWqzehN4CJFmin8CNp1ra2jS8DesAVfCJ0jOPh4F0eCoTNKsCKTddFkcyBRWm2Ojeg558H".getBytes());
        this.state = State.DONE;
    }

    @Override
    public void onRequestError(int requestId, RequestError error) {
        fail();
    }
}

public class BleRequestChannelTest {
    @Test
    public void openAndSendEchoRequest() {
        SecureRandomMock rand = new SecureRandomMock(Util.fromHex(
                // BleRequestChannel()
                "3e86a0ed" +
                // EcJpake#getRound1()
                "437ad5eed6730b21dd74439c69b7204586bb0acf1b185bdf6b297b4eaf321a29" +
                "47e683379435e42f6bb448c80664d0ff95a096930c44dd31312b777717ae2dae" +
                "661f9b710c89e7a3aeedc3f4defdfc77b3207bd4de389eb254b93f5c08d2deab" +
                "080631f61d4279556952d40d31709268384ccd38bebb975030394cc049743f62" +
                // EcJpake#getRound2()
                "f4405fa9e2f5d41df6226c9c8e142786" +
                "23297c9b9c3b4d4318f35b6d0f6cb0c5d9a6f14b628a26005a4750bc51d9e790" +
                // EcJpake#deriveSecret()
                "eb06efb4d3b4f6ef43d0bd34ffeec1ab"));
        OpenAndSendEchoRequestCallback callback = new OpenAndSendEchoRequestCallback();
        BleRequestChannel channel = new BleRequestChannel("CCLVHNT2GWHVJUB".getBytes(), callback,
                BleRequestChannel.DEFAULT_MAX_CONCURRENT_REQUESTS, rand);
        callback.channel(channel);
        channel.open();
        int id = channel.sendRequest(1 /* type */, "cEKwSsDfedIvUPweSBJMlGRc6BKZE60PAMwcjrb2SLeoBEi90pjCEWts9rz3fZVKIcngDGPLoruvgFweiUyGJDMW3F5KBZYuQt0u2rkIL9OKepAj8HnzTUmaLobIKziJhlVWqzehN4CJFmin8CNp1ra2jS8DesAVfCJ0jOPh4F0eCoTNKsCKTddFkcyBRWm2Ojeg558H".getBytes());
        assertEquals(id, 41197);
        assertTrue(callback.isDone());
    }
}
