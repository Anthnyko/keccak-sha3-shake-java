import java.util.Arrays;

public class TestSHA3SHAKE {

    private static String bytesToHex(byte[] arr) {
        StringBuilder sb = new StringBuilder();
        for (byte b : arr) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            out[i] = (byte)((hi << 4) | lo);
        }
        return out;
    }

    public static void main(String[] args) throws Exception {

        // --- SHA3-256 empty message test ---
        byte[] msgEmpty = new byte[0];
        byte[] sha3_256_empty = SHA3SHAKE.SHA3(256, msgEmpty);
        String got256 = bytesToHex(sha3_256_empty);
        String exp256 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

        System.out.println("SHA3-256(\"\") = " + got256);
        System.out.println("Expected       = " + exp256);
        System.out.println("PASS? " + got256.equals(exp256));
        System.out.println();

        // --- SHA3-512 empty message test ---
        String exp512 =
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6" +
                        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";

        byte[] sha3_512_empty = SHA3SHAKE.SHA3(512, msgEmpty);
        String got512 = bytesToHex(sha3_512_empty);

        System.out.println("SHA3-512(\"\") = " + got512);
        System.out.println("Expected       = " + exp512);
        System.out.println("PASS? " + got512.equals(exp512));
        System.out.println();

        // --- SHAKE128 empty message, 512-bit output ---
        int outBits = 512;
        byte[] shake128_empty = SHA3SHAKE.SHAKE(128, msgEmpty, outBits);
        String gotShake128 = bytesToHex(shake128_empty);
        String expShake128Prefix = "7f9c2ba4e88f827d616045507605853ed73b8093";

        System.out.println("SHAKE128(\"\")[:40 hex] = " + gotShake128.substring(0, 40));
        System.out.println("Expected prefix        = " + expShake128Prefix);
        System.out.println("PASS? " + gotShake128.startsWith(expShake128Prefix));
        System.out.println();

        // --- SHAKE256 empty message, 512-bit output ---
        byte[] shake256_empty = SHA3SHAKE.SHAKE(256, msgEmpty, outBits);
        String gotShake256 = bytesToHex(shake256_empty);
        String expShake256Prefix = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";

        System.out.println("SHAKE256(\"\")[:64 hex] = " + gotShake256.substring(0, 64));
        System.out.println("Expected prefix        = " + expShake256Prefix);
        System.out.println("PASS? " + gotShake256.startsWith(expShake256Prefix));


        SHA3SHAKE sha = new SHA3SHAKE();
        sha.isSHAKE = false;
        sha.init(256);

        sha.absorb("abc".getBytes());

        byte[] digest1 = sha.digest();
        byte[] digest2 = sha.digest();

        System.out.println(Arrays.equals(digest1, digest2));

        System.out.println(bytesToHex(digest1));


    }
}
