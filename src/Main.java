import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class Main {

    public static void main(String[] args) throws Exception {

        if (args.length < 1) {
            System.out.println("Usage:");
            System.out.println("  hash <sha3-224|sha3-256|sha3-384|sha3-512> <inputFile>");
            System.out.println("  mac <shake128|shake256> <tagBytes> <inputFile> <passphrase>");
            System.out.println("  enc <inputFile> <passphrase> <outputFile>");
            System.out.println("  dec <inputFile> <passphrase> <outputFile>");
            return;
        }

        String mode = args[0];

        switch (mode.toLowerCase()) {

            case "hash":
                String hashType = args[1];
                String hashFile = args[2];
                doHash(hashType, hashFile);
                break;

            case "mac":
                String macType = args[1];
                int tagBytes = Integer.parseInt(args[2]);
                String macFile = args[3];
                String macPass = args[4];
                doMAC(macType, tagBytes, macFile, macPass);
                break;

            case "enc":
                String encInput = args[1];
                String encPass = args[2];
                String encOutput = args[3];
                doEncrypt(encInput, encPass, encOutput);
                break;

            case "dec":
                String decInput = args[1];
                String decPass = args[2];
                String decOutput = args[3];
                doDecrypt(decInput, decPass, decOutput);
                break;

            default:
                System.out.println("Unknown mode: " + mode);
        }
    }

    private static void doHash(String type, String file) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(file));

        int suffix;
        switch (type.toLowerCase()) {
            case "sha3-224": suffix = 224; break;
            case "sha3-256": suffix = 256; break;
            case "sha3-384": suffix = 384; break;
            case "sha3-512": suffix = 512; break;
            default:
                throw new IllegalArgumentException("Invalid SHA-3 type: " + type);
        }

        byte[] hash = SHA3SHAKE.SHA3(suffix, data);
        System.out.println(bytesToHex(hash));
    }

    private static void doMAC(String type, int tagBytes, String file, String passphrase) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(file));
        byte[] pass = passphrase.getBytes("UTF-8");

        int suffix = type.equalsIgnoreCase("shake128") ? 128 : 256;

        SHA3SHAKE shake = new SHA3SHAKE();
        shake.isSHAKE = true;
        shake.init(suffix);
        shake.absorb(pass);
        shake.absorb(data);

        byte[] tag = shake.squeeze(tagBytes);
        System.out.println(bytesToHex(tag));
    }

    private static void doEncrypt(String inputFile, String passphrase, String outputFile) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(inputFile));
        byte[] pass = passphrase.getBytes("UTF-8");

        byte[] key = SHA3SHAKE.SHAKE(128, pass, 128);

        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);

        SHA3SHAKE shake = new SHA3SHAKE();
        shake.isSHAKE = true;
        shake.init(128);
        shake.absorb(nonce);
        shake.absorb(key);

        byte[] keystream = shake.squeeze(data.length);

        byte[] ciphertext = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            ciphertext[i] = (byte)(data[i] ^ keystream[i]);
        }

        byte[] out = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(ciphertext, 0, out, nonce.length, ciphertext.length);

        Files.write(Paths.get(outputFile), out);
    }

    private static void doDecrypt(String inputFile, String passphrase, String outputFile) throws Exception {
        byte[] cryptogram = Files.readAllBytes(Paths.get(inputFile));
        byte[] pass = passphrase.getBytes("UTF-8");


        byte[] nonce = new byte[16];
        System.arraycopy(cryptogram, 0, nonce, 0, 16);

        byte[] ciphertext = new byte[cryptogram.length - 16];
        System.arraycopy(cryptogram, 16, ciphertext, 0, ciphertext.length);

        byte[] key = SHA3SHAKE.SHAKE(128, pass, 128);

        SHA3SHAKE shake = new SHA3SHAKE();
        shake.isSHAKE = true;
        shake.init(128);
        shake.absorb(nonce);
        shake.absorb(key);

        byte[] keystream = shake.squeeze(ciphertext.length);

        // XOR to decrypt
        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            plaintext[i] = (byte)(ciphertext[i] ^ keystream[i]);
        }

        Files.write(Paths.get(outputFile), plaintext);
    }

    private static String bytesToHex(byte[] arr) {
        StringBuilder sb = new StringBuilder();
        for (byte b : arr) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
