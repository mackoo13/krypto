package krypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

public class Encrypt {

    private static byte[] withPadding(byte[] in, int blockSize, String padding) {
        int paddingSize = blockSize - (in.length % blockSize);
        byte[] out = new byte[in.length + paddingSize];
        System.arraycopy(in, 0, out, 0, in.length);
        switch(padding) {
            case "PKCS7":
                for (int i = in.length; i < out.length; i++) {
                    out[i] = (byte) paddingSize;
                }
                break;
            case "AnsiX923":
                for (int i = in.length; i < out.length-1; i++) {
                    out[i] = (byte) 0;
                }
                out[out.length-1] = (byte) paddingSize;
                break;
            case "ISO10126":
                Random rand = new Random();
                for (int i = in.length; i < out.length-1; i++) {
                    out[i] = (byte) rand.nextInt(255);
                }
                out[out.length-1] = (byte) paddingSize;
                break;
            default:
                out = in;
                break;
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4){
            throw new IOException("Usage: Encrypt algorithm ecb/cbc padding filename");
        }
        final String algorithm = args[0];               // "DES" or "Blowfish"
        final String ecbOrCbc = args[1].toUpperCase();  // "ECB" or "CBC"
        final String padding = args[2];                 // "PKCS7 or "ISO10126" or "AnsiX923" or "CiphertextStealing"
        final String fileName = args[3];                // "file to encode"

        final String keyStoreName = "myKey";
        final String keyStorePassword = "";

        final int blockSize = algorithm.equals("DES") ? 16 : 8;
        final byte[] ivBytes = (algorithm.equals("DES") ? "koalawombatkoala" : "koakoala").getBytes();
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        byte[] line = new byte[8192];
        byte[] ciphertext;
        byte[] prevPlainText = null;

        Key key = KeyLoader.loadKey(keyStoreName, keyStorePassword.toCharArray());
        Cipher cipher = Cipher.getInstance(algorithm + "/" + ecbOrCbc + "/NoPadding");

        FileInputStream fis = new FileInputStream(new File(fileName));
        FileOutputStream fos = new FileOutputStream(new File("enc-" + fileName));
        BufferedInputStream bis = new BufferedInputStream(fis);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        int bytesRead;

        if(ecbOrCbc.equals("ECB")) cipher.init(Cipher.ENCRYPT_MODE, key);
        else cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        while (line != null && (bytesRead = bis.read(line)) >= 0) {

            if(prevPlainText != null) {
                if(padding.equals("CiphertextStealing") && bytesRead < 8192) {
                    CiphertextStealing.encodeLastBlock(prevPlainText, line, cipher, bytesRead, bos);
                    line = null;
                } else {
                    System.out.println("Input: " + prevPlainText.length);
                    ciphertext = cipher.doFinal(prevPlainText);
                    System.out.println("Encrypted: " + ciphertext.length);
                    bos.write(ciphertext);
                }
            }
            if(line != null) prevPlainText = Arrays.copyOfRange(line, 0, bytesRead);
            else prevPlainText = null;
        }

        // last block, do padding magic
        if(prevPlainText != null) {
            System.out.println("Input (last): " + prevPlainText.length);
            ciphertext = cipher.doFinal(withPadding(prevPlainText, blockSize, padding));
            System.out.println("Encrypted (last): " + ciphertext.length);
            bos.write(ciphertext);
        }

        bis.close();
        bos.close();
    }
}