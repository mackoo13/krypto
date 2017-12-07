package krypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.util.Arrays;

public class Decrypt {

    private static byte[] cutPadding(byte[] in, String padding) {
        byte[] out;
        switch(padding) {
            case "PKCS7":
            case "AnsiX923":
            case "ISO10126":
                int paddingSize = in[in.length-1] & 0xFF;
                out = new byte[in.length - paddingSize];
                System.arraycopy(in, 0, out, 0, out.length);
                break;
            case "CiphertextSteal":
                out = in;
                break;
            default:
                out = in;
                break;
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4){
            throw new IOException("Usage: Decrypt algorithm ecb/cbc padding  filename");
        }
        final String algorithm = args[0];               // "DES" or "Blowfish"
        final String ecbOrCbc = args[1].toUpperCase();  // "ECB" or "CBC"
        final String padding = args[2];                 // "PKCS7 or "ISO10126" or "AnsiX923" or "CiphertextStealing"
        final String fileName = args[3];                // file to decode

        final String keyStoreName = "myKey";
        final String keyStorePassword = "";

        final byte[] ivBytes = (algorithm.equals("DES") ? "koalawombatkoala" : "koakoala").getBytes();
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        byte[] line = new byte[8192];
        byte[] ciphertext;
        byte[] prevPlainText = null;

        Key key = KeyLoader.loadKey(keyStoreName, keyStorePassword.toCharArray());
        Cipher cipher = Cipher.getInstance(algorithm + "/" + ecbOrCbc + "/NoPadding");

        FileInputStream fis = new FileInputStream(new File("enc-" + fileName));
        FileOutputStream fos = new FileOutputStream(new File("dec-" + fileName));
        BufferedInputStream bis = new BufferedInputStream(fis);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        int bytesRead;

        if(ecbOrCbc.equals("ECB")) cipher.init(Cipher.DECRYPT_MODE, key);
        else cipher.init(Cipher.DECRYPT_MODE, key, iv);

        while (line != null && (bytesRead = bis.read(line)) >= 0) {
            if(prevPlainText != null) {
                if(padding.equals("CiphertextStealing") && bytesRead < 8192) {
                    CiphertextStealing.encodeLastBlock(prevPlainText, line, cipher, bytesRead, bos);
                    line = null;
                } else {
                    System.out.println("Input: " + prevPlainText.length);
                    ciphertext = cipher.doFinal(prevPlainText);
                    System.out.println("Decrypted: " + ciphertext.length);
                    bos.write(ciphertext);
                }
            }
            if(line != null) prevPlainText = Arrays.copyOfRange(line, 0, bytesRead);
            else prevPlainText = null;
        }

        if(prevPlainText != null) {
            System.out.println("Input (last): " + prevPlainText.length);
            ciphertext = cutPadding(cipher.doFinal(prevPlainText), padding);
            System.out.println("Decrypted (last): " + ciphertext.length);
            bos.write(ciphertext);
        }

        bis.close();
        bos.close();
    }
}