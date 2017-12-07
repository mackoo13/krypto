package krypto;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;


public class RSAEncrypt {
    public static void main(String[] args) throws Exception {
        if (args.length != 2){
            throw new IOException("Usage: RSAEncrypt filename keysize");
        }
        final String fileName = args[0];
        final int keyLen = Integer.parseInt(args[1]);

        Cipher cipher = Cipher.getInstance("RSA");
        PublicKey publicKey = readPublicKey("Public" + keyLen + ".pem");
        System.out.println(publicKey);

        FileInputStream fis = new FileInputStream(new File(fileName));
        FileOutputStream fos = new FileOutputStream(new File("RSA-enc-" + fileName));

        int maxLen = keyLen/8 - 11;

        BufferedInputStream bis = new BufferedInputStream(fis, maxLen);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        int bytesRead;
        byte[] line = new byte[maxLen];

        long timeCount = 0;

        while ((bytesRead = bis.read(line)) >= 0) {

            byte[] lineFragment = Arrays.copyOfRange(line, 0, bytesRead);

            long startTime = System.nanoTime();
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            long endTime = System.nanoTime();

            timeCount += endTime - startTime;

            byte[] ciphertext = cipher.doFinal(lineFragment);
            bos.write(ciphertext);
        }

        long timeSum = (timeCount)/1000000;
        System.out.println("Time: " + timeSum + "ms");

        bis.close();
        bos.close();


    }

    private static PublicKey readPublicKey(String publicKeyFile) throws Exception {
        InputStream in = new FileInputStream(publicKeyFile);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
        PublicKey pubKey;

        BigInteger m = (BigInteger) oin.readObject();
        BigInteger e = (BigInteger) oin.readObject();
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        pubKey = fact.generatePublic(keySpec);

        return pubKey;
    }
}
