package krypto;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;

public class RSADecrypt {

    public static void main(String[] args) throws Exception {
        if (args.length != 2){
            throw new IOException("Usage: RSADecrypt filename keysize");
        }
        final String fileName = args[0];
        final int keyLen = Integer.parseInt(args[1]);

        Cipher cipher = Cipher.getInstance("RSA");
        PrivateKey privateKey = readPrivateKey("Private" + keyLen + ".pem");
        final int maxLen = keyLen/8;

        FileInputStream fis = new FileInputStream(new File("RSA-enc-"+ fileName));
        FileOutputStream fos = new FileOutputStream(new File("RSA-dec-" + fileName));
        BufferedInputStream bis = new BufferedInputStream(fis, keyLen);
        BufferedOutputStream bos = new BufferedOutputStream(fos);

        byte[] line = new byte[maxLen];

        long timeCount = 0;

        while (bis.read(line) >= 0) {
            long startTime = System.nanoTime();
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            long endTime = System.nanoTime();

            timeCount += endTime - startTime;
            byte[] clearText = cipher.doFinal(line);
            bos.write(clearText);
        }
        long timeSum = (timeCount)/1000000;
        System.out.println("Time: " + timeSum + "ms");

        bis.close();
        bos.close();
    }

    private static PrivateKey readPrivateKey(String privateKey) throws Exception {
        InputStream in = new FileInputStream(privateKey);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
        PrivateKey privKey;

        BigInteger m = (BigInteger) oin.readObject();
        BigInteger e = (BigInteger) oin.readObject();
        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        privKey = fact.generatePrivate(keySpec);

        return privKey;
    }
}
