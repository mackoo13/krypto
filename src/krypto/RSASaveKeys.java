package krypto;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RSASaveKeys {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IOException("Usage: RSASaveKeys keysize");
        }
        final int keyLen = Integer.parseInt(args[0]);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keyLen);

        KeyFactory fact = KeyFactory.getInstance("RSA");
        KeyPair kp = keyGen.genKeyPair();

        RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(),
                RSAPublicKeySpec.class);

        saveToFile("Private"+keyLen+".pem",
                pub.getModulus(), pub.getPublicExponent());

        RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(),
                RSAPrivateKeySpec.class);
        saveToFile("Public"+keyLen+".pem",
                priv.getModulus(), priv.getPrivateExponent());



    }

    private static void saveToFile(String fileName,
                                   BigInteger mod, BigInteger exp)
            throws IOException {
        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            oout.close();
        }
    }
}
