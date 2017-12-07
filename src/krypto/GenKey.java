/*Napisz program(-y) szyfruj¡cy i deszyfruj¡cy dowolny plik przy pomocy wskazanej metody szyfrowania i dopea-
nienia. Program ma umo»liwia¢ wybór jednego z dwóch trybów szyfrowania CBC i ECB.*/

package krypto;

import javax.crypto.*;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;

public class GenKey {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IOException("Usage: GenKey algorithm");
        }
        final String algorithm = args[0];

        javax.crypto.KeyGenerator keygen = javax.crypto.KeyGenerator.getInstance(algorithm);
        SecretKey key = keygen.generateKey();

        KeyStore ks;
        java.io.FileOutputStream fos = null;
        try {
            ks = KeyStore.getInstance("JCEKS");
            ks.load (null, "".toCharArray());

            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("".toCharArray());
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(key);
            ks.setEntry("myKey", skEntry, protParam);
            fos = new java.io.FileOutputStream("myKey");
            ks.store(fos, "".toCharArray());

        } catch (KeyStoreException | CertificateException e) {
            e.printStackTrace();
        } finally {
            if (fos != null) fos.close();
        }

    }
}