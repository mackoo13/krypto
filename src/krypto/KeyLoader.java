package krypto;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

class KeyLoader {

    static Key loadKey(String storeName, char[] password)
            throws KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, IOException {

        FileInputStream fis = new FileInputStream(storeName);
        KeyStore ks = KeyStore.getInstance("JCEKS");
        ks.load(fis, password);
        fis.close();
        return ks.getKey(storeName, password);
    }
}
