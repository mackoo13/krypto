package krypto;

import javax.crypto.Cipher;
import java.io.BufferedOutputStream;

public class CiphertextStealing {

    public static void encodeLastBlock(byte[] prevPlainText,
                                       byte[] line,
                                       Cipher cipher,
                                       int bytesRead,
                                       BufferedOutputStream bos) throws Exception {

        byte[] ciphertext;

        //last block, do padding magic
        System.out.println("Input (last): " + prevPlainText.length);
        ciphertext = cipher.doFinal(prevPlainText);
        System.out.println("Encrypted (last): " + ciphertext.length);

        byte[] last = new byte[8192];
        System.arraycopy(line, 0, last, 0, bytesRead);
        System.arraycopy(ciphertext, bytesRead, last, bytesRead, last.length - bytesRead);
        byte[] lastEncrypted = cipher.doFinal(last);
        bos.write(lastEncrypted);

        byte[] rest = new byte[bytesRead];
        System.out.println("Input (last): " + rest.length);
        System.arraycopy(ciphertext, 0, rest, 0, bytesRead);
        System.out.println("Encrypted (last): " + rest.length);
        bos.write(rest);
    }

}
