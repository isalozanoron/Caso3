package clases;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class Asimetrico {

    public static byte[] cifrarRSA(byte[] datos, PublicKey llavePublica) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, llavePublica);
        return cipher.doFinal(datos);
    }

    public static byte[] descifrarRSA(byte[] datos, PrivateKey llavePrivada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, llavePrivada);
        return cipher.doFinal(datos);
    }

    public static byte[] firmarRSA(byte[] datos, PrivateKey llavePrivada) throws Exception {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(llavePrivada);
        firma.update(datos);
        return firma.sign();
    }

    public static boolean verificarFirmaRSA(byte[] datos, byte[] firmaBytes, PublicKey llavePublica) throws Exception {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initVerify(llavePublica);
        firma.update(datos);
        return firma.verify(firmaBytes);
    }

    public static PublicKey bytesToPublicKey(byte[] llaveBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(llaveBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
}
