package clases;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class Simetrico {

    public static byte[] cifrarAES(byte[] datos, SecretKey llaveSimetrica, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, llaveSimetrica, iv);
        return cipher.doFinal(datos);
    }

    public static byte[] descifrarAES(byte[] datos, SecretKey llaveSimetrica, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, llaveSimetrica, iv);
        return cipher.doFinal(datos);
    }

    public static IvParameterSpec generarIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
