package clases;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class Simetrico {

    public static byte[] cifrarAES(byte[] datos, SecretKey llaveSimetrica, IvParameterSpec iv) throws Exception {
        long startTimeAES = System.nanoTime();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, llaveSimetrica, iv);
        byte[] encryptedData = cipher.doFinal(datos);
        long endTimeAES = System.nanoTime();
        long tiempoCifradoAES = (endTimeAES - startTimeAES) / 1000000;
        System.out.println("Tiempo de cifrado AES (ms): " + tiempoCifradoAES);
        return encryptedData;
    }

    public static byte[] descifrarAES(byte[] datos, SecretKey llaveSimetrica, IvParameterSpec iv) throws Exception {
        long startTimeAES = System.nanoTime();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, llaveSimetrica, iv);
        byte[] encryptedData = cipher.doFinal(datos);
        long endTimeAES = System.nanoTime();
        long tiempoCifradoAES = (endTimeAES - startTimeAES) / 1000000;
        System.out.println("Tiempo de descifrado AES (ms): " + tiempoCifradoAES);
        return encryptedData;
    }

    public static IvParameterSpec generarIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
