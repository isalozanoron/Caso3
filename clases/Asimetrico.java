package clases;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class Asimetrico {

    public static byte[] cifrarRSA(byte[] datos, PublicKey llavePublica) throws Exception {
        long startTimeRSA = System.nanoTime();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, llavePublica);
        byte[] encryptedRSA = cipher.doFinal(datos);
        long endTimeRSA = System.nanoTime();
        long tiempoCifradoRSA = (endTimeRSA - startTimeRSA) / 1000000;
        System.out.println("Tiempo de cifrado RSA (ms): " + tiempoCifradoRSA);
        return encryptedRSA;
    }

    public static byte[] descifrarRSA(byte[] datos, PrivateKey llavePrivada) throws Exception {
        long startTimeRSA = System.nanoTime();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, llavePrivada);
        byte[] encryptedRSA = cipher.doFinal(datos);
        long endTimeRSA = System.nanoTime();
        long tiempoDescifradoRSA = (endTimeRSA - startTimeRSA) / 1000000;
        System.out.println("Tiempo de descifrado RSA (ms): " + tiempoDescifradoRSA);
        return encryptedRSA;
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
