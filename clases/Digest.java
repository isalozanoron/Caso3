package clases;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Digest {

    public static byte[] calcularHMAC(byte[] datos, byte[] llaveHMAC) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(llaveHMAC, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        return mac.doFinal(datos);
    }
}
