import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;

public class KeyExchange {

    public static KeyPair generarParDH(DHParameterSpec dhSpec) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        return keyGen.generateKeyPair();
    }

    public static byte[] calcularSecretoCompartido(PrivateKey privadaLocal, PublicKey publicaRemota) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privadaLocal);
        keyAgree.doPhase(publicaRemota, true);
        return keyAgree.generateSecret();
    }

    public static byte[][] derivarLlaves(byte[] secretoCompartido) throws Exception {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(secretoCompartido);

        byte[] claveAES = new byte[32];
        byte[] claveHMAC = new byte[32];

        System.arraycopy(digest, 0, claveAES, 0, 32);
        System.arraycopy(digest, 32, claveHMAC, 0, 32);

        return new byte[][] { claveAES, claveHMAC };
    }
}
