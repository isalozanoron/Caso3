import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyGenerator {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        try (FileOutputStream out = new FileOutputStream("public.key")) {
            out.write(publicKey.getEncoded());
        }

        try (FileOutputStream out = new FileOutputStream("private.key")) {
            out.write(privateKey.getEncoded());
        }

        System.out.println("Llaves RSA generadas correctamente.");
    }
}
