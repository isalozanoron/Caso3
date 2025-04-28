import clases.Asimetrico;
import clases.Digest;
import clases.Simetrico;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Map;

public class Cliente {

    private static PublicKey llavePublicaServidor;

    public static void main(String[] args) throws Exception {
        cargarLlavePublica();

        Socket socket = new Socket("localhost", 5000);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        try {
            // Recibir parámetros Diffie-Hellman
            int paramLength = in.readInt();
            byte[] paramBytes = new byte[paramLength];
            in.readFully(paramBytes);

            AlgorithmParameters params = AlgorithmParameters.getInstance("DH");
            params.init(paramBytes);
            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

            // Generar par de llaves DH cliente
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(dhSpec);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // Enviar llave pública
            out.writeInt(keyPair.getPublic().getEncoded().length);
            out.write(keyPair.getPublic().getEncoded());

            // Recibir llave pública servidor
            int serverPubKeyLength = in.readInt();
            byte[] serverPubKeyBytes = new byte[serverPubKeyLength];
            in.readFully(serverPubKeyBytes);

            KeyFactory kf = KeyFactory.getInstance("DH");
            PublicKey serverPubKey = kf.generatePublic(new X509EncodedKeySpec(serverPubKeyBytes));

            // Crear llave compartida
            KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
            keyAgree.init(keyPair.getPrivate());
            keyAgree.doPhase(serverPubKey, true);

            byte[] sharedSecret = keyAgree.generateSecret();
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecret);

            byte[] llaveCifradoBytes = new byte[32];
            byte[] llaveHmacBytes = new byte[32];
            System.arraycopy(digest, 0, llaveCifradoBytes, 0, 32);
            System.arraycopy(digest, 32, llaveHmacBytes, 0, 32);

            SecretKey llaveCifrado = new SecretKeySpec(llaveCifradoBytes, "AES");

            // Recibir IV
            int ivLength = in.readInt();
            byte[] ivBytes = new byte[ivLength];
            in.readFully(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Recibir tabla cifrada
            int tablaLength = in.readInt();
            byte[] tablaCifrada = new byte[tablaLength];
            in.readFully(tablaCifrada);

            // Recibir firma
            int firmaLength = in.readInt();
            byte[] firma = new byte[firmaLength];
            in.readFully(firma);

            // Recibir HMAC
            int hmacLength = in.readInt();
            byte[] hmacRecibido = new byte[hmacLength];
            in.readFully(hmacRecibido);

            // Validar HMAC
            long inicioVerificacion = System.nanoTime();
            byte[] hmacCalculado = Digest.calcularHMAC(tablaCifrada, llaveHmacBytes);
            if (!MessageDigest.isEqual(hmacCalculado, hmacRecibido)) {
                System.out.println("Error en la consulta (HMAC inválido). Cerrando conexión.");
                socket.close();
                return;
            }
            long finVerificacion = System.nanoTime();
            System.out.println("Tiempo de verificación tabla (ns): " + (finVerificacion - inicioVerificacion));

            // Descifrar tabla
            byte[] tablaBytes = Simetrico.descifrarAES(tablaCifrada, llaveCifrado, iv);

            // Verificar firma
            boolean firmaValida = Asimetrico.verificarFirmaRSA(tablaBytes, firma, llavePublicaServidor);
            if (!firmaValida) {
                System.out.println("Firma inválida. Cerrando conexión.");
                socket.close();
                return;
            }

            // Mostrar servicios
            ByteArrayInputStream bais = new ByteArrayInputStream(tablaBytes);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Map<Integer, String> servicios = (Map<Integer, String>) ois.readObject();

            System.out.println("Servicios disponibles:");
            for (Map.Entry<Integer, String> entry : servicios.entrySet()) {
                System.out.println(entry.getKey() + ": " + entry.getValue());
            }

            // Para pruebas, seleccionamos aleatoriamente uno
            int servicioElegido = 1; // Puedes modificarlo si quieres seleccionar aleatoriamente
            System.out.println("Solicitando servicio con ID: " + servicioElegido);
            out.writeInt(servicioElegido);

            // Recibir IV de respuesta
            int ivRespLength = in.readInt();
            byte[] ivRespBytes = new byte[ivRespLength];
            in.readFully(ivRespBytes);
            IvParameterSpec ivResp = new IvParameterSpec(ivRespBytes);

            // Recibir respuesta cifrada
            int respLength = in.readInt();
            byte[] respuestaCifrada = new byte[respLength];
            in.readFully(respuestaCifrada);

            // Recibir HMAC de respuesta
            int hmacRespLength = in.readInt();
            byte[] hmacRespRecibido = new byte[hmacRespLength];
            in.readFully(hmacRespRecibido);

            // Validar HMAC de respuesta
            byte[] hmacRespCalculado = Digest.calcularHMAC(respuestaCifrada, llaveHmacBytes);
            if (!MessageDigest.isEqual(hmacRespCalculado, hmacRespRecibido)) {
                System.out.println("Error en la consulta de respuesta (HMAC inválido). Cerrando conexión.");
                socket.close();
                return;
            }

            // Descifrar respuesta
            byte[] respuestaBytes = Simetrico.descifrarAES(respuestaCifrada, llaveCifrado, ivResp);

            // Interpretar respuesta
            DataInputStream disResp = new DataInputStream(new ByteArrayInputStream(respuestaBytes));
            int ip = disResp.readInt();
            int puerto = disResp.readInt();

            System.out.println("Dirección IP del servicio: " + ip);
            System.out.println("Puerto del servicio: " + puerto);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            socket.close();
        }
    }

    private static void cargarLlavePublica() throws Exception {
        byte[] llavePublicaBytes = Files.readAllBytes(new File("public.key").toPath());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(llavePublicaBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        llavePublicaServidor = keyFactory.generatePublic(pubSpec);
    }
}
