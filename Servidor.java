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
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Servidor {

    private static final int PUERTO = 5000;
    private static final Map<Integer, String> servicios = new HashMap<>();
    private static PrivateKey llavePrivada;
    private static PublicKey llavePublica;

    public static void main(String[] args) throws Exception {
        cargarServicios();
        cargarLlaves();

        ServerSocket serverSocket = new ServerSocket(PUERTO);
        ExecutorService pool = Executors.newCachedThreadPool();

        System.out.println("Servidor principal escuchando en el puerto " + PUERTO);

        while (true) {
            Socket socket = serverSocket.accept();
            pool.execute(new Delegado(socket));
        }
    }

    private static void cargarServicios() {
        servicios.put(1, "Consulta Estado Vuelo");
        servicios.put(2, "Disponibilidad Vuelos");
        servicios.put(3, "Costo de Vuelo");
    }

    private static void cargarLlaves() throws Exception {
        byte[] llavePrivadaBytes = Files.readAllBytes(new File("private.key").toPath());
        byte[] llavePublicaBytes = Files.readAllBytes(new File("public.key").toPath());

        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(llavePrivadaBytes);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(llavePublicaBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        llavePrivada = keyFactory.generatePrivate(privSpec);
        llavePublica = keyFactory.generatePublic(pubSpec);
    }

    private static class Delegado implements Runnable {
        private final Socket socket;

        public Delegado(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (DataInputStream in = new DataInputStream(socket.getInputStream());
                 DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

                // Diffie-Hellman
                AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
                paramGen.init(1024);
                AlgorithmParameters params = paramGen.generateParameters();
                DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
                keyPairGen.initialize(dhSpec);
                KeyPair keyPair = keyPairGen.generateKeyPair();

                byte[] paramsEncoded = params.getEncoded();
                out.writeInt(paramsEncoded.length);
                out.write(paramsEncoded);

                out.writeInt(keyPair.getPublic().getEncoded().length);
                out.write(keyPair.getPublic().getEncoded());

                int clientPubKeyLength = in.readInt();
                byte[] clientPubKeyBytes = new byte[clientPubKeyLength];
                in.readFully(clientPubKeyBytes);

                KeyFactory kf = KeyFactory.getInstance("DH");
                PublicKey clientPubKey = kf.generatePublic(new X509EncodedKeySpec(clientPubKeyBytes));

                KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
                keyAgree.init(keyPair.getPrivate());
                keyAgree.doPhase(clientPubKey, true);

                byte[] sharedSecret = keyAgree.generateSecret();
                MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                byte[] digest = sha512.digest(sharedSecret);

                byte[] llaveCifradoBytes = new byte[32];
                byte[] llaveHmacBytes = new byte[32];
                System.arraycopy(digest, 0, llaveCifradoBytes, 0, 32);
                System.arraycopy(digest, 32, llaveHmacBytes, 0, 32);

                SecretKey llaveCifrado = new SecretKeySpec(llaveCifradoBytes, "AES");

                // Firmar tabla
                long inicioFirma = System.nanoTime();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos);
                oos.writeObject(servicios);
                oos.flush();
                byte[] tablaBytes = baos.toByteArray();

                byte[] firma = Asimetrico.firmarRSA(tablaBytes, llavePrivada);
                long finFirma = System.nanoTime();
                System.out.println("Tiempo de firma (ns): " + (finFirma - inicioFirma));

                // Cifrar tabla
                IvParameterSpec iv = Simetrico.generarIV();
                long inicioCifrado = System.nanoTime();
                byte[] tablaCifrada = Simetrico.cifrarAES(tablaBytes, llaveCifrado, iv);
                long finCifrado = System.nanoTime();
                System.out.println("Tiempo de cifrado tabla (ns): " + (finCifrado - inicioCifrado));

                // Calcular HMAC
                byte[] hmacTabla = Digest.calcularHMAC(tablaCifrada, llaveHmacBytes);

                // Enviar IV
                out.writeInt(iv.getIV().length);
                out.write(iv.getIV());

                // Enviar tabla cifrada
                out.writeInt(tablaCifrada.length);
                out.write(tablaCifrada);

                // Enviar firma
                out.writeInt(firma.length);
                out.write(firma);

                // Enviar HMAC
                out.writeInt(hmacTabla.length);
                out.write(hmacTabla);

                // Recibir identificador
                int idServicio = in.readInt();
                System.out.println("Cliente pidió servicio: " + idServicio);

                // Buscar servicio
                int ip = 127001; // Dummy IP (localhost)
                int puerto = 5001; // Dummy port
                if (!servicios.containsKey(idServicio)) {
                    ip = -1;
                    puerto = -1;
                }

                // Preparar respuesta
                ByteArrayOutputStream baosResp = new ByteArrayOutputStream();
                DataOutputStream dosResp = new DataOutputStream(baosResp);
                dosResp.writeInt(ip);
                dosResp.writeInt(puerto);
                dosResp.flush();
                byte[] respuestaBytes = baosResp.toByteArray();

                // Cifrar respuesta
                IvParameterSpec ivResp = Simetrico.generarIV();
                byte[] respuestaCifrada = Simetrico.cifrarAES(respuestaBytes, llaveCifrado, ivResp);

                // Calcular HMAC
                byte[] hmacRespuesta = Digest.calcularHMAC(respuestaCifrada, llaveHmacBytes);

                // Enviar IV de respuesta
                out.writeInt(ivResp.getIV().length);
                out.write(ivResp.getIV());

                // Enviar respuesta cifrada
                out.writeInt(respuestaCifrada.length);
                out.write(respuestaCifrada);

                // Enviar HMAC
                out.writeInt(hmacRespuesta.length);
                out.write(hmacRespuesta);

            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try { socket.close(); } catch (IOException e) { e.printStackTrace(); }
            }
        }
    }
}
