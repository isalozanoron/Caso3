import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class Servidor {

    private static final Map<Integer, String[]> services = new HashMap<>();
    private static PrivateKey privateKey;

    public static void main(String[] args) {
        try {
            privateKey = loadPrivateKey("llaves/private.key");
            initializeServices();

            ServerSocket serverSocket = new ServerSocket(12345);
            System.out.println("Servidor principal iniciado en puerto 12345...");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(() -> handleClient(clientSocket)).start();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket) {
        try (
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream())
        ) {
            System.out.println("Cliente conectado: " + socket.getInetAddress());

            // 1. Generar parámetros DH
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

            // 2. Generar par de llaves DH del servidor con esos parámetros
            KeyPair servidorDH = KeyExchange.generarParDH(dhSpec);
            PublicKey publicKeyServidor = servidorDH.getPublic();
            PrivateKey privateKeyServidor = servidorDH.getPrivate();

            // 3. Enviar parámetros DH y llave pública del servidor
            out.writeObject(dhSpec);
            out.writeObject(publicKeyServidor);
            out.flush();

            // 4. Recibir llave pública del cliente
            PublicKey publicKeyCliente = (PublicKey) in.readObject();

            // 5. Derivar llaves de sesión
            byte[] secretoCompartido = KeyExchange.calcularSecretoCompartido(privateKeyServidor, publicKeyCliente);
            byte[][] llaves = KeyExchange.derivarLlaves(secretoCompartido);
            byte[] claveAES = llaves[0];
            byte[] claveHMAC = llaves[1];

            System.out.println("→ Intercambio DH exitoso. Llaves de sesión derivadas.");

            // Serializar y cifrar tabla
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(services);
            oos.close();
            byte[] datosServicios = baos.toByteArray();

            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            byte[] datosCifrados = cifrarAES(datosServicios, claveAES, iv);
            byte[] firma = firmar(datosCifrados, privateKey);

            out.writeObject(iv);
            out.writeObject(datosCifrados);
            out.writeObject(firma);
            out.flush();

            System.out.println("→ Tabla de servicios cifrada y firmada enviada.");

            // Recibir ID y HMAC
            int idRecibido = (Integer) in.readObject();
            byte[] hmacRecibido = (byte[]) in.readObject();

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(claveHMAC, "HmacSHA256"));
            byte[] hmacEsperado = mac.doFinal(Integer.toString(idRecibido).getBytes());

            if (!Arrays.equals(hmacEsperado, hmacRecibido)) {
                System.out.println("❌ HMAC inválido. Terminando conexión.");
                out.writeObject(new String[]{"-1", "-1"});
                return;
            }

            System.out.println("✔️ HMAC válido. Consultando servicio...");
            String[] respuesta = services.getOrDefault(idRecibido, new String[]{"-1", "-1"});
            out.writeObject(respuesta);

        } catch (Exception e) {
            System.err.println("Error al manejar cliente: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void initializeServices() {
        services.put(1, new String[]{"192.168.0.101", "2001"});
        services.put(2, new String[]{"192.168.0.102", "2002"});
        services.put(3, new String[]{"192.168.0.103", "2003"});
    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static byte[] cifrarAES(byte[] datos, byte[] claveAES, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(claveAES, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(datos);
    }

    private static byte[] firmar(byte[] datos, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(datos);
        return signature.sign();
    }
}
