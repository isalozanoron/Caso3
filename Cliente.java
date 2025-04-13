import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class Cliente {

    private static PublicKey serverPublicKey;

    public static void main(String[] args) {
        try {
            serverPublicKey = loadPublicKey("llaves/public.key");

            Socket socket = new Socket("localhost", 12345);
            System.out.println("Conectado al servidor");

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // 1. Recibir parámetros DH y publicKey del servidor
            DHParameterSpec dhSpec = (DHParameterSpec) in.readObject();
            PublicKey publicKeyServidor = (PublicKey) in.readObject();

            // 2. Generar par DH usando los mismos parámetros
            KeyPair clienteDH = KeyExchange.generarParDH(dhSpec);
            PublicKey publicKeyCliente = clienteDH.getPublic();
            PrivateKey privateKeyCliente = clienteDH.getPrivate();

            // 3. Enviar publicKey del cliente
            out.writeObject(publicKeyCliente);
            out.flush();

            // 4. Derivar llaves de sesión
            byte[] secretoCompartido = KeyExchange.calcularSecretoCompartido(privateKeyCliente, publicKeyServidor);
            byte[][] llaves = KeyExchange.derivarLlaves(secretoCompartido);
            byte[] claveAES = llaves[0];
            byte[] claveHMAC = llaves[1];

            System.out.println("→ Intercambio DH exitoso. Llaves de sesión derivadas.");

            byte[] iv = (byte[]) in.readObject();
            byte[] datosCifrados = (byte[]) in.readObject();
            byte[] firma = (byte[]) in.readObject();

            if (!verificarFirma(datosCifrados, firma, serverPublicKey)) {
                System.out.println("❌ Error en la consulta: firma inválida.");
                socket.close();
                return;
            }
            System.out.println("✔️ Firma verificada correctamente.");

            byte[] datosDescifrados = descifrarAES(datosCifrados, claveAES, iv);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(datosDescifrados));
            Map<Integer, String[]> servicios = (Map<Integer, String[]>) ois.readObject();

            System.out.println("Servicios disponibles:");
            for (Map.Entry<Integer, String[]> entry : servicios.entrySet()) {
                System.out.println("ID: " + entry.getKey() +
                        " | IP: " + entry.getValue()[0] +
                        " | Puerto: " + entry.getValue()[1]);
            }

            Scanner scanner = new Scanner(System.in);
            System.out.print("Ingrese el ID del servicio deseado: ");
            int idSeleccionado = scanner.nextInt();

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(claveHMAC, "HmacSHA256"));
            byte[] hmac = mac.doFinal(Integer.toString(idSeleccionado).getBytes());

            out.writeObject(idSeleccionado);
            out.writeObject(hmac);
            out.flush();

            String[] respuesta = (String[]) in.readObject();
            if (respuesta[0].equals("-1")) {
                System.out.println("❌ Servicio no encontrado o HMAC inválido.");
            } else {
                System.out.println("✅ Dirección del servicio:");
                System.out.println("IP: " + respuesta[0] + " | Puerto: " + respuesta[1]);
            }

            in.close();
            out.close();
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static byte[] descifrarAES(byte[] datos, byte[] claveAES, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(claveAES, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(datos);
    }

    private static boolean verificarFirma(byte[] datos, byte[] firma, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(datos);
        return signature.verify(firma);
    }
}
