public class TestClienteIterativo {

    public static void main(String[] args) throws Exception {
        int cantidadConsultas = 32;

        for (int i = 0; i < cantidadConsultas; i++) {
            System.out.println("==== Consulta #" + (i + 1) + " ====");
            Cliente.main(null); // Llama a tu Cliente cada vez
            Thread.sleep(100); // Pequeña pausa de 100 ms entre consultas
        }
    }
}
