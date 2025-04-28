public class TestClienteIterativo {

    public static void main(String[] args) throws Exception {
        int cantidadConsultas = 32;

        for (int i = 0; i < cantidadConsultas; i++) {
            System.out.println("==== Consulta #" + (i + 1) + " ====");
            Cliente.main(null); 
            Thread.sleep(100); 
        }
    }
}
