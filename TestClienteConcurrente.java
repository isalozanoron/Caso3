import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class TestClienteConcurrente {

    public static void main(String[] args) throws Exception {
        int cantidadClientes = 64; // cambiarlo a 4, 16, 32 y 64 para las distintas pruebas

        ExecutorService executor = Executors.newFixedThreadPool(cantidadClientes);

        for (int i = 0; i < cantidadClientes; i++) {
            executor.execute(() -> {
                try {
                    Cliente.main(null);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }

        executor.shutdown();
        while (!executor.isTerminated()) {
        }

        System.out.println("Todas las consultas concurrentes han terminado.");
    }
}
