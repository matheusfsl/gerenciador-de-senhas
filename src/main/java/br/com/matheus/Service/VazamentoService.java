package br.com.matheus.Service;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Serviço para verificar se uma senha foi vazada usando a API do HaveIBeenPwned (HIBP)
 */
public class VazamentoService {

    private static final String API_URL = "https://api.pwnedpasswords.com/range/";

    /**
     * Verifica se uma senha foi vazada com base em sua hash SHA-1
     * Utiliza o método "k-anonymity" da API para proteger a senha do usuário
     *
     * @param senha Senha em texto claro
     * @return true se a senha foi encontrada em vazamentos, false caso contrário
     */
    public static boolean verificarSenhaVazada(String senha) {
        try {
            // Corrigido para SHA-1 (requerido pela API HIBP)
            String sha1Hash = CriptografiaService.toSHA1(senha);
            String prefix = sha1Hash.substring(0, 5);
            String suffix = sha1Hash.substring(5);

            URL url = new URL(API_URL + prefix);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setReadTimeout(5000);
            conn.setConnectTimeout(5000);

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.toUpperCase().startsWith(suffix)) {
                        return true;
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("Erro ao verificar vazamento de senha: " + e.getMessage());
        }
        return false;
    }
}
