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
            String sha1Hash = CriptografiaService.toSHA512(senha);
            String prefix = sha1Hash.substring(0, 5);
            String suffix = sha1Hash.substring(5);

            URL url = new URL(API_URL + prefix);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // Linha no formato: SUFIXO:QUANTIDADE
                    if (line.startsWith(suffix)) {
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
