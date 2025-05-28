package Service;

import java.security.SecureRandom;

public class SenhaService {

    // Conjunto de caracteres usados para gerar a senha forte
    private static final String CARACTERES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";

    // secureRandom para garantir aleatoriedade forte na geração da senha
    private static final SecureRandom random = new SecureRandom();

    public static String gerarSenhaForte(int tamanho) {
        StringBuilder sb = new StringBuilder(tamanho);
        for (int i = 0; i < tamanho; i++) {
            sb.append(CARACTERES.charAt(random.nextInt(CARACTERES.length())));
        }
        return sb.toString();
    }

    public static int calcularForcaSenha(String senha) {
        int score = 0;

        // Comprimento
        if (senha.length() >= 8) score++;
        if (senha.length() >= 12) score++;

        // Diversidade de caracteres
        if (senha.matches(".*[a-z].*")) score++;
        if (senha.matches(".*[A-Z].*")) score++;
        if (senha.matches(".*[0-9].*")) score++;
        if (senha.matches(".*[!@#$%^&*()_+].*")) score++;

        return score;
    }
}
