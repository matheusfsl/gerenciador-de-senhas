package br.com.matheus.Service;

import java.security.SecureRandom;

public class SenhaService {

    // Conjunto de caracteres utilizados na geração da senha
    // Inclui letras maiúsculas, minúsculas, números e caracteres especiais
    private static final String CARACTERES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";

    // Gerador de números aleatórios criptograficamente seguro
    private static final SecureRandom random = new SecureRandom();

    /**
     * Gera uma senha aleatória forte com base no tamanho especificado.
     *
     * @param tamanho O comprimento desejado da senha
     * @return Uma senha aleatória contendo letras, números e caracteres especiais
     */
    public static String gerarSenhaForte(int tamanho) {
        StringBuilder sb = new StringBuilder(tamanho);

        // Adiciona caracteres aleatórios um a um até atingir o tamanho desejado
        for (int i = 0; i < tamanho; i++) {
            sb.append(CARACTERES.charAt(random.nextInt(CARACTERES.length())));
        }

        return sb.toString();
    }

    /**
     * Calcula a força da senha com base em critérios simples:
     * comprimento e diversidade de caracteres.
     *
     * A pontuação vai de 0 (fraca) até 6 (muito forte).
     *
     * @param senha A senha a ser avaliada
     * @return Um score entre 0 e 6 indicando a força da senha
     */
    public static int calcularForcaSenha(String senha) {
        int score = 0;

        // Flags para identificar presença de tipos de caracteres
        boolean temMinuscula = false;
        boolean temMaiuscula = false;
        boolean temNumero = false;
        boolean temEspecial = false;

        // Itera sobre cada caractere da senha para verificar os critérios
        for (char c : senha.toCharArray()) {
            if (Character.isLowerCase(c)) temMinuscula = true;
            else if (Character.isUpperCase(c)) temMaiuscula = true;
            else if (Character.isDigit(c)) temNumero = true;
            else if ("!@#$%^&*()_+".indexOf(c) >= 0) temEspecial = true;
        }

        // Verifica comprimento
        if (senha.length() >= 8) score++;
        if (senha.length() >= 12) score++;

        // Verifica diversidade de tipos de caracteres
        if (temMinuscula) score++;
        if (temMaiuscula) score++;
        if (temNumero) score++;
        if (temEspecial) score++;

        return score;
    }
}
