package br.com.matheus.Service;

import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class CriptografiaService {
    // Configurações para AES
    private static final String ALGORITHM = "AES";

    // Métodos BCrypt para hashing de senhas


    /**
     * Gera um hash BCrypt para a senha fornecida
     * @param senha Senha em texto claro
     * @return Hash BCrypt da senha
     */
    public static String hashSenha(String senha) {
        // O gensalt() gera um salt aleatório e determina o fator de custo automaticamente
        return BCrypt.hashpw(senha, BCrypt.gensalt());
    }

    /**
     * Verifica se uma senha em texto claro corresponde a um hash BCrypt
     * @param senha Senha em texto claro para verificar
     * @param hash Hash BCrypt armazenado
     * @return true se a senha corresponder ao hash, false caso contrário
     */
    public static boolean verificarSenha(String senha, String hash) {
        try {
            return BCrypt.checkpw(senha, hash);
        } catch (Exception e) {
            // Pode ocorrer se o hash estiver mal formatado
            return false;
        }
    }

    // Métodos AES para criptografia das credenciais
    // --------------------------------------------

    /**
     * Criptografa um texto usando AES
     * @param dado Texto a ser criptografado
     * @param chave Chave secreta (deve ter 16, 24 ou 32 caracteres)
     * @return Texto criptografado em Base64
     * @throws RuntimeException Se ocorrer erro na criptografia
     */
    public static String criptografar(String dado, String chave) {
        try {
            // Garante que a chave tenha tamanho válido para AES (128, 192 ou 256 bits)
            byte[] chaveBytes = gerarChaveAES(chave);
            SecretKeySpec secretKey = new SecretKeySpec(chaveBytes, ALGORITHM);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] dadoCriptografado = cipher.doFinal(dado.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(dadoCriptografado);
        } catch (Exception e) {
            throw new RuntimeException("Falha na criptografia", e);
        }
    }

    /**
     * Descriptografa um texto usando AES
     * @param dadoCriptografado Texto criptografado em Base64
     * @param chave Chave secreta usada na criptografia
     * @return Texto descriptografado
     * @throws RuntimeException Se ocorrer erro na descriptografia
     */
    public static String descriptografar(String dadoCriptografado, String chave) {
        try {
            // Garante que a chave tenha tamanho válido para AES
            byte[] chaveBytes = gerarChaveAES(chave);
            SecretKeySpec secretKey = new SecretKeySpec(chaveBytes, ALGORITHM);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] bytesDescriptografados = cipher.doFinal(Base64.getDecoder().decode(dadoCriptografado));
            return new String(bytesDescriptografados, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Falha na descriptografia", e);
        }
    }

    /**
     * Gera uma chave AES de tamanho fixo (128, 192 ou 256 bits) a partir de uma string qualquer
     * @param chave Chave original
     * @return Bytes da chave com tamanho adequado
     * @throws Exception Se ocorrer erro ao gerar o hash da chave
     */
    private static byte[] gerarChaveAES(String chave) throws Exception {
        // Usa SHA-256 para gerar um hash fixo da chave (32 bytes = 256 bits)
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(chave.getBytes(StandardCharsets.UTF_8));

        // para AES-128 (16 bytes), pegamos os primeiros 16 bytes do hash
        // Para AES-192 (24 bytes), pegar os primeiros 24 bytes
        // para AES-256 (32 bytes), usar o hash completo
        byte[] chaveAES = new byte[16]; // Usando AES-128
        System.arraycopy(hash, 0, chaveAES, 0, chaveAES.length);

        return chaveAES;
    }

    // Método auxiliar para gerar hash SHA-1 (usado na verificação de vazamentos)
    public static String toSHA1(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString().toUpperCase();
        } catch (Exception e) {
            throw new RuntimeException("Falha ao gerar hash SHA-1", e);
        }
    }
}