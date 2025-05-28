package br.com.matheus.Service;

import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class CriptografiaService {
    private static final String ALGORITHM = "AES"; // Algoritmo de criptografia simétrica (AES)
    private static final int AES_KEY_SIZE = 128;   // Tamanho da chave AES em bits (128 bits = 16 bytes)
    private static final int GCM_IV_LENGTH = 12;   // Tamanho do vetor de inicialização (IV) para AES-GCM (12 bytes é o recomendado)
    private static final int GCM_TAG_LENGTH = 128; // Tamanho da tag de autenticação do AES-GCM em bits

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Gera um hash BCrypt para a senha fornecida
     */
    public static String hashSenha(String senha) {
        return BCrypt.hashpw(senha, BCrypt.gensalt());
    }

    /**
     * Verifica se uma senha em texto claro corresponde a um hash BCrypt
     */
    public static boolean verificarSenha(String senha, String hash) {
        try {
            return BCrypt.checkpw(senha, hash);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Criptografa um texto usando AES/GCM com IV aleatório
     */
    public static String criptografar(String dado, String chave) {
        try {
            byte[] chaveBytes = gerarChaveAES(chave);
            SecretKeySpec secretKey = new SecretKeySpec(chaveBytes, ALGORITHM);

            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv); // IV aleatório

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

            byte[] dadoCriptografado = cipher.doFinal(dado.getBytes(StandardCharsets.UTF_8));

            // Concatenar IV + dado criptografado e codificar em Base64
            byte[] resultadoComIV = new byte[iv.length + dadoCriptografado.length];
            System.arraycopy(iv, 0, resultadoComIV, 0, iv.length);
            System.arraycopy(dadoCriptografado, 0, resultadoComIV, iv.length, dadoCriptografado.length);

            return Base64.getEncoder().encodeToString(resultadoComIV);
        } catch (Exception e) {
            throw new RuntimeException("Falha na criptografia", e);
        }
    }

    /**
     * Descriptografa um texto usando AES/GCM extraindo o IV do início do texto
     */
    public static String descriptografar(String dadoCriptografado, String chave) {
        try {
            byte[] dados = Base64.getDecoder().decode(dadoCriptografado);
            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] dadoReal = new byte[dados.length - GCM_IV_LENGTH];

            // Separa IV e dado criptografado
            System.arraycopy(dados, 0, iv, 0, iv.length);
            System.arraycopy(dados, iv.length, dadoReal, 0, dadoReal.length);

            byte[] chaveBytes = gerarChaveAES(chave);
            SecretKeySpec secretKey = new SecretKeySpec(chaveBytes, ALGORITHM);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

            byte[] bytesDescriptografados = cipher.doFinal(dadoReal);
            return new String(bytesDescriptografados, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Falha na descriptografia", e);
        }
    }

    /**
     * Gera uma chave AES de 128 bits a partir de uma string
     */
    private static byte[] gerarChaveAES(String chave) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(chave.getBytes(StandardCharsets.UTF_8));
        byte[] chaveAES = new byte[16]; // AES-128
        System.arraycopy(hash, 0, chaveAES, 0, chaveAES.length);
        return chaveAES;
    }

    /**
     * Gera um hash SHA-512 em formato hexadecimal (útil para checar vazamentos de senha)
     */
    // SHA-512 - uso interno, não compatível com HaveIBeenPwned
    public static String toSHA512(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString().toUpperCase();
        } catch (Exception e) {
            throw new RuntimeException("Falha ao gerar hash SHA-512", e);
        }
    }

    // SHA-1 - necessário para verificar com a API do HaveIBeenPwned, ja que o outro não é compativel 
    public static String toSHA1(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString().toUpperCase();
        } catch (Exception e) {
            throw new RuntimeException("Falha ao gerar hash SHA-1", e);
        }
    }
}
