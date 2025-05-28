package br.com.matheus.Service;

import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.security.MessageDigest;

public class CriptografiaService {

    // Constantes para configurar a criptografia AES-GCM
    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";

    private static final int AES_KEY_SIZE_BITS = 128; // Tamanho da chave AES
    private static final int SALT_LENGTH = 16;        // Salt de 16 bytes para PBKDF2
    private static final int GCM_IV_LENGTH = 12;      // IV recomendado para GCM 
    private static final int GCM_TAG_LENGTH_BITS = 128; // Tamanho da tag de autenticação GCM
    private static final int PBKDF2_ITERATIONS = 65536; // Número de iterações para derivar a chave

    private static final SecureRandom secureRandom = new SecureRandom();

    // Método para gerar hash de senha usando BCrypt
    public static String hashSenha(String senha) {
        return BCrypt.hashpw(senha, BCrypt.gensalt());
    }

    // Método para verificar se a senha confere com o hash BCrypt armazenado
    public static boolean verificarSenha(String senha, String hash) {
        try {
            return BCrypt.checkpw(senha, hash);
        } catch (Exception e) {
            // Caso algo dê errado, retorna falso para garantir segurança
            return false;
        }
    }

    // Gera a chave AES a partir da senha e do salt usando PBKDF2WithHmacSHA256
    private static SecretKeySpec gerarChaveAES(String senha, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(
                senha.toCharArray(),
                salt,
                PBKDF2_ITERATIONS,
                AES_KEY_SIZE_BITS
        );
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, AES_ALGORITHM);
    }

    // Criptografa a string usando AES-GCM e uma senha
    // O resultado é uma string Base64 contendo salt + IV + dados criptografados
    public static String criptografar(String dado, String senha) {
        try {
            // Primeiro gera um salt aleatório para derivar a chave
            byte[] salt = new byte[SALT_LENGTH];
            secureRandom.nextBytes(salt);

            // Deriva a chave AES com a senha e o salt gerado
            SecretKeySpec keySpec = gerarChaveAES(senha, salt);

            // Gera o vetor de inicialização (IV) aleatório para o AES-GCM
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            // Inicializa o Cipher para criptografar
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            // Faz a criptografia dos dados em bytes UTF-8
            byte[] encrypted = cipher.doFinal(dado.getBytes(StandardCharsets.UTF_8));

            // Junta o salt + IV + texto criptografado para guardar tudo junto
            ByteBuffer buffer = ByteBuffer.allocate(salt.length + iv.length + encrypted.length);
            buffer.put(salt);
            buffer.put(iv);
            buffer.put(encrypted);

            // Codifica tudo em Base64 para facilitar armazenamento/transmissão
            return Base64.getEncoder().encodeToString(buffer.array());
        } catch (Exception e) {
            throw new RuntimeException("Erro ao criptografar dado", e);
        }
    }

    // Descriptografa a string que foi criptografada pelo método acima
    // Recebe Base64 com salt + IV + dados e retorna o texto original
    public static String descriptografar(String dadoCriptografado, String senha) {
        try {
            byte[] decoded = Base64.getDecoder().decode(dadoCriptografado);

            ByteBuffer buffer = ByteBuffer.wrap(decoded);

            // Extrai o salt para derivar a chave correta
            byte[] salt = new byte[SALT_LENGTH];
            buffer.get(salt);

            // Extrai o vetor de inicialização (IV) usado na criptografia
            byte[] iv = new byte[GCM_IV_LENGTH];
            buffer.get(iv);

            // Extrai o texto criptografado que sobra no buffer
            byte[] encrypted = new byte[buffer.remaining()];
            buffer.get(encrypted);

            // Regenera a chave AES com a senha e o salt extraído
            SecretKeySpec keySpec = gerarChaveAES(senha, salt);

            // Inicializa o Cipher para descriptografar
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            // Decripta os dados e converte para string UTF-8
            byte[] decrypted = cipher.doFinal(encrypted);

            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao descriptografar dado", e);
        }
    }

    // Método para gerar hash SHA512 em hexadecimal maiúsculo
    public static String toSHA512(String texto) {
        return gerarHashHex(texto, "SHA-512");
    }

    // Método para gerar hash SHA1 em hexadecimal maiúsculo
    public static String toSHA1(String texto) {
        return gerarHashHex(texto, "SHA-1");
    }

    // Método genérico para gerar hash em hexadecimal maiúsculo usando o algoritmo indicado
    private static String gerarHashHex(String texto, String algoritmo) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algoritmo);
            byte[] hash = digest.digest(texto.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                // Converte byte para string hex de 2 dígitos
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString().toUpperCase();
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar hash com " + algoritmo, e);
        }
    }

}
