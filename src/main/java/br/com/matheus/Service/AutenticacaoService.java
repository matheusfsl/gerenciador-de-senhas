package br.com.matheus.Service;

import br.com.matheus.Model.Usuario;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

import java.util.Scanner;

public class AutenticacaoService {

    private static final TimeProvider timeProvider = new SystemTimeProvider();
    private static final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private static final CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    /**
     * Gera um segredo seguro para o 2FA do usuário
     */
    public static String gerarSecret2FA() {
        return new DefaultSecretGenerator().generate();
    }

    /**
     * Gera uma URL compatível com Google Authenticator e outros apps TOTP
     *
     * @param secret Segredo 2FA do usuário
     * @param email  E-mail do usuário (usado como identificador)
     * @return URL no padrão otpauth://
     */
    public static String getQRCode(String secret, String email) {
        return String.format("otpauth://totp/%s?secret=%s&issuer=PasswordManager", email, secret);
    }

    /**
     * Verifica se o código fornecido é válido para o segredo
     *
     * @param code   Código TOTP fornecido pelo usuário
     * @param secret Segredo 2FA do usuário
     * @return true se o código for válido
     */
    public static boolean verificarCodigo2FA(String code, String secret) {
        try {
            return verifier.isValidCode(secret, code);
        } catch (Exception e) {
            System.err.println("Erro ao verificar o código 2FA: " + e.getMessage());
            return false;
        }
    }

    /**
     * Autentica o usuário solicitando o código via terminal
     * (apenas para testes ou aplicações CLI; não use em produção web)
     *
     * @param usuario Usuário com segredo 2FA
     * @return true se o código digitado for válido
     */
    public static boolean autenticar2FA(Usuario usuario) {
        System.out.print("Digite o código do seu autenticador: ");
        try (Scanner scanner = new Scanner(System.in)) {
            String code = scanner.nextLine().trim();
            return verificarCodigo2FA(code, usuario.getSecret2FA());
        } catch (Exception e) {
            System.err.println("Erro ao ler o código do console: " + e.getMessage());
            return false;
        }
    }
}
