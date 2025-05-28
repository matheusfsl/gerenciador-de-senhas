package Service;

import Model.Usuario;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

import java.util.Scanner;

public class AutenticacaoService {
    // gera e retorna um segredo único para configurar o 2FA de um usuário
    public static String gerarSecret2FA() {
        return new DefaultSecretGenerator().generate();
    }

    // gera a URL no formato padrão OTPAUTH que pode ser transformada em um qr Code
    // e escaneada por aplicativos autenticadores como Google Authenticator
    public static String getQRCode(String secret, String email) {
        return "otpauth://totp/" + email + "?secret=" + secret + "&issuer=PasswordManager";
    }

    // vrifica se o código digitado pelo usuário é válido com base no segredo e no tempo atual
    public static boolean verificarCodigo2FA(String code, String secret) {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        return verifier.isValidCode(secret, code);
    }

    // método interativo que pede ao usuário para digitar o código 2FA no console,
    // e chama o método de verificação com o segredo do usuário
    public static boolean autenticar2FA(Usuario usuario) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Digite o código do seu autenticador:");
        String code = scanner.nextLine();
        return verificarCodigo2FA(code, usuario.getSecret2FA());
    }
}
