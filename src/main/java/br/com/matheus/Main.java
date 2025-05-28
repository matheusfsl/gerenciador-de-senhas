import Model.Credencial;
import Model.Usuario;
import Service.AutenticacaoService;
import Service.CriptografiaService;
import Service.SenhaService;
import Service.VazamentoService;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Main {
    private static List<Usuario> usuarios = new ArrayList<>();
    private static List<Credencial> credenciais = new ArrayList<>();
    private static Usuario usuarioLogado = null;
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        exibirMenuPrincipal();
    }

    private static void exibirMenuPrincipal() {
        while (true) {
            System.out.println("\n=== Gerenciador de Senhas ===");
            if (usuarioLogado == null) {
                System.out.println("1. Cadastrar usuário");
                System.out.println("2. Login");
                System.out.println("3. Sair");
            } else {
                System.out.println("1. Adicionar credencial");
                System.out.println("2. Listar credenciais");
                System.out.println("3. Gerar senha forte");
                System.out.println("4. Verificar senha vazada");
                System.out.println("5. Configurar 2FA");
                System.out.println("6. Logout");
            }

            System.out.print("Escolha uma opção: ");
            int opcao = lerInteiroSeguro();

            if (usuarioLogado == null) {
                switch (opcao) {
                    case 1 -> cadastrarUsuario();
                    case 2 -> fazerLogin();
                    case 3 -> System.exit(0);
                    default -> System.out.println("Opção inválida!");
                }
            } else {
                switch (opcao) {
                    case 1 -> adicionarCredencial();
                    case 2 -> listarCredenciais();
                    case 3 -> gerarSenhaForte();
                    case 4 -> verificarSenhaVazada();
                    case 5 -> configurar2FA();
                    case 6 -> logout();
                    default -> System.out.println("Opção inválida!");
                }
            }
        }
    }

    private static void cadastrarUsuario() {
        String email;
        while (true) {
            System.out.print("Email: ");
            email = scanner.nextLine().trim();
            if (email.matches("^[\\w\\.-]+@[\\w\\.-]+\\.\\w+$")) break;
            System.out.println("Email inválido. Tente novamente.");
        }

        String nome;
        do {
            System.out.print("Nome: ");
            nome = scanner.nextLine().trim();
            if (nome.isEmpty()) System.out.println("Nome não pode ser vazio.");
        } while (nome.isEmpty());

        String senha;
        do {
            System.out.print("Senha (mínimo 6 caracteres): ");
            senha = scanner.nextLine();
            if (senha.length() < 6) System.out.println("Senha muito curta.");
        } while (senha.length() < 6);

        if (VazamentoService.verificarSenhaVazada(senha)) {
            System.out.println("Atenção: Esta senha foi encontrada em vazamentos de dados!");
        }

        String senhaHash = CriptografiaService.hashSenha(senha);
        Usuario novoUsuario = new Usuario(email, nome);
        novoUsuario.setSenhaHash(senhaHash);
        usuarios.add(novoUsuario);

        System.out.println("Usuário cadastrado com sucesso!");
    }

    private static void fazerLogin() {
        System.out.print("Email: ");
        String email = scanner.nextLine().trim();
        System.out.print("Senha: ");
        String senha = scanner.nextLine();

        for (Usuario usuario : usuarios) {
            if (usuario.getEmail().equalsIgnoreCase(email)) {
                if (CriptografiaService.verificarSenha(senha, usuario.getSenhaHash())) {
                    if (usuario.getSecret2FA() != null && !usuario.getSecret2FA().isEmpty()) {
                        if (!AutenticacaoService.autenticar2FA(usuario)) {
                            System.out.println("Código 2FA inválido!");
                            return;
                        }
                    }
                    usuarioLogado = usuario;
                    System.out.println("Login realizado com sucesso!");
                    return;
                }
            }
        }
        System.out.println("Email ou senha incorretos!");
    }

    private static void adicionarCredencial() {
        System.out.print("URL do serviço: ");
        String url = scanner.nextLine().trim();
        if (url.isEmpty()) {
            System.out.println("A URL não pode ser vazia.");
            return;
        }

        System.out.print("Email/usuário: ");
        String email = scanner.nextLine().trim();
        if (email.isEmpty()) {
            System.out.println("O email de login não pode ser vazio.");
            return;
        }

        System.out.print("Senha (deixe em branco para gerar uma): ");
        String senha = scanner.nextLine();

        if (senha.isEmpty()) {
            senha = SenhaService.gerarSenhaForte(12);
            System.out.println("Senha gerada: " + senha);
        }

        String chave = usuarioLogado.getSenhaHash().substring(0, 16);
        String senhaCriptografada = CriptografiaService.criptografar(senha, chave);

        Credencial novaCredencial = new Credencial(email, url, usuarioLogado.getId());
        novaCredencial.setSenhaCriptografada(senhaCriptografada);
        credenciais.add(novaCredencial);

        System.out.println("Credencial adicionada com sucesso!");
    }

    private static void listarCredenciais() {
        System.out.println("\nSuas credenciais:");
        boolean encontrou = false;
        for (Credencial credencial : credenciais) {
            if (credencial.getUsuarioId() == usuarioLogado.getId()) {
                encontrou = true;
                String chave = usuarioLogado.getSenhaHash().substring(0, 16);
                String senha = CriptografiaService.descriptografar(credencial.getSenhaCriptografada(), chave);

                System.out.println("URL: " + credencial.getUrl());
                System.out.println("Email: " + credencial.getEmail());
                System.out.println("Senha: " + senha);
                System.out.println("Força: " + SenhaService.calcularForcaSenha(senha) + "/5");
                System.out.println("-------------------");
            }
        }
        if (!encontrou) System.out.println("Nenhuma credencial encontrada.");
    }

    private static void gerarSenhaForte() {
        System.out.print("Tamanho da senha (mínimo 8, padrão 12): ");
        String input = scanner.nextLine();
        int tamanho = 12;
        if (!input.isEmpty()) {
            try {
                tamanho = Integer.parseInt(input);
                if (tamanho < 8) {
                    System.out.println("Tamanho muito pequeno. Usando 12.");
                    tamanho = 12;
                }
            } catch (NumberFormatException e) {
                System.out.println("Valor inválido. Usando 12.");
            }
        }

        String senha = SenhaService.gerarSenhaForte(tamanho);
        System.out.println("Senha gerada: " + senha);
        System.out.println("Força: " + SenhaService.calcularForcaSenha(senha) + "/5");
    }

    private static void verificarSenhaVazada() {
        System.out.print("Digite a senha para verificar: ");
        String senha = scanner.nextLine();

        if (senha.isEmpty()) {
            System.out.println("Senha não pode ser vazia.");
            return;
        }

        if (VazamentoService.verificarSenhaVazada(senha)) {
            System.out.println("Esta senha foi encontrada em vazamentos de dados!");
        } else {
            System.out.println("Esta senha não foi encontrada em vazamentos conhecidos.");
        }
    }

    private static void configurar2FA() {
        if (usuarioLogado.getSecret2FA() == null || usuarioLogado.getSecret2FA().isEmpty()) {
            String secret = AutenticacaoService.gerarSecret2FA();
            usuarioLogado.setSecret2FA(secret);

            System.out.println("Escaneie este QR Code no seu autenticador:");
            System.out.println(AutenticacaoService.getQRCode(secret, usuarioLogado.getEmail()));
            System.out.println("Ou adicione manualmente com esta key: " + secret);


            System.out.print("Digite o código gerado no seu app autenticador: ");
            String codigo = scanner.nextLine().trim();
            if (!AutenticacaoService.verificarCodigo2FA(secret, codigo)) {
                usuarioLogado.setSecret2FA(null);
                System.out.println("Código inválido! Tente configurar o 2FA novamente.");
            } else {
                System.out.println("2FA configurado com sucesso!");
            }

        } else {
            System.out.println("2FA já está configurado para esta conta.");
            System.out.println("Secret: " + usuarioLogado.getSecret2FA());
        }
    }

    private static void logout() {
        usuarioLogado = null;
        System.out.println("Logout realizado com sucesso!");
    }

    // Função para ler inteiros com segurança
    private static int lerInteiroSeguro() {
        while (true) {
            String input = scanner.nextLine();
            try {
                return Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.print("Entrada inválida. Digite um número: ");
            }
        }
    }
}