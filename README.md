# Password Manager - Serviços de Segurança em Java

Este projeto contém serviços essenciais para gerenciamento seguro de senhas e autenticação, desenvolvidos em Java. Inclui funcionalidades para:

- Autenticação de dois fatores (2FA) baseada em TOTP (Time-Based One-Time Password)
- Criptografia e descriptografia AES para armazenamento seguro de dados
- Hashing e verificação de senhas usando BCrypt
- Geração de senhas fortes e avaliação da força da senha

---

## Funcionalidades

### 1. Autenticação 2FA

- Geração de secret para 2FA
- Criação de URLs QR Code para configuração em aplicativos autenticadores (Google Authenticator, Authy etc.)
- Verificação de códigos TOTP gerados no dispositivo do usuário

### 2. Criptografia
- Criptografia e descriptografia usando AES no modo GCM com autenticação
- Geração de chave AES segura a partir de senha base via SHA-256
- Uso de vetor de inicialização (IV) aleatório para cada criptografia
- Hashing seguro de senhas com BCrypt
- Verificação segura de senhas com BCrypt
- Geração de hash SHA-512 para verificação de vazamento de senhas
- Geração de hash SHA-1 para necessidades específicas

### 3. Senhas

- Geração de senhas aleatórias fortes, com letras maiúsculas, minúsculas, números e símbolos
- Cálculo da força da senha baseado em comprimento e diversidade de caracteres

---

## Tecnologias e Bibliotecas

- Java 21+
- API externa: Have I Been Pwned - Passwords
- Java Cryptography Architecture (JCA) para criptografia AES

---

## Teste de qualidade 

![image](https://github.com/user-attachments/assets/eaf863ae-e5e7-401f-a665-c4e484bda048)


---


## Como usar

git clone https://github.com/matheusfsl/gerenciador-de-senhas.git
