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
- Criptografia e descriptografia de dados sensíveis usando AES no modo GCM com autenticação
- Geração de chave AES segura e com tamanho adequado a partir de uma senha base usando SHA-256
- Uso de vetor de inicialização  aleatório para cada criptografia, aumentando a segurança contra ataques de padrão
- Hashing seguro de senhas com BCrypt, incluindo geração automática de salt e fator de custo ajustável
- Verificação segura de correspondência de senhas hashadas com BCrypt
- Geração de hash SHA-512 para uso em verificação de vazamentos de senhas

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

![image](https://github.com/user-attachments/assets/4c207929-02d9-4b44-ab1e-e487d59ae68d)


---


## Como usar

git clone https://github.com/matheusfsl/gerenciador-de-senhas.git
