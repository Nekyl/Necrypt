# Necrypt - Cofre Criptografado

Um cofre de senhas local, para linha de comando, que prioriza a segurança e a simplicidade. Construído sem componentes de rede, ele garante que seus segredos permaneçam exclusivamente sob seu controle, no seu dispositivo.

O objetivo deste projeto não é competir com gerenciadores de senha comerciais cheios de recursos, mas sim oferecer uma ferramenta **transparente, auditável e extremamente segura** para quem valoriza o controle total sobre seus dados mais sensíveis.

## 📜 Filosofia e Foco

O Necrypt nasceu da necessidade de um local seguro para armazenar as "receitas" de senhas geradas por ferramentas determinísticas, como o [GeNekyl](https://github.com/Nekyl/GeNekyl). Em vez de salvar a senha final (o produto), o cofre foi projetado para guardar os ingredientes: a **senha mestra**, o **identificador** e o **salt pessoal**.

Essa abordagem aumenta drasticamente a segurança: mesmo que o arquivo do cofre fosse comprometido (o que é extremamente improvável), um invasor teria apenas os componentes, não a senha final de seus serviços.

## ✨ Destaques e Funcionalidades

*   **Interface de Linha de Comando Rica:** Utiliza a biblioteca `rich` para uma experiência visualmente agradável e intuitiva no terminal.
*   **Anotações em Markdown:** O campo de observações suporta Markdown, permitindo que você adicione notas detalhadas, listas (`- [x]`), blocos de código (`` ` ``) e muito mais.
*   **Backup e Restauração Seguros:** Exporte e importe seu cofre com uma camada adicional de criptografia, protegida por uma senha de backup dedicada.
*   **Protocolo de Autodestruição:** Após 5 tentativas de login falhas, o cofre inicia um protocolo de segurança que sobrescreve o banco de dados com dados aleatórios e apaga todos os arquivos relacionados, protegendo contra ataques de força bruta.
*   **Formatação Segura:** Uma opção para apagar permanentemente e de forma segura todos os dados, exigindo múltiplas confirmações e a senha mestra.

## 📸 Screenshots

A seguir, algumas imagens que ilustram o funcionamento do Necrypt:

### Menu Principal e Adição de Segredo

| Menu Principal | Adicionar Novo Segredo |
| :----------------------------------------------------------: | :----------------------------------------------------------: |
| <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/Welcome.png" width="300"> | <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/AddSecret.png" width="300"> |

### Consulta e Listagem de Segredos

| Listar Segredos | Consultar Segredo |
| :----------------------------------------------------------: | :----------------------------------------------------------: |
| <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/SearchIDs.png" width="300"> | <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/Consult.png" width="300"> |

### Backup e Restauração

| Exportar Backup | Importar Backup |
| :----------------------------------------------------------: | :----------------------------------------------------------: |
| <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/BackupDown.png" width="300"> | <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/BackUP.png" width="300"> |

### Formatação do Cofre

| Formatar Cofre |
| :----------------------------------------------------------: |
| <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/Wipe.png" width="150"> |

## 🔐 Segurança em Primeiro Lugar: Uma Análise Profunda

A segurança não é uma funcionalidade, é a fundação deste projeto. Cada escolha foi feita para minimizar a superfície de ataque e usar criptografia de ponta.

### 1. Criptografia do Banco de Dados com SQLCipher

O coração do cofre é um banco de dados SQLite criptografado via **SQLCipher**.
*   **Algoritmo:** A criptografia é configurada para usar **AES-256-GCM**. O modo GCM (Galois/Counter Mode) é um padrão moderno que oferece tanto confidencialidade quanto autenticidade dos dados, protegendo contra corrupção e adulteração.

### 2. Derivação de Chave Robusta com Argon2id

A senha que você digita nunca é usada diretamente para criptografar o cofre. Em vez disso, ela passa por um processo de derivação de chave (KDF) rigoroso usando **Argon2id**, o vencedor da [Password Hashing Competition](https://www.password-hashing.net/).

O processo é dividido em duas etapas cruciais:
1.  **Verificação Rápida:** Sua senha é primeiro verificada contra um *hash* armazenado localmente (`.db.hash`). Isso permite que o programa recuse rapidamente senhas incorretas sem tentar decifrar o banco de dados.
2.  **Derivação da Chave do Cofre:** Se a senha estiver correta, ela é então combinada com um *salt* diferente e exclusivo do banco de dados (`.db.salt`) para derivar a chave AES-256 real que abre o cofre.

Essa separação garante que, mesmo que o hash de verificação vaze, o *salt* para a chave de criptografia permanece secreto, adicionando uma camada extra de proteção.

### 3. Limpeza Segura de Memória

Senhas e chaves de criptografia são dados voláteis e sensíveis. Para evitar que permaneçam na memória RAM após o uso, o Necrypt utiliza uma função `secure_wipe` que acessa a memória em baixo nível (via `ctypes.memset`) para sobrescrever os *buffers* com zeros, limpando-os efetivamente.

### 4. Backups Criptografados de ponta a ponta

Quando você exporta um backup, os dados não são simplesmente jogados em um arquivo. O conteúdo do cofre é serializado e, em seguida, criptografado usando **AES-GCM** com uma chave derivada da senha de backup que você fornece (também usando Argon2id). Isso significa que seus backups são tão seguros quanto o próprio cofre.

## 🚀 O Fluxo de Trabalho Ideal: Necrypt + GeNekyl

Para extrair o potencial máximo desta ferramenta, use-a em conjunto com um gerador de senhas determinísticas como o **GeNekyl**.

**O conceito:** Você não precisa mais salvar senhas complexas e aleatórias. Em vez disso, você salva os "ingredientes" que o GeNekyl usa para gerar a mesma senha complexa todas as vezes.

#### Passo a Passo do Uso Inteligente:

1.  **No GeNekyl (Modo Mestre):**
    *   Defina uma **Senha Mestra** forte (pode ser a mesma para vários serviços ou única, você decide).
    *   Use um **Identificador** claro e único (ex: `github.com`, `email_pessoal_google`).
    *   Adicione um **Salt Pessoal** (opcional, mas recomendado para segurança extra).
    *   Configure os parâmetros (tamanho, caracteres) e gere a senha. Use-a no serviço desejado.

2.  **No Necrypt:**
    *   Crie uma nova entrada (`Adicionar novo segredo`).
    *   **Identificador:** Dê um nome que o lembre do serviço (ex: "GitHub (Nekyl)").
    *   **Senha que vamos guardar:** Salve aqui a **Senha Mestra** que você usou no GeNekyl.
    *   **Salt pessoal:** Salve aqui o **Salt Pessoal** que você usou.
    *   **Observações (Markdown):** Anote o **Identificador** exato do GeNekyl e quaisquer outros parâmetros que você alterou (ex: tamanho 20, sem símbolos).

**Por que isso é tão seguro?**

*   **Sem Armazenamento de Senha Final:** Sua senha real (`G&n3kYl-!s-@w3s0m3`) não está armazenada em lugar nenhum.
*   **Resiliência:** Se você precisar acessar sua conta do GitHub, basta abrir o cofre, pegar os três "ingredientes", colocá-los no GeNekyl e a sua senha será recriada perfeitamente.
*   **Compartimentalização:** O cofre protege os ingredientes. O GeNekyl contém a lógica de geração. Um atacante precisaria comprometer ambos e entender seu fluxo de trabalho para ter acesso a algo.

## 🛠️ Como Usar

### Pré-requisitos

Certifique-se de ter o Python 3 instalado. As dependências estão listadas abaixo. Recomenda-se criar um ambiente virtual.

```bash
pip install pysqlcipher3-binary appdirs cryptography argon2-cffi rich secure-getpass prompt-toolkit
```

### Executando

Clone o repositório e execute o script:

```bash
git clone https://github.com/Nekyl/Necrypt.git
cd Necrypt
Python setup.py build_ext --inplace
python cofre.py
```

Na primeira execução, você será solicitado a criar sua senha de acesso principal. **Não há como recuperar esta senha.** Se você a esquecer, a única opção é apagar os arquivos do cofre e começar de novo (ou restaurar um backup, se tiver).

## ⚠️ Aviso Final

Este é um projeto pessoal construído com as melhores práticas de segurança em mente. No entanto, a segurança de seus dados depende fundamentalmente de três coisas:
1.  **A força da sua senha mestra.**
2.  **A segurança do ambiente onde você executa este script.**
3.  **Manter backups regulares e seguros.**

Use com sabedoria.

## 📜 Licença

Este projeto é licenciado sob a **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License**.

[![Licença CC BY-NC-SA 4.0](https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png)](http://creativecommons.org/licenses/by-nc-sa/4.0/)

Para ver uma cópia desta licença, visite [http://creativecommons.org/licenses/by-nc-sa/4.0/](http://creativecommons.org/licenses/by-nc-sa/4.0/).
