# Necrypt - Cofre Criptografado Híbrido

Um cofre de senhas local, para linha de comando, que agora oferece um **modelo de segurança híbrido**, permitindo que você escolha entre a portabilidade clássica de uma senha mestra ou a segurança máxima de uma chave atrelada ao seu dispositivo.

Construído sem componentes de rede, ele garante que seus segredos permaneçam exclusivamente sob seu controle. O objetivo deste projeto não é competir com gerenciadores de senha comerciais cheios de recursos, mas sim oferecer uma ferramenta **transparente, auditável e extremamente segura** para quem valoriza o controle total sobre seus dados mais sensíveis.

## 📜 Filosofia e Foco

O Necrypt nasceu da necessidade de um local seguro para armazenar as "receitas" de senhas geradas por ferramentas determinísticas, como o [GeNekyl](https://github.com/Nekyl/GeNekyl). Em vez de salvar a senha final (o produto), o cofre foi projetado para guardar os ingredientes: a **senha mestra**, o **identificador** e o **salt pessoal**.

Essa abordagem aumenta drasticamente a segurança: mesmo que o arquivo do cofre fosse comprometido (o que é extremamente improvável), um invasor teria apenas os componentes, não a senha final de seus serviços.

## ✨ Destaques e Funcionalidades

*   **Modelo de Segurança Híbrido:** Na primeira execução, **você escolhe** como seu cofre irá operar. Essa escolha é permanente e define o paradigma de segurança dos seus dados.
*   **Modo Atrelado ao Dispositivo:** Para segurança máxima, a chave do cofre é gerada aleatoriamente e armazenada no `keyring` nativo do sistema (Keychain, Keystore, etc.). O acesso é liberado via biometria ou PIN do dispositivo, eliminando a necessidade de uma senha mestra.
*   **Desbloqueio Rápido (Modo Senha Mestra):** Combine a robustez de uma senha mestra forte com a conveniência de usar a biometria/PIN do seu dispositivo para desbloqueios rápidos em sessões futuras.
*   **Interface de Linha de Comando Rica:** Utiliza a biblioteca `rich` para uma experiência visualmente agradável e intuitiva no terminal.
*   **Anotações em Markdown:** O campo de observações suporta Markdown, permitindo que você adicione notas detalhadas, listas (`- [x]`), blocos de código (`` ` ``) e muito mais.
*   **Backup e Restauração Seguros:** Exporte e importe seu cofre com uma camada adicional de criptografia, protegida por uma senha de backup dedicada.
*   **Protocolo de Autodestruição:** No modo Senha Mestra, após 5 tentativas de login falhas, o cofre inicia um protocolo que apaga todos os arquivos relacionados, protegendo contra ataques de força bruta.
*   **Formatação Segura:** Uma opção para apagar permanentemente e de forma segura todos os dados, exigindo múltiplas confirmações e a devida autenticação.

## 📸 Screenshots

A seguir, algumas imagens que ilustram o funcionamento do Necrypt:

### Menu Principal e Adição de Segredo

| Menu Principal | Adicionar Novo Segredo |
| :---: | :---: |
| <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/Welcome.png" width="300"> | <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/AddSecret.png" width="300"> |

### Listagem e Consulta de Segredos

| Listar Segredos | Consultar Segredo |
| :---: | :---: |
| <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/SearchIDs.png" width="300"> | <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/Consult.png" width="300"> |

### Backup e Restauração

| Exportar Backup | Importar Backup |
| :---: | :---: |
| <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/BackupDown.png" width="300"> | <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/BackUP.png" width="300"> |

### Formatação do Cofre

| Formatar Cofre |
| :---: |
| <img src="https://raw.githubusercontent.com/Nekyl/Necrypt/refs/heads/main/assets/Wipe.png" width="150"> |

## 🔐 Segurança em Primeiro Lugar: Uma Arquitetura Flexível

A segurança evoluiu de uma fundação única para uma arquitetura flexível, onde você define o equilíbrio entre segurança e portabilidade.

### A Fundação: Criptografia Inabalável (AES-256-GCM + Argon2id)

Independente do modo escolhido, a base criptográfica é a mesma e utiliza os padrões mais robustos disponíveis:
*   **Criptografia do Banco de Dados:** O coração do cofre é um banco de dados SQLite criptografado via **SQLCipher**. A criptografia é configurada para usar **AES-256-GCM**. O modo GCM (Galois/Counter Mode) é um padrão moderno que oferece tanto confidencialidade quanto autenticidade dos dados, protegendo contra corrupção e adulteração.
*   **Derivação de Chave Robusta:** Senhas humanas sempre passam pelo **Argon2id**, o vencedor da [Password Hashing Competition](https://www.password-hashing.net/), para serem transformadas em chaves criptográficas seguras, tornando ataques de força bruta extremamente lentos e caros.

### Modelo 1: Senha Mestra (Portabilidade e Controle Clássico)

Este é o modo tradicional, ideal para quem precisa de **portabilidade** para acessar o cofre em múltiplos dispositivos.
*   **Como Funciona:** Seu cofre é protegido por uma única Senha Mestra. Os arquivos do cofre (`.db`, `.hash`, `.salt`) podem ser copiados para outro computador, e o acesso é liberado com a digitação da senha.
*   **Derivação de Chave em Duas Etapas:**
    1.  **Verificação Rápida:** Sua senha é primeiro verificada contra um *hash* armazenado localmente (`.db.hash`). Isso permite que o programa recuse rapidamente senhas incorretas sem tentar decifrar o banco de dados.
    2.  **Derivação da Chave do Cofre:** Se a senha estiver correta, ela é então combinada com um *salt* diferente e exclusivo do banco de dados (`.db.salt`) para derivar a chave AES-256 real que abre o cofre.
*   **Recurso de Conveniência:** Para evitar digitar a senha toda vez, você pode habilitar o **Desbloqueio Rápido**, que usa o `keyring` do sistema para permitir o acesso via biometria/PIN nas próximas vezes.

### Modelo 2: Atrelado ao Dispositivo (Segurança Máxima e Conveniência)

Este modo oferece segurança superior ao **remover o elo mais fraco da cadeia: a senha humana memorizada.**
*   **Como Funciona:** Uma chave de criptografia de 256 bits, longa e aleatória, é gerada e armazenada de forma segura no chaveiro (`keyring`) do seu sistema operacional. **Não existe uma senha mestra para adivinhar ou quebrar.** Sua biometria ou PIN apenas autoriza o sistema a liberar essa chave para o Necrypt.
*   **Ponto Forte:** Segurança offline superior. Se os arquivos do cofre forem roubados, eles são inúteis para um atacante. Não há uma senha para ser atacada por força bruta. A chave está segura em outro lugar, protegida pelo seu dispositivo.
*   **Ideal Para:** Usuários que usarão o cofre em um único dispositivo e priorizam a máxima segurança contra o roubo dos arquivos.

### Limpeza Segura de Memória & Backups Criptografados

*   **Limpeza de Memória:** Para evitar que senhas e chaves permaneçam na memória RAM, o Necrypt utiliza uma função `secure_wipe` que acessa a memória em baixo nível (via `ctypes.memset`) para sobrescrever os *buffers* com zeros.
*   **Backups Seguros:** As exportações são sempre criptografadas com **AES-GCM**, usando uma chave derivada de uma senha de backup dedicada via Argon2id. Seus backups são tão seguros quanto o próprio cofre.

## 🚀 O Fluxo de Trabalho Ideal: Necrypt + GeNekyl

O propósito original do Necrypt brilha em qualquer um dos modos de segurança. Use-o com um gerador de senhas determinísticas como o **GeNekyl**.

**O conceito:** Você não precisa mais salvar senhas complexas e aleatórias. Em vez disso, você salva os "ingredientes" que o GeNekyl usa para gerar a mesma senha complexa todas as vezes.

#### Passo a Passo do Uso Inteligente:

1.  **No GeNekyl:**
    *   Defina uma **Senha Mestra** forte.
    *   Use um **Identificador** claro e único (ex: `github.com`).
    *   Adicione um **Salt Pessoal** (opcional, mas recomendado).
    *   Gere a senha e use-a no serviço desejado.

2.  **No Necrypt:**
    *   Crie uma nova entrada (`Adicionar novo segredo`).
    *   **Identificador:** Dê um nome que o lembre do serviço (ex: "GitHub (Nekyl)").
    *   **Senha que vamos guardar:** Salve aqui a **Senha Mestra** que você usou no GeNekyl.
    *   **Salt pessoal:** Salve aqui o **Salt Pessoal** que você usou.
    *   **Observações (Markdown):** Anote o **Identificador** exato do GeNekyl e quaisquer outros parâmetros que você alterou (ex: `tamanho: 20, sem símbolos`).

**Por que isso é tão seguro?**
Sua senha final (`G&n3kYl-!s-@w3s0m3`) não está armazenada em lugar nenhum. Para acessá-la, um atacante precisaria comprometer seu cofre, entender seu fluxo de trabalho e ter acesso à lógica do GeNekyl.

## 🛠️ Como Usar

### Pré-requisitos

Certifique-se de ter o Python 3 instalado. Recomenda-se criar um ambiente virtual.

```bash
pip install --no-cache-dir --no-binary :all: sqlcipher3 appdirs cryptography argon2-cffi rich secure-getpass prompt-toolkit flask requests keyring
```

Ou a partir do arquivo de dependências:
```bash
pip install -r requirements.txt
```

### Executando

Clone o repositório e execute o script principal:

```bash
# Se Termux, pode ser necessário:
pkg install python-dev clang openssl-dev

git clone https://github.com/Nekyl/Necrypt.git
cd Necrypt

# Se você usa a versão compilada de secure_getpass
python setup.py build_ext --inplace

# Execute o aplicativo
python cofre.py
```

Na primeira execução, você será guiado para **escolher seu modelo de segurança**. Esta decisão é crucial, permanente e definirá como seu cofre funcionará.

## ⚠️ Aviso Final

Este é um projeto pessoal construído com as melhores práticas de segurança em mente. No entanto, a segurança de seus dados depende fundamentalmente de três coisas:
1.  **A força da sua senha mestra** (no modo clássico) e a **segurança do seu dispositivo** (no modo atrelado).
2.  A segurança do ambiente onde você executa este script.
3.  Manter backups regulares e seguros.

Use com sabedoria.

## 🤝 Contribuições

Contribuições são bem-vindas! Se você encontrar um bug, tiver uma sugestão de melhoria ou quiser adicionar uma nova funcionalidade, sinta-se à vontade para abrir uma *Issue* ou enviar um *Pull Request*.

## 📜 Licença

Este projeto é licenciado sob a **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License**.

[![Licença CC BY-NC-SA 4.0](https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png)](http://creativecommons.org/licenses/by-nc-sa/4.0/)

Para ver uma cópia desta licença, visite [http://creativecommons.org/licenses/by-nc-sa/4.0/](http://creativecommons.org/licenses/by-nc-sa/4.0/).
