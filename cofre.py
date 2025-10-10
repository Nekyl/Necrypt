# cofre.py
import subprocess
import os
import hashlib
import sys
import json
from pathlib import Path
import ctypes
import hmac
from typing import Optional, Tuple

from sqlcipher3 import dbapi2 as sqlite
from appdirs import user_data_dir

# --- IMPORTS DE CRIPTOGRAFIA ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2 import PasswordHasher, low_level
from argon2.exceptions import VerifyMismatchError

# --- IMPORT DE DESBLOQUEIO RÁPIDO ---
import keyring

# --- Importações do Rich ---
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.markdown import Markdown
from rich.prompt import Prompt, Confirm
from rich.align import Align


import subprocess 
import sys 
# Importando função segura de captura de senha
from secure_getpass import get_secure_pass

from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings

# --- Inicializações e Configurações ---
console = Console()
ph = PasswordHasher(time_cost=6, memory_cost=524288, parallelism=8)

NOME_APP = "Necrypt"
AUTOR_APP = "Nekyl"
USER_NAME = "SEU_NOME"
DIRETORIO_DADOS = user_data_dir(NOME_APP, AUTOR_APP)
os.makedirs(DIRETORIO_DADOS, exist_ok=True)
NOME_DO_BANCO = os.path.join(DIRETORIO_DADOS, "meu_cofre_pessoal.db")
CAMINHO_HASH_DB = os.path.join(DIRETORIO_DADOS, "meu_cofre_pessoal.db.hash")
CAMINHO_SALT_DB = os.path.join(DIRETORIO_DADOS, "meu_cofre_pessoal.db.salt")
CAMINHO_QUICK_UNLOCK = os.path.join(DIRETORIO_DADOS, "quick_unlock.session")
CAMINHO_VAULT_MODE = os.path.join(DIRETORIO_DADOS, "vault_mode.cfg")
KEYRING_SERVICE_NAME = f"{NOME_APP}-{USER_NAME}"

# --- Centralizando o estilo ---
THEME = {
    "panel.main": "magenta",
    "panel.menu": "blue",
    "panel.action": "yellow",
    "panel.danger": "bold red",
    "prompt.default": "cyan",
    "prompt.confirm": "bold yellow",
    "feedback.success": "bold green",
    "feedback.error": "bold red",
    "feedback.info": "yellow",
    "feedback.special": "bold blue",
    "title": "bold bright_white",
}

# --- FUNÇÃO DE LIMPEZA DE MEMÓRIA ---
def secure_wipe(buffer: bytearray):
    """Sobrescreve um buffer mutável (bytearray) com zeros para limpar dados sensíveis."""
    try:
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buffer)), 0, len(buffer))
    except Exception:
        for i in range(len(buffer)):
            buffer[i] = 0

def limpar_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

# --- FUNÇÕES DE AUTENTICAÇÃO E CONEXÃO ---

def autenticar_com_dispositivo_termux() -> bool:
    """Usa o termux-api para acionar a autenticação biométrica/PIN do Android."""
    console.print(f"[{THEME['feedback.info']}]Aguardando autenticação do dispositivo via Termux:API...[/]")
    try:
        resultado = subprocess.run(['termux-fingerprint'], capture_output=True, text=True, timeout=60)
        if resultado.returncode != 0:
            console.print(f"[{THEME['feedback.error']}]Autenticação cancelada ou falhou. ({resultado.stderr.strip()})[/]")
            return False
        saida_json = json.loads(resultado.stdout)
        if saida_json.get("auth_result") == "AUTH_RESULT_SUCCESS":
            return True
        else:
            console.print(f"[{THEME['feedback.error']}]Falha na autenticação do dispositivo: {saida_json.get('error_msg')}[/]")
            return False
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired, Exception) as e:
        console.print(f"[{THEME['feedback.error']}]Erro durante a autenticação: {e}[/]")
        return False

def conectar_com_chave_derivada(senha_acesso: bytearray) -> Optional[sqlite.Connection]:
    """Deriva uma chave da senha mestra e conecta ao banco de dados."""
    try:
        with open(CAMINHO_SALT_DB, "rb") as f: db_salt = f.read()
        chave_db = low_level.hash_secret_raw(
            secret=bytes(senha_acesso), salt=db_salt, time_cost=6, memory_cost=524288,
            parallelism=8, hash_len=32, type=low_level.Type.ID
        )
        conn = sqlite.connect(NOME_DO_BANCO)
        chave_db_hex = chave_db.hex()
        conn.execute(f"PRAGMA key = \"x'{chave_db_hex}'\"")
        conn.execute("PRAGMA kdf_iter = 1")
        conn.execute("PRAGMA cipher = 'aes-256-gcm'")
        conn.execute("PRAGMA cipher_page_size = 4096")
        conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='segredos'")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS segredos (identificador TEXT PRIMARY KEY NOT NULL, senha_mestra TEXT NOT NULL, salt_pessoal TEXT, observacao TEXT)""")
        conn.commit()
        return conn
    except sqlite.DatabaseError:
        console.print(f"\n[{THEME['feedback.error']}]ERRO GRAVE: A senha está correta, mas o arquivo do cofre parece corrompido.[/]\n")
        return None
    except Exception as e:
        console.print(f"Erro inesperado ao conectar: {e}")
        return None

def login_modo_senha_mestra() -> Optional[sqlite.Connection]:
    """Lida com o fluxo de login para um cofre no modo Senha Mestra."""
    conn = None
    senha_acesso_db_bytes = tentar_desbloqueio_rapido()
    if senha_acesso_db_bytes:
        try:
            with open(CAMINHO_HASH_DB, "r") as f: hash_db = f.read()
            ph.verify(hash_db, bytes(senha_acesso_db_bytes))
            conn = conectar_com_chave_derivada(senha_acesso_db_bytes)
            if conn:
                console.print(f"\n[{THEME['feedback.success']}]Desbloqueio rápido bem-sucedido! Bem-vindo de volta, {USER_NAME}.[/]\n")
            else:
                senha_acesso_db_bytes = None
        except (VerifyMismatchError, FileNotFoundError):
            console.print(f"\n[{THEME['feedback.error']}]A senha da sessão é inválida. Por favor, entre com a senha mestra.[/]\n")
            senha_acesso_db_bytes = None
        finally:
            if senha_acesso_db_bytes: secure_wipe(senha_acesso_db_bytes)
    
    if not conn:
        for _ in range(5):
            senha_acesso_db_bytes = None
            try:
                senha_str = get_secure_pass("Senha de acesso, por favor: ")
                senha_acesso_db_bytes = bytearray(senha_str.encode('utf-8'))
                del senha_str
                with open(CAMINHO_HASH_DB, "r") as f: hash_db = f.read()
                ph.verify(hash_db, bytes(senha_acesso_db_bytes))
                console.print(f"\n[{THEME['feedback.info']}]Chave aceita. Abrindo o cofre...[/]")
                conn = conectar_com_chave_derivada(senha_acesso_db_bytes)
                if conn:
                    console.print(f"\n[{THEME['feedback.success']}]Cofre desbloqueado. Bem-vindo de volta, {USER_NAME}.[/]\n")
                    return conn
                else:
                    console.print(f"\n[{THEME['feedback.error']}]Acesso negado.[/]\n")
            except VerifyMismatchError:
                console.print(f"\n[{THEME['feedback.error']}]Acesso negado.[/]\n")
            finally:
                if senha_acesso_db_bytes: secure_wipe(senha_acesso_db_bytes)
    return conn

def login_modo_dispositivo() -> Optional[sqlite.Connection]:
    """Lida com o fluxo de login para um cofre no modo Atrelado ao Dispositivo."""
    db_key = None
    try:
        if 'ANDROID_ROOT' in os.environ:
            if not autenticar_com_dispositivo_termux(): return None
        else:
            console.print(f"[{THEME['feedback.info']}]Acessando o chaveiro do sistema para abrir o cofre...[/]")

        key_hex = keyring.get_password(KEYRING_SERVICE_NAME, USER_NAME)
        if not key_hex:
            console.print(f"[{THEME['feedback.error']}]Não foi possível recuperar a chave do cofre do chaveiro do sistema.[/]")
            return None
        
        db_key = bytearray.fromhex(key_hex)
        conn = sqlite.connect(NOME_DO_BANCO)
        conn.execute(f"PRAGMA key = \"x'{db_key.hex()}'\"")
        conn.execute("SELECT count(*) FROM sqlite_master")
        console.print(f"\n[{THEME['feedback.success']}]Cofre desbloqueado com sucesso via chave do dispositivo![/]\n")
        return conn
    except (sqlite.DatabaseError, ValueError):
        console.print(f"\n[{THEME['feedback.error']}]ERRO GRAVE: A chave foi recuperada, mas o cofre está corrompido.[/]\n")
        return None
    except Exception as e:
        console.print(f"\n[{THEME['feedback.error']}]Ocorreu um erro ao desbloquear: {e}[/]\n")
        return None
    finally:
        if db_key: secure_wipe(db_key)

# --- FUNÇÕES DE CONFIGURAÇÃO INICIAL ---

def setup_modo_senha_mestra() -> Optional[sqlite.Connection]:
    """Executa a configuração para o modo Senha Mestra."""
    senha_bytes = None
    try:
        senha_str = get_secure_pass("Crie sua Senha Mestra: ")
        confirma_str = get_secure_pass("Confirme a senha: ")
        if not hmac.compare_digest(senha_str.encode('utf-8'), confirma_str.encode('utf-8')) or not senha_str:
            console.print(f"[{THEME['feedback.error']}]Senhas não batem ou estão em branco. Configuração cancelada.[/]")
            return None
        
        senha_bytes = bytearray(senha_str.encode('utf-8'))
        del senha_str, confirma_str
        
        console.print("[cyan]Criando seu cofre...[/cyan]")
        with open(CAMINHO_HASH_DB, "w") as f: f.write(ph.hash(bytes(senha_bytes)))
        with open(CAMINHO_SALT_DB, "wb") as f: f.write(os.urandom(16))
        
        return conectar_com_chave_derivada(senha_bytes)
    finally:
        if senha_bytes: secure_wipe(senha_bytes)

def setup_modo_dispositivo() -> Optional[sqlite.Connection]:
    """Executa a configuração para o modo Atrelado ao Dispositivo."""
    db_key = None
    try:
        if 'ANDROID_ROOT' in os.environ:
            console.print(f"[{THEME['feedback.info']}]Será necessário autenticar no dispositivo para criar a chave segura.[/]")
            if not autenticar_com_dispositivo_termux():
                console.print(f"[{THEME['feedback.error']}]Autenticação falhou. Não é possível criar o cofre.[/]")
                return None

        console.print("[cyan]Gerando chave segura e salvando no chaveiro do sistema...[/cyan]")
        db_key = bytearray(os.urandom(32))
        keyring.set_password(KEYRING_SERVICE_NAME, USER_NAME, db_key.hex())

        console.print("[cyan]Criando seu cofre criptografado...[/cyan]")
        conn = sqlite.connect(NOME_DO_BANCO)
        conn.execute(f"PRAGMA key = \"x'{db_key.hex()}'\"")
        conn.execute("PRAGMA kdf_iter = 1")
        conn.execute("PRAGMA cipher = 'aes-256-gcm'")
        conn.execute("PRAGMA cipher_page_size = 4096")
        conn.execute("""CREATE TABLE segredos (identificador TEXT PRIMARY KEY NOT NULL, senha_mestra TEXT NOT NULL, salt_pessoal TEXT, observacao TEXT)""")
        conn.commit()
        return conn
    except Exception as e:
        console.print(f"[{THEME['feedback.error']}]Ocorreu um erro ao configurar o modo dispositivo: {e}[/]")
        if os.path.exists(NOME_DO_BANCO): os.remove(NOME_DO_BANCO)
        try: keyring.delete_password(KEYRING_SERVICE_NAME, USER_NAME)
        except: pass
        return None
    finally:
        if db_key: secure_wipe(db_key)

def setup_novo_cofre() -> Tuple[Optional[sqlite.Connection], Optional[str]]:
    """Lida com a configuração inicial do cofre, permitindo a escolha do modelo de segurança."""
    console.rule("[bold yellow]🚀 Configuração Inicial do Cofre[/bold yellow]")
    markdown_text = """
# Escolha o Modelo de Segurança do Seu Cofre

Seu cofre pode operar de duas maneiras. Esta escolha é permanente.

---

### 1. Modo Senha Mestra (Clássico & Portátil)

*   **Como funciona:** Seu cofre é criptografado com uma única Senha Mestra que só você sabe.
*   **Vantagens:**
    *   **Portabilidade:** Você pode copiar os arquivos do cofre para outro computador ou celular, digitar sua senha e ter acesso.
    *   **Recuperação:** Se você perder seu aparelho, seus dados não estão perdidos, desde que você se lembre da senha.
*   **Ideal para:** Usuários que precisam acessar seus segredos em **múltiplos dispositivos** ou que priorizam a capacidade de **recuperação** em caso de perda do aparelho.

---

### 2. Modo Atrelado ao Dispositivo (Máxima Conveniência & Segurança Offline)

*   **Como funciona:** Seu cofre é criptografado com uma chave secreta, aleatória e segura, armazenada diretamente no chaveiro (`keyring`) do seu aparelho. **Não existe uma senha mestra para lembrar.** O acesso é feito via biometria/PIN.
*   **Vantagens:**
    *   **Segurança Offline Superior:** Se os arquivos do cofre forem roubados, eles são inúteis para o atacante, pois não há uma senha para ser quebrada.
    *   **Conveniência:** O acesso é rápido e fácil, usando a segurança nativa do seu dispositivo.
*   **Ideal para:** Usuários que usarão o cofre em **um único dispositivo** e priorizam a **máxima segurança contra o roubo dos arquivos**, confiando em seu próprio sistema de backup para migração e recuperação.
"""
    console.print(Panel(Markdown(markdown_text), border_style="magenta", title="[bold]Análise com Cuidado[/bold]"))
    escolha = Prompt.ask(f"\n[{THEME['prompt.default']}]> Qual modo você escolhe? [/]", choices=["1", "2"], default="1")

    if escolha == '1':
        console.print(f"\n[{THEME['feedback.info']}]Você escolheu o Modo Senha Mestra. Vamos criar a sua...[/]")
        conn = setup_modo_senha_mestra()
        if conn:
            with open(CAMINHO_VAULT_MODE, "w") as f: f.write("master_password")
            return conn, "master_password"
    elif escolha == '2':
        console.print(f"\n[{THEME['feedback.info']}]Você escolheu o Modo Atrelado ao Dispositivo. Configurando...[/]")
        conn = setup_modo_dispositivo()
        if conn:
            with open(CAMINHO_VAULT_MODE, "w") as f: f.write("device_bound")
            return conn, "device_bound"
    return None, None

# --- FUNÇÕES DE DESBLOQUEIO RÁPIDO (Apenas para Modo Senha Mestra) ---

def tentar_desbloqueio_rapido() -> Optional[bytearray]:
    if not os.path.exists(CAMINHO_QUICK_UNLOCK): return None
    session_key = None
    try:
        if not Confirm.ask(f"\n[{THEME['prompt.confirm']}]Sessão de desbloqueio rápido encontrada. Tentar autenticação com o dispositivo?[/]", default=True):
            return None
        
        if 'ANDROID_ROOT' in os.environ:
            if not autenticar_com_dispositivo_termux(): return None
        
        console.print(f"[{THEME['feedback.info']}]Recuperando chave da sessão...[/]")
        session_key_hex = keyring.get_password(KEYRING_SERVICE_NAME, USER_NAME)
        if not session_key_hex:
            console.print(f"[{THEME['feedback.error']}]Não foi possível recuperar a chave da sessão do chaveiro.[/]")
            return None
        
        session_key = bytearray.fromhex(session_key_hex)
        with open(CAMINHO_QUICK_UNLOCK, "rb") as f: encrypted_data = f.read()
        nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]
        
        aesgcm = AESGCM(bytes(session_key))
        return bytearray(aesgcm.decrypt(nonce, ciphertext, None))
    except (InvalidTag, Exception) as e:
        console.print(f"[{THEME['feedback.error']}]Ocorreu um erro durante o Desbloqueio Rápido: {e}[/]")
        return None
    finally:
        if session_key: secure_wipe(session_key)

def habilitar_desbloqueio_rapido():
    console.rule(style=THEME["panel.action"])
    console.print(Panel.fit("⚙️ Habilitar Desbloqueio Rápido ⚙️", border_style=THEME["panel.action"]))
    senha_mestra_bytes, session_key = None, None
    try:
        senha_mestra_str = get_secure_pass("Para confirmar, digite sua senha mestra ATUAL: ")
        senha_mestra_bytes = bytearray(senha_mestra_str.encode('utf-8'))
        del senha_mestra_str
        with open(CAMINHO_HASH_DB, "r") as f: ph.verify(f.read(), bytes(senha_mestra_bytes))

        session_key = bytearray(os.urandom(32))
        nonce = os.urandom(12)
        ciphertext = AESGCM(bytes(session_key)).encrypt(nonce, bytes(senha_mestra_bytes), None)
        with open(CAMINHO_QUICK_UNLOCK, "wb") as f: f.write(nonce + ciphertext)
        keyring.set_password(KEYRING_SERVICE_NAME, USER_NAME, session_key.hex())
        console.print(f"\n[{THEME['feedback.success']}]✅ Desbloqueio Rápido habilitado com sucesso![/]\n")
    except VerifyMismatchError:
        console.print(f"\n[{THEME['feedback.error']}]Senha mestra incorreta.[/]\n")
    except Exception as e:
        console.print(f"\n[{THEME['feedback.error']}]Ocorreu um erro: {e}[/]\n")
    finally:
        if senha_mestra_bytes: secure_wipe(senha_mestra_bytes)
        if session_key: secure_wipe(session_key)

def desabilitar_desbloqueio_rapido():
    console.rule(style=THEME["panel.danger"])
    console.print(Panel.fit("⚙️ Desabilitar Desbloqueio Rápido ⚙️", border_style=THEME["panel.danger"]))
    if not os.path.exists(CAMINHO_QUICK_UNLOCK):
        console.print(f"\n[{THEME['feedback.info']}]O Desbloqueio Rápido já está desabilitado.[/]\n")
        return
    if Confirm.ask(f"[{THEME['prompt.confirm']}]Tem certeza?[/]"):
        try:
            keyring.delete_password(KEYRING_SERVICE_NAME, USER_NAME)
            if os.path.exists(CAMINHO_QUICK_UNLOCK):
                with open(CAMINHO_QUICK_UNLOCK, "wb") as f: f.write(os.urandom(128))
                os.remove(CAMINHO_QUICK_UNLOCK)
            console.print(f"\n[{THEME['feedback.success']}]✅ Desbloqueio Rápido desabilitado.[/]\n")
        except Exception as e:
            console.print(f"\n[{THEME['feedback.error']}]Ocorreu um erro: {e}[/]\n")

# --- FUNÇÕES DE BACKUP ---
def exportar_cofre(conn):
    console.print(Panel.fit("[bold blue]📤 Exportar Backup Criptografado[/bold blue]", border_style=THEME["panel.menu"]))
    cursor = conn.cursor()
    cursor.execute("SELECT identificador, senha_mestra, salt_pessoal, observacao FROM segredos")
    registros = cursor.fetchall()
    if not registros:
        console.print(f"\n[{THEME['feedback.info']}]O cofre está vazio, {USER_NAME}. Sem nada pra fazer backup.[/]\n"); return

    json_data = json.dumps([dict(zip([c[0] for c in cursor.description], row)) for row in registros]).encode('utf-8')
    senha_backup = None
    try:
        senha_str = get_secure_pass("Crie uma senha FORTE para este backup: ")
        confirma_str = get_secure_pass("Confirme a senha: ")
        if not hmac.compare_digest(senha_str.encode('utf-8'), confirma_str.encode('utf-8')) or not senha_str:
            console.print(f"\n[{THEME['feedback.error']}]Senhas não batem ou estão em branco. Cancelado.[/]\n"); return
        
        senha_backup = bytearray(senha_str.encode('utf-8'))
        del senha_str, confirma_str
        
        nome_base = Prompt.ask(f"[{THEME['prompt.default']}]> Qual nome você quer dar ao arquivo de backup?[/]")
        if not nome_base:
            console.print(f"\n[{THEME['feedback.error']}]Preciso de um nome para o arquivo. Exportação cancelada.[/]\n"); return

        caminho_completo = Path.home() / "Downloads" / (f"{nome_base}.2b" if not nome_base.endswith('.2b') else nome_base)
        caminho_completo.parent.mkdir(exist_ok=True)

        salt = os.urandom(16)
        chave_backup = low_level.hash_secret_raw(bytes(senha_backup), salt, 6, 524288, 8, 32, low_level.Type.ID)
        nonce = os.urandom(12)
        dados_finais = salt + nonce + AESGCM(chave_backup).encrypt(nonce, json_data, None)
        with open(caminho_completo, "wb") as f: f.write(dados_finais)
        console.print(f"\n[{THEME['feedback.success']}]Backup '{caminho_completo.name}' salvo com sucesso na sua pasta de Downloads![/]\n")
    except Exception as e:
        console.print(f"\n[{THEME['feedback.error']}]Falhou ao salvar o arquivo: {e}[/]\n")
    finally:
        if senha_backup: secure_wipe(senha_backup)

def importar_cofre(conn):
    console.print(Panel.fit("[bold blue]📥 Importar Backup Criptografado[/bold blue]", border_style=THEME["panel.menu"]))
    console.print(f"[{THEME['feedback.info']}]ATENÇÃO, {USER_NAME}: Isso vai apagar TUDO que está no cofre atual.[/]")
    if Prompt.ask(f"\n[{THEME['prompt.confirm']}]> Digite '[bold red]IMPORTAR[/bold red]' para confirmar[/]").upper() != "IMPORTAR":
        console.print(f"\n[{THEME['feedback.info']}]Importação cancelada.[/]\n"); return

    nome_base = Prompt.ask(f"[{THEME['prompt.default']}]> Qual o nome do arquivo de backup (.2b) nos seus Downloads?[/]")
    if not nome_base: return
    caminho_completo = Path.home() / "Downloads" / (f"{nome_base}.2b" if not nome_base.endswith('.2b') else nome_base)
    if not caminho_completo.exists():
        console.print(f"\n[{THEME['feedback.error']}]Arquivo não encontrado: {caminho_completo}[/]\n"); return
    
    senha_backup = None
    try:
        senha_str = get_secure_pass("Digite a senha do arquivo de backup: ")
        senha_backup = bytearray(senha_str.encode('utf-8'))
        del senha_str
        with open(caminho_completo, "rb") as f: dados_finais = f.read()
        salt, nonce, ciphertext = dados_finais[:16], dados_finais[16:28], dados_finais[28:]
        chave_backup = low_level.hash_secret_raw(bytes(senha_backup), salt, 6, 524288, 8, 32, low_level.Type.ID)
        json_data_bytes = AESGCM(chave_backup).decrypt(nonce, ciphertext, None)
        dados_restaurados = json.loads(json_data_bytes.decode('utf-8'))

        cursor = conn.cursor()
        cursor.execute("DELETE FROM segredos")
        for item in dados_restaurados:
            cursor.execute("INSERT INTO segredos (identificador, senha_mestra, salt_pessoal, observacao) VALUES (?, ?, ?, ?)",
                (item.get('identificador'), item.get('senha_mestra'), item.get('salt_pessoal'), item.get('observacao')))
        conn.commit()
        console.print(f"\n[{THEME['feedback.success']}]Prontinho! Cofre restaurado com sucesso a partir de '{caminho_completo.name}'.[/]\n")
    except InvalidTag:
        console.print(f"\n[{THEME['feedback.error']}]Importação falhou. Senha errada ou arquivo corrompido.[/]\n")
    except Exception as e:
        console.print(f"\n[{THEME['feedback.error']}]Ocorreu um erro: {e}[/]\n")
    finally:
        if senha_backup: secure_wipe(senha_backup)

# --- FUNÇÕES PRINCIPAIS DO COFRE ---

def adicionar_entrada(conn):
    console.rule(style=THEME["panel.action"])
    console.print(Panel.fit("✨ Adicionar um Novo Segredo ✨", border_style=THEME["panel.action"]))
    identificador = Prompt.ask(f"[{THEME['prompt.default']}]> Dê um nome para este Identificador[/]")
    senha_mestra = get_secure_pass(f"[{THEME['prompt.default']}]> Agora, a senha que vamos guardar[/]")
    salt_pessoal = Prompt.ask(f"[{THEME['prompt.default']}]> Quer adicionar um 'salt' pessoal? (opcional)[/]")
    console.line()
    instrucoes_md = """
• Escreva suas anotações. Markdown é suportado.
• Para finalizar, tecle [bold cyan]Ctrl+D[/] ou digite [bold cyan]fim[/] em uma linha vazia.
"""
    console.print(Panel(instrucoes_md, title="[bold]📝 Observações[/bold]", title_align="left", border_style="blue"))

    bindings = KeyBindings()
    @bindings.add('c-d')
    def _(event): event.app.current_buffer.validate_and_handle()
    @bindings.add('enter')
    def _(event):
        buffer = event.app.current_buffer
        if not buffer.text.strip() or buffer.text.split('\n')[-1].strip().lower() == 'fim':
            if buffer.text.split('\n')[-1].strip().lower() == 'fim':
                buffer.text = '\n'.join(buffer.text.split('\n')[:-1])
            buffer.validate_and_handle()
        else: buffer.insert_text('\n')
    
    try:
        observacao = PromptSession(key_bindings=bindings, rprompt='[Ctrl+D para Salvar]').prompt('> ', multiline=True)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO segredos (identificador, senha_mestra, salt_pessoal, observacao) VALUES (?, ?, ?, ?)", (identificador, senha_mestra, salt_pessoal, observacao.strip()))
        conn.commit()
        console.print(f"\n[{THEME['feedback.success']}]✅ Segredo '{identificador}' guardado com sucesso![/]\n")
    except sqlite.IntegrityError:
        console.print(f"\n[{THEME['feedback.error']}]❌ Opa, {USER_NAME}, o identificador '{identificador}' já está em uso.[/]\n")
    except KeyboardInterrupt:
        console.print("\n[red]Operação cancelada.[/red]")

def limpar_clipboard_apos_delay(delay_em_segundos):
    """
    Espera por um tempo definido e depois limpa a área de transferência
    executando o comando com uma string vazia.
    """
    time.sleep(delay_em_segundos)
    try:
        # Checa novamente se está no Termux
        if "com.termux" in sys.prefix:
            subprocess.run(['termux-clipboard-set'], input='', text=True, check=True)
            # Você pode opcionalmente mostrar uma notificação no Android
            # subprocess.run(['termux-notification', '--title', 'Segurança', '--content', 'Área de transferência foi limpa.'])
    except Exception:
        # Se falhar (o que é raro), não faz nada para não interromper o usuário.
        pass

def consultar_entrada(conn):
    console.rule(style=THEME["panel.action"])
    console.print(Panel.fit("🔍 Consultar um Segredo", border_style=THEME["panel.action"]))
    identificador = Prompt.ask(f"[{THEME['prompt.default']}]> Qual Identificador você quer ver?[/]")
    
    cursor = conn.cursor()
    cursor.execute("SELECT senha_mestra, salt_pessoal, observacao FROM segredos WHERE identificador = ?", (identificador,))
    resultado = cursor.fetchone()

    if resultado:
        senha, salt, obs = resultado
        console.print(Panel(f"Aqui estão os dados para: [bold magenta]'{identificador}'[/bold magenta]", border_style="magenta", expand=False))
        
        console.print(Rule("[bold cyan]Senha[/bold cyan]", style="cyan"))
        console.print(f"[bold green]\n{senha}\n")
        console.print(Rule(style="cyan"))
        
        console.print(Rule("[bold yellow]Salt Pessoal[/bold yellow]", style="yellow"))
        console.print(Align.center(f"[bold green]{salt}[/]" if salt else "[italic](nenhum)[/italic]"))
        console.print(Rule(style="yellow"))

        if obs:
            console.print(Panel(Markdown(obs), title="[bold green]Observações[/bold green]", border_style="green", padding=(1,2)))
        
        console.line()

        
        if Confirm.ask(f"[{THEME['prompt.default']}]Deseja copiar a senha para a área de transferência?[/]"):
            try:
                # Verifica se está rodando no Termux (Android)
                if "com.termux" in sys.prefix:
                    # Executa o comando 'termux-clipboard-set' passando a senha
                    subprocess.run(['termux-clipboard-set'], input=senha, text=True, check=True)
                    
                    console.print(f"[{THEME['feedback.success']}]✓ Senha copiada com sucesso usando Termux:API![/]")
                    console.print("[yellow bold]Aviso:[/yellow bold] [italic]Por segurança, limpe sua área de transferências após o uso.[/italic]")
                else:
                    # Se não for Termux, continua usando pyperclip como alternativa
                    # (você pode remover isso se seu script só roda no Termux)
                    import pyperclip
                    pyperclip.copy(senha)
                    console.print(f"[{THEME['feedback.success']}]✓ Senha copiada com sucesso para a área de transferência![/]")

            except FileNotFoundError:
                console.print(f"[{THEME['feedback.error']}]Comando 'termux-clipboard-set' não encontrado. Verifique se o pacote 'termux-api' está instalado.[/]")
            except Exception as e:
                console.print(f"[{THEME['feedback.error']}]Ocorreu um erro ao copiar: {e}[/]")

        console.line()

    else:
        console.print(f"\n[{THEME['feedback.error']}]Uhm... não encontrei nada com o nome '{identificador}'.[/]\n")

def listar_identificadores(conn):
    console.rule(style="green")
    cursor = conn.cursor()
    cursor.execute("SELECT identificador FROM segredos ORDER BY identificador")
    resultados = cursor.fetchall()
    if resultados:
        table = Table(title=f"[{THEME['title']}]Nossos Segredos Guardados[/]", border_style="green", expand=True)
        table.add_column("Identificador 📌", justify="left", style="cyan")
        for (identificador,) in resultados: table.add_row(identificador)
        console.print(table)
        console.line()
    else:
        console.print(f"\n[{THEME['feedback.info']}]Nosso cofre está vazio. Que tal adicionar nosso primeiro segredo?[/]\n")

def remover_entrada(conn):
    console.rule(style=THEME["panel.danger"])
    console.print(Panel.fit("🗑️ Remover um Segredo", border_style=THEME["panel.danger"]))
    identificador = Prompt.ask(f"[{THEME['prompt.default']}]> Qual Identificador vamos apagar?[/]")
    if Confirm.ask(f"\n[{THEME['prompt.confirm']}]Tem [bold red]CERTEZA[/bold red] que quer apagar '{identificador}' pra sempre?[/]"):
        cursor = conn.cursor()
        cursor.execute("DELETE FROM segredos WHERE identificador = ?", (identificador,))
        conn.commit()
        if cursor.rowcount > 0: console.print(f"\n[{THEME['feedback.success']}]Pronto. O segredo '{identificador}' virou poeira cósmica.[/]\n")
        else: console.print(f"\n[{THEME['feedback.error']}]Não achei nada com o nome '{identificador}' pra apagar.[/]\n")
    else: console.print(f"\n[{THEME['feedback.info']}]Operação cancelada. O segredo '{identificador}' está a salvo.[/]\n")

def alterar_senha_mestra(conn):
    console.rule(style=THEME["panel.action"])
    console.print(Panel.fit("🔑 Alterar a Chave Mestra do Cofre 🔑", border_style=THEME["panel.action"]))
    console.print("\n[italic]Isso é sério. Se você esquecer essa nova senha, já era.[/italic]\n")
    senha_atual_bytes, nova_senha_bytes = None, None
    try:
        senha_atual_str = get_secure_pass("Primeiro, sua senha ATUAL: ")
        senha_atual_bytes = bytearray(senha_atual_str.encode('utf-8'))
        del senha_atual_str
        with open(CAMINHO_HASH_DB, "r") as f: ph.verify(f.read(), bytes(senha_atual_bytes))

        nova_senha_str = get_secure_pass("Ok. Agora, a NOVA senha: ")
        confirma_nova_senha_str = get_secure_pass("Confirme a NOVA senha: ")
        if not hmac.compare_digest(nova_senha_str.encode('utf-8'), confirma_nova_senha_str.encode('utf-8')) or not nova_senha_str:
            console.print(f"\n[{THEME['feedback.error']}]As novas senhas não batem. Cancelado.[/]\n"); return
        nova_senha_bytes = bytearray(nova_senha_str.encode('utf-8'))
        del nova_senha_str, confirma_nova_senha_str

        with open(CAMINHO_SALT_DB, "rb") as f: db_salt = f.read()
        nova_chave_db = low_level.hash_secret_raw(bytes(nova_senha_bytes), db_salt, 6, 524288, 8, 32, low_level.Type.ID)
        conn.execute(f"PRAGMA rekey = \"x'{nova_chave_db.hex()}'\"")
        conn.commit()
        with open(CAMINHO_HASH_DB, "w") as f: f.write(ph.hash(bytes(nova_senha_bytes)))
        console.print(f"\n[{THEME['feedback.success']}]Feito! A senha do cofre foi alterada. Não vai esquecer, hein?.[/]\n")
    except VerifyMismatchError:
        console.print(f"\n[{THEME['feedback.error']}]Senha atual incorreta. Abortando.[/]\n")
    except Exception as e:
        console.print(f"\n[{THEME['feedback.error']}]Ocorreu um erro: {e}[/]\n")
    finally:
        if senha_atual_bytes: secure_wipe(senha_atual_bytes)
        if nova_senha_bytes: secure_wipe(nova_senha_bytes)

def corromper_e_apagar_tudo(vault_mode: str):
    console.rule(f"[{THEME['panel.danger']}]PROTOCOLO DE AUTODESTRUIÇÃO ATIVADO[/]", style=THEME["panel.danger"])
    try:
        if os.path.exists(NOME_DO_BANCO):
            with open(NOME_DO_BANCO, "wb") as f: f.write(os.urandom(max(os.path.getsize(NOME_DO_BANCO), 4096)))
            os.remove(NOME_DO_BANCO); console.print(f"[{THEME['feedback.error']}]- Arquivo do cofre deletado.[/]")
        
        if vault_mode == "master_password":
            if os.path.exists(CAMINHO_HASH_DB): os.remove(CAMINHO_HASH_DB); console.print(f"[{THEME['feedback.error']}]- Arquivo de verificação deletado.[/]")
            if os.path.exists(CAMINHO_SALT_DB): os.remove(CAMINHO_SALT_DB); console.print(f"[{THEME['feedback.error']}]- Arquivo de salt deletado.[/]")
            desabilitar_desbloqueio_rapido()
        elif vault_mode == "device_bound":
            try:
                keyring.delete_password(KEYRING_SERVICE_NAME, USER_NAME)
                console.print(f"[{THEME['feedback.error']}]- Chave do cofre deletada do chaveiro.[/]")
            except Exception: pass
        
        if os.path.exists(CAMINHO_VAULT_MODE): os.remove(CAMINHO_VAULT_MODE); console.print(f"[{THEME['feedback.error']}]- Configuração de modo deletada.[/]")
        console.line(); console.print("[bold red on black] MISSÃO CUMPRIDA. TODOS OS DADOS FORAM PERMANENTEMENTE DESTRUÍDOS. [/bold red on black]")
        console.print("[italic]Foi bom enquanto durou...[/italic]\n")
    except Exception as e:
        console.print(f"\n[{THEME['feedback.error']}]Erro na autodestruição: {e}[/]\n")

def formatar_cofre(vault_mode: str):
    console.rule(style=THEME["panel.danger"])
    console.print(Panel.fit("💥 FORMATAR O COFRE 💥", border_style=THEME["panel.danger"]))
    console.print("Isso é um adeus sem volta. [bold red]TUDO SERÁ APAGADO.[/bold red]", justify="center")
    if Prompt.ask(f"\n[{THEME['prompt.confirm']}]> Digite '[bold red]APAGAR TUDO[/bold red]' se tiver coragem[/]").upper() != "APAGAR TUDO":
        console.print(f"\n[{THEME['feedback.success']}]Formatação cancelada. Seu cofre respira aliviado.[/]\n"); return
      
    if Prompt.ask(f"[{THEME['prompt.confirm']}]> Última chance. Digite '[bold red]SIM, TENHO CERTEZA[/bold red]'[/]").upper() != "SIM, TENHO CERTEZA":
        console.print(f"\n[{THEME['feedback.success']}]Formatação cancelada. Quase, hein?[/]\n"); return
    
    auth_success = False
    if vault_mode == "master_password":
        senha_bytes = None
        try:
            senha_str = get_secure_pass("Confirme com sua senha mestra: ")
            senha_bytes = bytearray(senha_str.encode('utf-8'))
            del senha_str
            with open(CAMINHO_HASH_DB, "r") as f: ph.verify(f.read(), bytes(senha_bytes))
            auth_success = True
        except (VerifyMismatchError, FileNotFoundError):
            console.print(f"\n[{THEME['feedback.error']}]SENHA INCORRETA. Abortado.[/]\n")
        finally:
            if senha_bytes: secure_wipe(senha_bytes)
    elif vault_mode == "device_bound":
        console.print(f"[{THEME['feedback.info']}]Autenticação do dispositivo necessária para confirmar.[/]")
        auth_success = autenticar_com_dispositivo_termux() if 'ANDROID_ROOT' in os.environ else Confirm.ask(f"[{THEME['prompt.confirm']}]Prosseguir com a formatação?[/]")

    if auth_success:
        corromper_e_apagar_tudo(vault_mode)
        console.print("\nO cofre foi... formatado."); sys.exit()
    else:
        console.print(f"\n[{THEME['feedback.error']}]AUTENTICAÇÃO FALHOU. Formatação abortada.[/]\n")

# --- MENUS ---

def menu_backup(conn):
    while True:
        console.rule(style=THEME["panel.menu"])
        menu_text = Text("\nGerenciamento de Backup", justify="center", style=THEME["title"])
        menu_text.append("\n\n1. 📤 Exportar Cofre (Criar Backup)", style="green")
        menu_text.append("\n2. 📥 Importar Cofre (Restaurar Backup)", style="yellow")
        menu_text.append("\n3. ↩️ Voltar ao Menu Principal", style="white")
        
        painel_menu_backup = Panel(menu_text, title="💾 Backup", border_style=THEME["panel.menu"], expand=False)
        console.print(Align.center(painel_menu_backup))
        
        escolha = Prompt.ask(f"[{THEME['prompt.default']}]> Sua escolha[/]", choices=['1', '2', '3'])
        if escolha == '1': exportar_cofre(conn)
        elif escolha == '2': importar_cofre(conn)
        elif escolha == '3': break

def menu_desbloqueio_rapido():
    while True:
        console.rule(style=THEME["panel.menu"])
        status = "[bold green]Habilitado[/]" if os.path.exists(CAMINHO_QUICK_UNLOCK) else "[bold red]Desabilitado[/]"
        menu_text = Text(f"\nStatus Atual: {status}", justify="center", style=THEME["title"])
        menu_text.append("\n\n1. ✅ Habilitar Desbloqueio Rápido", style="green")
        menu_text.append("\n2. ❌ Desabilitar Desbloqueio Rápido", style="red")
        menu_text.append("\n3. ↩️ Voltar ao Menu Principal", style="white")
        
        painel_menu_quick_unlock = Panel(menu_text, title="⚙️ Gerenciar Desbloqueio Rápido", border_style=THEME["panel.menu"], expand=False)
        console.print(Align.center(painel_menu_quick_unlock))
        
        escolha = Prompt.ask(f"[{THEME['prompt.default']}]> Sua escolha[/]", choices=['1', '2', '3'])
        if escolha == '1': habilitar_desbloqueio_rapido()
        elif escolha == '2': desabilitar_desbloqueio_rapido()
        elif escolha == '3': break

# --- FUNÇÃO PRINCIPAL ---

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print(Panel.fit(
        Text("Cofre Digital", justify="center", style=THEME["title"]) +
        Text("\nNosso pequeno espaço seguro.", justify="center", style="cyan"),
        border_style=THEME["panel.main"]
    ))
    
    conn, vault_mode = None, None

    if not os.path.exists(NOME_DO_BANCO):
        conn, vault_mode = setup_novo_cofre()
        if not conn:
            console.print(f"\n[{THEME['feedback.error']}]Falha na configuração inicial. Saindo.[/]"); return
    else:
        try:
            with open(CAMINHO_VAULT_MODE, "r") as f: vault_mode = f.read().strip()
        except FileNotFoundError:
            vault_mode = "master_password"
            with open(CAMINHO_VAULT_MODE, "w") as f: f.write(vault_mode)
        
        if vault_mode == "master_password": conn = login_modo_senha_mestra()
        elif vault_mode == "device_bound": conn = login_modo_dispositivo()
        else: console.print(f"[{THEME['feedback.error']}]Modo de cofre inválido: '{vault_mode}'.[/]"); return

    if not conn:
        if vault_mode == "master_password":
            console.print(f"[{THEME['feedback.error']}]Múltiplas falhas. Ativando protocolo de segurança...[/]")
            corromper_e_apagar_tudo(vault_mode)
        else: console.print(f"[{THEME['feedback.error']}]Falha ao autenticar. Saindo.[/]")
        return

    # Construção do Menu Dinâmico
    menu_items = {
        '1': ("✨ Adicionar novo segredo", "green", adicionar_entrada, (conn,)),
        '2': ("🔍 Consultar um segredo", "cyan", consultar_entrada, (conn,)),
        '3': ("📜 Listar todos os segredos", "yellow", listar_identificadores, (conn,)),
        '4': ("🗑️ Remover um segredo", "red", remover_entrada, (conn,)),
    }
    next_opt = 5
    if vault_mode == 'master_password':
        menu_items[str(next_opt)] = ("🔑 Alterar Senha de Acesso", "bold yellow", alterar_senha_mestra, (conn,)); next_opt += 1
        menu_items[str(next_opt)] = ("💾 Backup (Exportar/Importar)", "bold blue", menu_backup, (conn,)); next_opt += 1
        menu_items[str(next_opt)] = ("⚙️ Gerenciar Desbloqueio Rápido", "bold magenta", menu_desbloqueio_rapido, ()); next_opt += 1
    else: # device_bound
        menu_items[str(next_opt)] = ("💾 Backup (Exportar/Importar)", "bold blue", menu_backup, (conn,)); next_opt += 1
    
    menu_items[str(next_opt)] = ("💥 Formatar o Cofre (APAGAR TUDO)", "bold red", formatar_cofre, (vault_mode,)); next_opt += 1
    menu_items[str(next_opt)] = ("🚪 Sair", "bold white", lambda: None, ()); next_opt += 1


    while True:
        console.rule(style=THEME["panel.menu"])
        menu_text = Text("O que faremos agora?", justify="center", style=THEME["title"])
        for key, (text, style, _, _) in menu_items.items():
            menu_text.append(f"\n{key}. {text}", style=style)
        
        painel_menu = Panel(menu_text, title="Menu Principal", border_style=THEME["panel.menu"], expand=False)
        console.print(Align.center(painel_menu))
        
        escolha = Prompt.ask(f"[{THEME['prompt.default']}]> Sua escolha[/]", choices=list(menu_items.keys()))
        
        if menu_items[escolha][2].__name__ == '<lambda>': # Sair
            break

        func_to_call = menu_items[escolha][2]
        args_for_func = menu_items[escolha][3]
        func_to_call(*args_for_func)

    conn.close()
    console.print(f"\n[{THEME['feedback.special']}]Cofre trancado. Seus segredos estão seguros comigo. Até a próxima, {USER_NAME}.[/]\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Operação interrompida. Saindo...[/yellow]")