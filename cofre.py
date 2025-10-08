 # cofre.py

import os
import hashlib
import sys
import json
from pathlib import Path
import ctypes
import hmac
   
from pysqlcipher3 import dbapi2 as sqlite
from appdirs import user_data_dir

# --- IMPORTS DE CRIPTOGRAFIA ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2 import PasswordHasher, low_level
from argon2.exceptions import VerifyMismatchError

# --- Importações do Rich ---
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.markdown import Markdown
from rich.prompt import Prompt, Confirm
from rich.align import Align

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
        # Fallback caso ctypes falhe
        for i in range(len(buffer)):
            buffer[i] = 0

# --- FUNÇÕES DE BACKUP ---

def exportar_cofre(conn):
    console.print(Panel.fit("[bold blue]📤 Exportar Backup Criptografado[/bold blue]", border_style=THEME["panel.menu"]))
    cursor = conn.cursor()
    cursor.execute("SELECT identificador, senha_mestra, salt_pessoal, observacao FROM segredos")
    registros = cursor.fetchall()

    if not registros:
        console.print(f"\n[{THEME['feedback.info']}]O cofre está vazio, {USER_NAME}. Sem nada pra fazer backup.[/]\n"); return

    dados_para_backup = [dict(zip([c[0] for c in cursor.description], row)) for row in registros]
    json_data = json.dumps(dados_para_backup).encode('utf-8')

    console.print("\n[italic]Para proteger seu backup, vamos criar uma senha só pra ele.[/italic]")
    
    senha_backup = None
    try:
        senha_backup_str = get_secure_pass("Crie uma senha FORTE para este arquivo de backup: ")
        confirma_senha_str = get_secure_pass("Confirme a senha, por favor: ")

        senhas_batem = hmac.compare_digest(senha_backup_str.encode('utf-8'), confirma_senha_str.encode('utf-8'))

        if not senhas_batem or not senha_backup_str:
            console.print(f"\n[{THEME['feedback.error']}]Senhas não batem ou estão em branco. Operação cancelada.[/]\n"); return

        senha_backup = bytearray(senha_backup_str.encode('utf-8'))
        del senha_backup_str, confirma_senha_str

        nome_base = Prompt.ask(f"[{THEME['prompt.default']}]> Qual nome você quer dar ao arquivo de backup?[/]")
        if not nome_base:
            console.print(f"\n[{THEME['feedback.error']}]Preciso de um nome para o arquivo. Exportação cancelada.[/]\n"); return

        nome_arquivo = f"{nome_base}.2b" if not nome_base.endswith('.2b') else nome_base
        caminho_downloads = Path.home() / "Downloads"
        caminho_downloads.mkdir(exist_ok=True)
        caminho_completo = caminho_downloads / nome_arquivo

        salt = os.urandom(16)
        chave_backup = low_level.hash_secret_raw(
            secret=bytes(senha_backup),
            salt=salt,
            time_cost=6,
            memory_cost=524288,
            parallelism=8,
            hash_len=32,
            type=low_level.Type.ID
        )

        aesgcm = AESGCM(chave_backup)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, json_data, None)
        dados_finais = salt + nonce + ciphertext

        with open(caminho_completo, "wb") as f: f.write(dados_finais)
        console.print(f"\n[{THEME['feedback.success']}]Backup '{nome_arquivo}' salvo com sucesso na sua pasta de Downloads. Guarde com carinho! 😉[/]\n")
    
    except Exception as e:
        console.print(f"\n[{THEME['feedback.error']}]Puts, falhou ao salvar o arquivo: {e}[/]\n")
    finally:
        if senha_backup:
            secure_wipe(senha_backup)


def importar_cofre(conn):
    console.print(Panel.fit("[bold blue]📥 Importar Backup Criptografado[/bold blue]", border_style=THEME["panel.menu"]))
    console.print(f"[{THEME['feedback.info']}]ATENÇÃO, {USER_NAME}: Isso vai apagar TUDO que está no cofre atual e substituir pelo backup.[/]")
    
    if Prompt.ask(f"\n[{THEME['prompt.confirm']}]> Digite '[bold red]IMPORTAR[/bold red]' para confirmar[/]").upper() != "IMPORTAR":
        console.print(f"\n[{THEME['feedback.success']}]Ufa, importação cancelada. Tudo seguro.[/]\n"); return

    nome_base = Prompt.ask(f"[{THEME['prompt.default']}]> Qual o nome do arquivo de backup (.2b) que está nos seus Downloads?[/]")
    if not nome_base:
        console.print(f"\n[{THEME['feedback.error']}]Sem nome, sem restauração. Importação cancelada.[/]\n"); return

    nome_arquivo = f"{nome_base}.2b" if not nome_base.endswith('.2b') else nome_base
    caminho_downloads = Path.home() / "Downloads"
    caminho_completo = caminho_downloads / nome_arquivo

    if not caminho_completo.exists():
        console.print(f"\n[{THEME['feedback.error']}]Não achei esse arquivo. Certeza que está em '{caminho_completo}', {USER_NAME}?[/]\n"); return
    
    senha_backup = None
    try:
        senha_backup_str = get_secure_pass("Digite a senha do arquivo de backup: ")
        senha_backup = bytearray(senha_backup_str.encode('utf-8'))
        del senha_backup_str

        with open(caminho_completo, "rb") as f: dados_finais = f.read()
        salt, nonce, ciphertext = dados_finais[:16], dados_finais[16:28], dados_finais[28:]
        
        chave_backup = low_level.hash_secret_raw(
            secret=bytes(senha_backup),
            salt=salt,
            time_cost=6,
            memory_cost=524288,
            parallelism=8,
            hash_len=32,
            type=low_level.Type.ID
        )

        aesgcm = AESGCM(chave_backup)
        json_data_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        dados_restaurados = json.loads(json_data_bytes.decode('utf-8'))

        cursor = conn.cursor()
        cursor.execute("DELETE FROM segredos")
        for item in dados_restaurados:
            cursor.execute(
                "INSERT INTO segredos (identificador, senha_mestra, salt_pessoal, observacao) VALUES (?, ?, ?, ?)",
                (item.get('identificador'), item.get('senha_mestra'), item.get('salt_pessoal'), item.get('observacao'))
            )
        conn.commit()
        console.print(f"\n[{THEME['feedback.success']}]Prontinho! Cofre restaurado com sucesso a partir de '{nome_arquivo}'. Tudo de volta no lugar.[/]\n")
    except InvalidTag:
        console.print(f"\n[{THEME['feedback.error']}]Importação falhou. Ou a senha está errada, ou o arquivo está corrompido.[/]\n")
    except Exception as e:
        console.print(f"\n[{THEME['feedback.error']}]Deu um erro esquisito aqui: {e}[/]\n")
    finally:
        if senha_backup:
            secure_wipe(senha_backup)

# --- FUNÇÕES PRINCIPAIS ---

def verificar_senha_e_conectar(senha_acesso: bytearray):
    # ETAPA 1: Verificação rápida do hash da senha
    if not os.path.exists(CAMINHO_HASH_DB):
        console.print("\n[bold yellow]Primeiro acesso detectado. Bem-vindo ao nosso cantinho secreto![/bold yellow]")
        console.print("[cyan]Criando seu cofre...[/cyan]")
        hash_db = ph.hash(bytes(senha_acesso))
        with open(CAMINHO_HASH_DB, "w") as f: f.write(hash_db)

        # Gera e salva um salt dedicado para a chave do banco de dados
        db_salt = os.urandom(16)
        with open(CAMINHO_SALT_DB, "wb") as f: f.write(db_salt)
    else:
        with open(CAMINHO_HASH_DB, "r") as f: hash_db = f.read()

    try:
        ph.verify(hash_db, bytes(senha_acesso))
        console.print(f"\n[{THEME['feedback.info']}]Chave aceita. Derivando chave do cofre (isso pode levar um momento)...[/]")

        # ETAPA 2: Derivação segura da chave do banco de dados
        with open(CAMINHO_SALT_DB, "rb") as f: db_salt = f.read()

        chave_db = low_level.hash_secret_raw(
            secret=bytes(senha_acesso),
            salt=db_salt,
            time_cost=6,
            memory_cost=524288,
            parallelism=8,
            hash_len=32,  # 32 bytes = 256 bits
            type=low_level.Type.ID
        )

        # ETAPA 3: Conexão com o banco de dados usando a chave derivada
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
    except VerifyMismatchError:
        return None  # Senha incorreta (pego na verificação rápida)
    except sqlite.DatabaseError:
        console.print(f"\n[{THEME['feedback.error']}]ERRO GRAVE: A senha está correta, mas o arquivo do cofre parece corrompido. Espero que você tenha um backup...[/]\n")
        return None

def adicionar_entrada(conn):
    console.rule(style=THEME["panel.action"])
    console.print(Panel.fit("✨ Adicionar um Novo Segredo ✨", border_style=THEME["panel.action"]))
    
    identificador = Prompt.ask(f"[{THEME['prompt.default']}]> Dê um nome para este Identificador (ex: 'email da steam')[/]")
    senha_mestra = get_secure_pass(f"[{THEME['prompt.default']}]> Agora, a senha que vamos guardar[/]")
    salt_pessoal = Prompt.ask(f"[{THEME['prompt.default']}]> Quer adicionar um 'salt' pessoal? (opcional)[/]")

    console.line()
    
    instrucoes_md = """
• Escreva suas anotações. Markdown é suportado.
• Para finalizar, tecle [bold cyan]Ctrl+D[/] ou digite [bold cyan]fim[/] em uma linha vazia.
• Tecle [bold cyan]Enter[/] para pular se não quiser adicionar observação. 
    """
    console.print(Panel(instrucoes_md, title="[bold]📝 Observações[/bold]", title_align="left", border_style="blue"))

    session = PromptSession()
    bindings = KeyBindings()

    @bindings.add('c-d')
    def _(event):
        event.app.current_buffer.validate_and_handle()

    @bindings.add('enter')
    def _(event):
        buffer = event.app.current_buffer
        lines = buffer.text.split('\n')
        if not buffer.text.strip() or lines[-1].strip().lower() == 'fim':
            if lines[-1].strip().lower() == 'fim':
                buffer.text = '\n'.join(lines[:-1])
            buffer.validate_and_handle()
        else:
            buffer.insert_text('\n')

    observacao_final = ""
    try:
        observacao_final = session.prompt(
            message='> ',
            multiline=True,
            key_bindings=bindings,
            rprompt='[Ctrl+D para Salvar]'
        )
    except KeyboardInterrupt:
        console.print("\n[red]Operação cancelada.[/red]")
        return

    observacao_processada = observacao_final.strip()
    
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO segredos (identificador, senha_mestra, salt_pessoal, observacao) VALUES (?, ?, ?, ?)", (identificador, senha_mestra, salt_pessoal, observacao_processada))
        conn.commit()
        console.print(f"\n[{THEME['feedback.success']}]✅ Segredo '{identificador}' guardado com sucesso![/]\n")
    except sqlite.IntegrityError:
        console.print(f"\n[{THEME['feedback.error']}]❌ Opa, {USER_NAME}, o identificador '{identificador}' já está em uso. Tente outro nome.[/]\n")


def consultar_entrada(conn):
    console.rule(style=THEME["panel.action"])
    console.print(Panel.fit("🔍 Consultar um Segredo", border_style=THEME["panel.action"]))
    identificador = Prompt.ask(f"[{THEME['prompt.default']}]> Qual Identificador você quer ver?[/]")
    cursor = conn.cursor()
    cursor.execute("SELECT senha_mestra, salt_pessoal, observacao FROM segredos WHERE identificador = ?", (identificador,))
    resultado = cursor.fetchone()
    if resultado:
        senha_mestra, salt_pessoal, observacao = resultado
        
        console.print(Panel(f"Aqui estão os dados para: [bold magenta]'{identificador}'[/bold magenta]", border_style="magenta", expand=False))
        
        console.print(Rule("[bold cyan]Senha Mestra[/bold cyan]", style="cyan"))
        console.print(f"[bold green]\n{senha_mestra}\n")
        console.print(Rule(style="cyan"))
        
        
        console.print(Rule("[bold yellow]Salt Pessoal[/bold yellow]", style="yellow"))
        salt_text = f"[bold green]{salt_pessoal}[/bold green]" if salt_pessoal else "[italic](nenhum)[/italic]"
        console.print(Align.center(salt_text))
        console.print(Rule(style="yellow"))
        
        if observacao:
            console.print(Panel(Markdown(observacao), title="[bold green]Observações[/bold green]", border_style="green", padding=(1,2)))
        
        console.print(Rule(style="magenta"))
        console.line()

    else:
        console.print(f"\n[{THEME['feedback.error']}]Uhm... não encontrei nada com o nome '{identificador}'. Digitou certo?[/]\n")


def alterar_senha_mestra(conn):
    console.rule(style=THEME["panel.action"])
    console.print(Panel.fit("🔑 Alterar a Chave Mestra do Cofre 🔑", border_style=THEME["panel.action"]))
    console.print("\n[italic]Isso é sério. Se você esquecer essa nova senha, já era.[/italic]\n")
    
    senha_atual_bytes = None
    nova_senha_bytes = None
    try:
        senha_atual_str = get_secure_pass("Primeiro, sua senha ATUAL: ")
        senha_atual_bytes = bytearray(senha_atual_str.encode('utf-8'))
        del senha_atual_str

        with open(CAMINHO_HASH_DB, "r") as f: hash_db_atual = f.read()
        try:
            ph.verify(hash_db_atual, bytes(senha_atual_bytes))
        except VerifyMismatchError:
            console.print(f"\n[{THEME['feedback.error']}]Senha atual incorreta. Abortando por segurança.[/]\n"); return

        nova_senha_str = get_secure_pass("Ok. Agora, a NOVA senha: ")
        confirma_nova_senha_str = get_secure_pass("Confirme a NOVA senha: ")
        
        if not hmac.compare_digest(nova_senha_str.encode('utf-8'), confirma_nova_senha_str.encode('utf-8')):
            console.print(f"\n[{THEME['feedback.error']}]As novas senhas não batem. Tente de novo quando estiver mais concentrado.[/]\n"); return
        if not nova_senha_str:
            console.print(f"\n[{THEME['feedback.error']}]A nova senha não pode ser um vazio existencial. Cancelado.[/]\n"); return
            
        nova_senha_bytes = bytearray(nova_senha_str.encode('utf-8'))
        del nova_senha_str, confirma_nova_senha_str

        # Deriva a NOVA chave de 256 bits usando a NOVA senha, mas o MESMO salt antigo do DB
        with open(CAMINHO_SALT_DB, "rb") as f: db_salt = f.read()
        nova_chave_db = low_level.hash_secret_raw(
            secret=bytes(nova_senha_bytes),
            salt=db_salt,
            time_cost=6,
            memory_cost=524288,
            parallelism=8,
            hash_len=32,
            type=low_level.Type.ID
        )
        
        # Usa a nova chave derivada para recriptografar o banco
        nova_chave_db_hex = nova_chave_db.hex()
        conn.execute(f"PRAGMA rekey = \"x'{nova_chave_db_hex}'\"")
        conn.commit()

        # Atualiza o arquivo de hash de verificação rápida com a nova senha
        novo_hash_db = ph.hash(bytes(nova_senha_bytes))
        with open(CAMINHO_HASH_DB, "w") as f: f.write(novo_hash_db)

        console.print(f"\n[{THEME['feedback.success']}]Feito! A senha do cofre foi alterada. Não vai esquecer, hein?.[/]\n")
    
    except Exception as e:
        console.print(f"\n[{THEME['feedback.error']}]Deu um erro bizarro ao tentar trocar a chave: {e}[/]\n")
    finally:
        if senha_atual_bytes:
            secure_wipe(senha_atual_bytes)
        if nova_senha_bytes:
            secure_wipe(nova_senha_bytes)


def corromper_e_apagar_tudo():
    console.rule(f"[{THEME['panel.danger']}]PROTOCOLO DE AUTODESTRUIÇÃO ATIVADO[/]", style=THEME["panel.danger"])
    try:
        if os.path.exists(NOME_DO_BANCO):
            tamanho_lixo = os.path.getsize(NOME_DO_BANCO)
            with open(NOME_DO_BANCO, "wb") as f: f.write(os.urandom(max(tamanho_lixo, 4096)))
            console.print(f"[{THEME['feedback.error']}]- Cofre sobrescrito com lixo digital.[/]")
            os.remove(NOME_DO_BANCO)
            console.print(f"[{THEME['feedback.error']}]- Arquivo do cofre deletado.[/]")
        if os.path.exists(CAMINHO_HASH_DB):
            os.remove(CAMINHO_HASH_DB)
            console.print(f"[{THEME['feedback.error']}]- Arquivo de verificação deletado.[/]")
        if os.path.exists(CAMINHO_SALT_DB):
            os.remove(CAMINHO_SALT_DB)
            console.print(f"[{THEME['feedback.error']}]- Arquivo de salt do banco deletado.[/]")

        console.line()
        console.print("[bold red on black] MISSÃO CUMPRIDA. TODOS OS DADOS FORAM PERMANENTEMENTE DESTRUÍDOS. [/bold red on black]")
        console.print("[italic]Foi bom enquanto durou...[/italic]\n")
    except Exception as e:
        console.print(f"\n[{THEME['feedback.error']}]Até pra destruir deu erro: {e}[/]\n")

def formatar_cofre():
    console.rule(style=THEME["panel.danger"])
    console.print(Panel.fit("💥 FORMATAR O COFRE 💥", border_style=THEME["panel.danger"]))
    console.print("Isso é um adeus sem volta. [bold red]TUDO SERÁ APAGADO.[/bold red]", justify="center")
    
    if Prompt.ask(f"\n[{THEME['prompt.confirm']}]> Digite '[bold red]APAGAR TUDO[/bold red]' se tiver coragem[/]").upper() != "APAGAR TUDO":
        console.print(f"\n[{THEME['feedback.success']}]Formatação cancelada. Seu cofre respira aliviado.[/]\n"); return
    
    if Prompt.ask(f"[{THEME['prompt.confirm']}]> Última chance. Digite '[bold red]SIM, TENHO CERTEZA[/bold red]'[/]").upper() != "SIM, TENHO CERTEZA":
        console.print(f"\n[{THEME['feedback.success']}]Formatação cancelada. Quase, hein?[/]\n"); return
    
    senha_final_bytes = None
    try:
        senha_final_str = get_secure_pass("Por segurança, digite a senha do cofre: ")
        senha_final_bytes = bytearray(senha_final_str.encode('utf-8'))
        del senha_final_str

        conn_teste = verificar_senha_e_conectar(senha_final_bytes)
        if conn_teste:
            conn_teste.close()
            corromper_e_apagar_tudo()
            console.print("\nO cofre foi... formatado."); sys.exit()
        else:
            console.print(f"\n[{THEME['feedback.error']}]SENHA INCORRETA. A autodestruição foi abortada.[/]\n")
    finally:
        if senha_final_bytes:
            secure_wipe(senha_final_bytes)


def listar_identificadores(conn):
    console.rule(style="green")
    cursor = conn.cursor()
    cursor.execute("SELECT identificador FROM segredos ORDER BY identificador")
    resultados = cursor.fetchall()
    if resultados:
        table = Table(title=f"[{THEME['title']}]Nossos Segredos Guardados[/]", border_style="green", expand=True, padding=(0,2))
        table.add_column("Identificador 📌", justify="left", style="cyan", no_wrap=False)
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


def limpar_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    limpar_terminal()
    painel_boas_vindas = Panel.fit(
        Text("Cofre Digital", justify="center", style=THEME["title"]) +
        Text("\nNosso pequeno espaço seguro.", justify="center", style="cyan"),
        border_style=THEME["panel.main"]
    )
    console.print(painel_boas_vindas)
    console.line()
    
    conn = None
    for i in range(5):
        senha_acesso_db_bytes = None
        try:
            senha_acesso_db_str = get_secure_pass("Senha de acesso, por favor: ")
            senha_acesso_db_bytes = bytearray(senha_acesso_db_str.encode('utf-8'))
            del senha_acesso_db_str

            conn = verificar_senha_e_conectar(senha_acesso_db_bytes)

            if conn:
                console.print(f"\n[{THEME['feedback.success']}]Cofre desbloqueado. Bem-vindo de volta, {USER_NAME}.[/]\n");
                break
            else:
                console.print(f"\n[{THEME['feedback.error']}]Acesso negado.[/]\n")
        finally:
             if senha_acesso_db_bytes:
                secure_wipe(senha_acesso_db_bytes)
    
    if not conn:
        console.print(f"[{THEME['feedback.error']}]Múltiplas falhas de autenticação. Ativando protocolo de segurança...[/]")
        corromper_e_apagar_tudo()
        return

    while True:
        console.rule(style=THEME["panel.menu"])
        menu_text = Text("O que faremos agora?", justify="center", style=THEME["title"])
        menu_text.append("\n\n1. ✨ Adicionar novo segredo", style="green")
        menu_text.append("\n2. 🔍 Consultar um segredo", style="cyan")
        menu_text.append("\n3. 📜 Listar todos os segredos", style="yellow")
        menu_text.append("\n4. 🗑️ Remover um segredo", style="red")
        menu_text.append("\n5. 🔑 Alterar Senha de Acesso", style="bold yellow")
        menu_text.append("\n6. 💾 Backup (Exportar/Importar)", style="bold blue")
        menu_text.append("\n7. 💥 Formatar o Cofre (APAGAR TUDO)", style="bold red")
        menu_text.append("\n8. 🚪 Sair", style="bold white")
        
        painel_menu = Panel(menu_text, title="Menu Principal", border_style=THEME["panel.menu"], expand=False)
        console.print(Align.center(painel_menu))
        
        escolha = Prompt.ask(f"[{THEME['prompt.default']}]> Sua escolha[/]", choices=[str(i) for i in range(1, 9)])
        
        if escolha == '1': adicionar_entrada(conn)
        elif escolha == '2': consultar_entrada(conn)
        elif escolha == '3': listar_identificadores(conn)
        elif escolha == '4': remover_entrada(conn)
        elif escolha == '5': alterar_senha_mestra(conn)
        elif escolha == '6': menu_backup(conn)
        elif escolha == '7': formatar_cofre()
        elif escolha == '8': break
    
    conn.close()
    console.print(f"\n[{THEME['feedback.special']}]Cofre trancado. Seus segredos estão seguros comigo. Até a próxima, {USER_NAME}.[/]\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Operação interrompida. Saindo...[/yellow]")