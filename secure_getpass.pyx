# secure_getpass.pyx

import sys
from libc.stdlib cimport malloc, free
from libc.string cimport memset
from libc.stdio cimport putchar

# --- Lógica de captura de caracteres para diferentes sistemas operacionais ---
try:
    # Lógica para Unix-like (Linux, macOS)
    import termios, tty
    def _getch():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch
except ImportError:
    try:
        # Lógica para Windows
        import msvcrt
        def _getch():
            return msvcrt.getch().decode('utf-8')
    except ImportError:
        # Fallback para sistemas não suportados (menos seguro, pois pode ter echo)
        def _getch():
            return sys.stdin.read(1)

def get_secure_pass(prompt: str, buffer_size: int = 512):
    """
    Captura a senha de forma segura, usando um buffer em C que é
    imediatamente limpo da memória após o uso.
    """
    cdef char* password_buffer = <char*>malloc(buffer_size * sizeof(char))
    cdef int i = 0
    # Não precisamos de 'cdef char c', pois a variável de loop pode ser dinâmica
    
    if not password_buffer:
        raise MemoryError("Falha ao alocar memória para a senha.")

    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        
        while i < (buffer_size - 1):
            char_in = _getch()
            
            # Tecla Enter/Return finaliza a entrada
            if char_in == '\r' or char_in == '\n':
                putchar(b'\n')
                break
            
            # Tecla Backspace/Delete (códigos para Unix e Windows)
            if char_in == '\x7f' or char_in == '\b':
                if i > 0:
                    i -= 1
                    # Move o cursor para trás, escreve um espaço, move para trás de novo
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            # Caracteres imprimíveis
            elif len(char_in.encode('utf-8')) == 1: # Garante que não é uma tecla de controle estranha
                password_buffer[i] = char_in.encode('utf-8')[0]
                sys.stdout.write('*')
                sys.stdout.flush()
                i += 1
        
        # Adiciona o terminador nulo para formar uma string C válida
        password_buffer[i] = 0

        # Converte o buffer C para uma string Python para ser retornada
        py_password = password_buffer[:i].decode('utf-8')
        return py_password
        
    finally:
        # --- ETAPA MAIS IMPORTANTE ---
        # Limpa o buffer com zeros, destruindo a senha da memória RAM.
        memset(password_buffer, 0, buffer_size)
        # Libera a memória alocada.
        free(password_buffer)
