
import mysql.connector
from werkzeug.security import generate_password_hash
import config


def criar_admin():
    nome = input("Nome do administrador: ")
    usuario = input("Nome de usuario: ")
    senha = input("Senha: ")

    senha_hash = generate_password_hash(senha)

    conexao = None
    cursor = None

    try:
        conexao = mysql.connector.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USUARIO,
            password=config.MYSQL_SENHA,
            database=config.MYSQL_BANCO
        )

        cursor = conexao.cursor()

        comando = """
            INSERT INTO administradores (nome, usuario, senha_hash)
            VALUES (%s, %s, %s)
        """

        cursor.execute(comando, (nome, usuario, senha_hash))
        conexao.commit()

        print("\nAdministrador cadastrado com sucesso!")

    except mysql.connector.Error as erro:
        print(f"\nErro ao cadastrar administrador: {erro}")

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


if __name__ == "__main__":
    criar_admin()
