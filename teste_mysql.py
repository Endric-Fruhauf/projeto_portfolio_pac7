
import mysql.connector
from mysql.connector import Error
import config


try:
    print("=== TESTE DE CONEXAO COM MYSQL ===\n")

    conexao = mysql.connector.connect(
        host=config.MYSQL_HOST,
        port=config.MYSQL_PORT,
        user=config.MYSQL_USUARIO,
        password=config.MYSQL_SENHA,
        database=config.MYSQL_BANCO
    )

    if conexao.is_connected():
        print("Conexao com MySQL estabelecida!")

        cursor = conexao.cursor()
        cursor.execute("SELECT DATABASE();")

        banco = cursor.fetchone()
        print("Banco conectado:", banco[0])

        cursor.close()
        conexao.close()

        print("\nConexao encerrada corretamente.")

except Error as erro:
    print("\nErro na conexao com MySQL:")
    print(erro)
