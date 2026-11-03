
import requests
import mysql.connector
import config


def sincronizar_usuarios():
    sessao = None
    conexao = None
    cursor = None

    resultado_sync = {
        "novos": 0,
        "atualizados": 0,
        "ignorados": 0,
        "sucesso": False
    }

    try:
        print("=== SINCRONIZACAO DE USUARIOS ===\n")

        # 1. Autenticar no iDFace
        resposta = requests.post(
            f"http://{config.IDFACE_IP}/login.fcgi",
            json={
                "login": config.IDFACE_USUARIO,
                "password": config.IDFACE_SENHA
            },
            timeout=10
        )

        resposta.raise_for_status()
        sessao = resposta.json().get("session")

        if not sessao:
            raise Exception(
                "Nao foi possivel autenticar no iDFace."
            )

        print("Autenticacao no iDFace realizada!")

        # 2. Consultar usuarios do iDFace
        resposta = requests.post(
            f"http://{config.IDFACE_IP}/load_objects.fcgi?session={sessao}",
            json={"object": "users"},
            timeout=10
        )

        resposta.raise_for_status()
        usuarios = resposta.json().get("users", [])

        print(f"Usuarios encontrados no iDFace: {len(usuarios)}")

        # 3. Conectar ao MySQL
        conexao = mysql.connector.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USUARIO,
            password=config.MYSQL_SENHA,
            database=config.MYSQL_BANCO
        )

        cursor = conexao.cursor()

        print("\nConexao com MySQL realizada!")

        # 4. Inserir ou atualizar usuarios
        for usuario in usuarios:

            id_idface = usuario.get("id")
            matricula = usuario.get("registration")
            nome = usuario.get("name")

            if id_idface is None or not matricula or not nome:
                resultado_sync["ignorados"] += 1
                print("Usuario ignorado: dados incompletos.")
                continue

            cursor.execute(
                """
                SELECT id FROM usuarios
                WHERE matricula = %s OR id_idface = %s
                """,
                (matricula, id_idface)
            )

            existente = cursor.fetchone()

            if existente:
                cursor.execute(
                    """
                    UPDATE usuarios
                    SET id_idface = %s,
                        matricula = %s,
                        nome = %s
                    WHERE id = %s
                    """,
                    (id_idface, matricula, nome, existente[0])
                )

                resultado_sync["atualizados"] += 1

            else:
                cursor.execute(
                    """
                    INSERT INTO usuarios
                    (id_idface, matricula, nome)
                    VALUES (%s, %s, %s)
                    """,
                    (id_idface, matricula, nome)
                )

                resultado_sync["novos"] += 1

            print(f"Processado: {nome} | Matricula: {matricula}")

        conexao.commit()

        resultado_sync["sucesso"] = True

        print("\n=== RESULTADO ===")
        print("Novos usuarios:", resultado_sync["novos"])
        print("Usuarios atualizados:", resultado_sync["atualizados"])
        print("Usuarios ignorados:", resultado_sync["ignorados"])
        print("Sincronizacao concluida!")

    except requests.exceptions.RequestException as erro:
        print("\nErro na comunicacao com iDFace:")
        print(erro)

    except mysql.connector.Error as erro:
        if conexao and conexao.is_connected():
            conexao.rollback()

        print("\nErro no MySQL:")
        print(erro)

    except Exception as erro:
        if conexao and conexao.is_connected():
            conexao.rollback()

        print("\nErro inesperado:")
        print(erro)

    finally:
        # 5. Encerrar sessao do iDFace
        if sessao:
            try:
                requests.post(
                    f"http://{config.IDFACE_IP}/logout.fcgi?session={sessao}",
                    timeout=5
                )
            except requests.exceptions.RequestException:
                pass

        # 6. Encerrar conexao com MySQL
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()

    return resultado_sync


if __name__ == "__main__":
    sincronizar_usuarios()
