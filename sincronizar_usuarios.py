
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

        # =====================================
        # 1. AUTENTICAR NO IDFACE
        # =====================================

        resposta = requests.post(
            f"http://{config.IDFACE_IP}/login.fcgi",
            json={
                "login": config.IDFACE_USUARIO,
                "password": config.IDFACE_SENHA
            },
            timeout=10
        )

        resposta.raise_for_status()
        dados_login = resposta.json()

        if "error" in dados_login:
            raise Exception(
                f"Erro de autenticacao: {dados_login['error']}"
            )

        sessao = dados_login.get("session")

        if not sessao:
            raise Exception(
                "O iDFace nao retornou uma sessao valida."
            )

        print("Autenticacao no iDFace realizada!")

        # =====================================
        # 2. CONSULTAR USUARIOS
        # =====================================

        resposta = requests.post(
            f"http://{config.IDFACE_IP}/load_objects.fcgi",
            params={"session": sessao},
            json={"object": "users"},
            timeout=10
        )

        resposta.raise_for_status()
        dados_usuarios = resposta.json()

        if "error" in dados_usuarios:
            raise Exception(
                f"Erro ao consultar usuarios: {dados_usuarios['error']}"
            )

        usuarios = dados_usuarios.get("users", [])

        print(
            f"Usuarios encontrados no iDFace: {len(usuarios)}"
        )

        # =====================================
        # 3. CONSULTAR PRIVILEGIOS
        # =====================================

        resposta = requests.post(
            f"http://{config.IDFACE_IP}/load_objects.fcgi",
            params={"session": sessao},
            json={"object": "user_roles"},
            timeout=10
        )

        resposta.raise_for_status()
        dados_privilegios = resposta.json()

        if "error" in dados_privilegios:
            raise Exception(
                "Erro ao consultar privilegios: "
                f"{dados_privilegios['error']}"
            )

        privilegios = dados_privilegios.get("user_roles", [])

        # Guarda os IDs dos usuarios administradores.
        administradores_idface = {
            privilegio["user_id"]
            for privilegio in privilegios
            if privilegio.get("role") == 1
        }

        print(
            f"Usuarios com privilegio administrativo: "
            f"{len(administradores_idface)}"
        )

        # =====================================
        # 4. CONECTAR AO MYSQL
        # =====================================

        conexao = mysql.connector.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USUARIO,
            password=config.MYSQL_SENHA,
            database=config.MYSQL_BANCO
        )

        cursor = conexao.cursor()

        print("\nConexao com MySQL realizada!")

        # =====================================
        # 5. SINCRONIZAR USUARIOS
        # =====================================

        for usuario in usuarios:

            id_idface = usuario.get("id")
            nome = usuario.get("name")

            if id_idface is None or not nome:
                resultado_sync["ignorados"] += 1
                print(
                    "Usuario ignorado: ID ou nome ausente."
                )
                continue

            # Determinar categoria pelo user_roles.
            categoria = (
                "administrador"
                if id_idface in administradores_idface
                else "membro"
            )

            # Procurar pelo identificador do equipamento.
            cursor.execute(
                """
                SELECT id
                FROM usuarios
                WHERE id_idface = %s
                """,
                (id_idface,)
            )

            existente = cursor.fetchone()

            if existente:

                # Atualizar usuario existente.
                cursor.execute(
                    """
                    UPDATE usuarios
                    SET nome = %s,
                        categoria = %s
                    WHERE id = %s
                    """,
                    (
                        nome,
                        categoria,
                        existente[0]
                    )
                )

                resultado_sync["atualizados"] += 1

                print(
                    f"Atualizado: {nome} | "
                    f"ID MySQL: {existente[0]} | "
                    f"ID iDFace: {id_idface} | "
                    f"Categoria: {categoria}"
                )

            else:

                # Inserir usuario novo.
                cursor.execute(
                    """
                    INSERT INTO usuarios
                    (id_idface, nome, categoria)
                    VALUES (%s, %s, %s)
                    """,
                    (
                        id_idface,
                        nome,
                        categoria
                    )
                )

                id_mysql = cursor.lastrowid

                resultado_sync["novos"] += 1

                print(
                    f"Novo usuario: {nome} | "
                    f"ID MySQL: {id_mysql} | "
                    f"ID iDFace: {id_idface} | "
                    f"Categoria: {categoria}"
                )

        # =====================================
        # 6. CONFIRMAR ALTERACOES
        # =====================================

        conexao.commit()

        resultado_sync["sucesso"] = True

        print("\n=== RESULTADO ===")
        print(
            "Novos usuarios:",
            resultado_sync["novos"]
        )
        print(
            "Usuarios atualizados:",
            resultado_sync["atualizados"]
        )
        print(
            "Usuarios ignorados:",
            resultado_sync["ignorados"]
        )
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

        # =====================================
        # 7. ENCERRAR SESSAO DO IDFACE
        # =====================================

        if sessao:
            try:
                requests.post(
                    f"http://{config.IDFACE_IP}/logout.fcgi",
                    params={"session": sessao},
                    timeout=5
                )
            except requests.exceptions.RequestException:
                pass

        # =====================================
        # 8. ENCERRAR CONEXAO MYSQL
        # =====================================

        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()

    return resultado_sync


if __name__ == "__main__":
    sincronizar_usuarios()
