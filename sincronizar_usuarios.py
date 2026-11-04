
import mysql.connector
import config

from idface import IDFaceError


def sincronizar_usuarios(idface):
    conexao = None
    cursor = None

    resultado_sync = {
        "novos": 0,
        "atualizados": 0,
        "inativados": 0,
        "ignorados": 0,
        "sucesso": False
    }

    try:
        print("=== SINCRONIZACAO DE USUARIOS ===\n")

        # =====================================
        # 1. CONSULTAR USUARIOS NO IDFACE
        # =====================================

        usuarios = idface.consultar_usuarios()

        if not isinstance(usuarios, list):
            raise ValueError(
                "Resposta invalida ao consultar usuarios no iDFace."
            )

        print(f"Usuarios encontrados no iDFace: {len(usuarios)}")

        # =====================================
        # 2. CONSULTAR PRIVILEGIOS
        # =====================================

        dados_privilegios = idface.requisicao(
            "load_objects.fcgi",
            {"object": "user_roles"}
        )

        if not isinstance(dados_privilegios, dict):
            raise ValueError(
                "Resposta invalida ao consultar privilegios do iDFace."
            )

        privilegios = dados_privilegios.get("user_roles", [])

        if not isinstance(privilegios, list):
            raise ValueError(
                "Lista de privilegios do iDFace invalida."
            )

        administradores_idface = {
            int(privilegio["user_id"])
            for privilegio in privilegios
            if privilegio.get("role") == 1
            and privilegio.get("user_id") is not None
        }

        print(
            "Usuarios com privilegio administrativo: "
            f"{len(administradores_idface)}"
        )

        # =====================================
        # 3. CONECTAR AO MYSQL
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
        # 4. IDENTIFICAR USUARIOS PRESENTES
        # =====================================

        ids_presentes = set()

        for usuario in usuarios:
            id_idface = usuario.get("id")

            if id_idface is not None:
                ids_presentes.add(int(id_idface))

        # =====================================
        # 5. SINCRONIZAR USUARIOS DO IDFACE
        # =====================================

        for usuario in usuarios:

            id_idface = usuario.get("id")
            nome = usuario.get("name")

            if id_idface is None or not nome:
                resultado_sync["ignorados"] += 1

                print("Usuario ignorado: ID ou nome ausente.")
                continue

            id_idface = int(id_idface)

            categoria = (
                "administrador"
                if id_idface in administradores_idface
                else "membro"
            )

            cursor.execute(
                """
                SELECT id, ativo
                FROM usuarios
                WHERE id_idface = %s
                """,
                (id_idface,)
            )

            existente = cursor.fetchone()

            if existente:

                id_mysql, ativo = existente

                # Cadastro historico nunca e reativado.
                if not ativo:
                    resultado_sync["ignorados"] += 1

                    print(
                        f"Cadastro historico ignorado: {nome} | "
                        f"ID MySQL: {id_mysql} | "
                        f"ID iDFace: {id_idface}"
                    )

                    continue

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
                        id_mysql
                    )
                )

                resultado_sync["atualizados"] += 1

                print(
                    f"Atualizado: {nome} | "
                    f"ID MySQL: {id_mysql} | "
                    f"ID iDFace: {id_idface} | "
                    f"Categoria: {categoria}"
                )

            else:

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
        # 6. IDENTIFICAR USUARIOS EXCLUIDOS
        # =====================================

        cursor.execute(
            """
            SELECT id, id_idface, nome
            FROM usuarios
            WHERE ativo = 1
              AND categoria = 'membro'
              AND id_idface IS NOT NULL
            """
        )

        usuarios_ativos = cursor.fetchall()

        for id_mysql, id_idface, nome in usuarios_ativos:

            if id_idface not in ids_presentes:

                cursor.execute(
                    """
                    UPDATE usuarios
                    SET ativo = 0
                    WHERE id = %s
                    """,
                    (id_mysql,)
                )

                resultado_sync["inativados"] += 1

                print(
                    f"Usuario excluido do iDFace: {nome} | "
                    f"ID MySQL: {id_mysql} | "
                    f"ID iDFace: {id_idface} | "
                    "Cadastro preservado como historico."
                )

        # =====================================
        # 7. CONFIRMAR ALTERACOES
        # =====================================

        conexao.commit()

        resultado_sync["sucesso"] = True

        print("\n=== RESULTADO ===")
        print("Novos usuarios:", resultado_sync["novos"])
        print("Usuarios atualizados:", resultado_sync["atualizados"])
        print("Usuarios inativados:", resultado_sync["inativados"])
        print("Usuarios ignorados:", resultado_sync["ignorados"])
        print("Sincronizacao de usuarios concluida!")

    except IDFaceError as erro:

        if conexao and conexao.is_connected():
            conexao.rollback()

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

        # A sessao do iDFace pertence ao servidor.py.
        # Portanto, nao encerramos a sessao aqui.

        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()

    return resultado_sync


if __name__ == "__main__":
    from idface import IDFaceClient

    try:
        with IDFaceClient() as cliente:
            sincronizar_usuarios(cliente)

    except Exception as erro:
        print("Erro ao executar sincronizacao:", erro)
