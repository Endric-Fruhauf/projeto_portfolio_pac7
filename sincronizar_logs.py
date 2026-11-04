
import mysql.connector
import config

from datetime import datetime
from idface import IDFaceError


def sincronizar_logs(idface):
    conexao = None
    cursor = None

    resultado_sync = {
        "novos": 0,
        "atualizados": 0,
        "ignorados": 0,
        "sucesso": False
    }

    try:
        print("=== SINCRONIZACAO DE REGISTROS DE ACESSO ===\n")

        # =====================================
        # 1. CONECTAR AO MYSQL
        # =====================================

        conexao = mysql.connector.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USUARIO,
            password=config.MYSQL_SENHA,
            database=config.MYSQL_BANCO
        )

        cursor = conexao.cursor()

        print("Conexao com MySQL realizada!\n")

        # =====================================
        # 2. DESCOBRIR ULTIMO REGISTRO
        # =====================================

        cursor.execute(
            """
            SELECT COALESCE(MAX(id_idface), 0)
            FROM registros_acesso
            """
        )

        ultimo_id = cursor.fetchone()[0]

        print(f"Ultimo registro sincronizado: {ultimo_id}")

        # =====================================
        # 3. BUSCAR REGISTROS EM LOTES DE 50
        # =====================================

        continuar = True

        while continuar:

            resposta = idface.requisicao(
                "load_objects.fcgi",
                {
                    "object": "access_logs",
                    "fields": [
                        "id",
                        "time",
                        "event",
                        "device_id",
                        "user_id",
                        "identifier_id",
                        "portal_id"
                    ],
                    "where": [
                        {
                            "object": "access_logs",
                            "field": "id",
                            "operator": ">",
                            "value": ultimo_id
                        }
                    ],
                    "limit": 50,
                    "order": ["ascending", "id"]
                }
            )

            registros = resposta.get("access_logs", [])

            print(
                f"\nRegistros encontrados neste lote: "
                f"{len(registros)}"
            )

            if not registros:
                break

            maior_id_lote = ultimo_id

            # =====================================
            # 4. PROCESSAR REGISTROS
            # =====================================

            for registro in registros:

                id_registro = registro.get("id")
                horario = registro.get("time")
                evento = registro.get("event")
                dispositivo = registro.get("device_id")
                usuario_idface = registro.get("user_id")

                if id_registro is None:
                    resultado_sync["ignorados"] += 1
                    continue

                maior_id_lote = max(
                    maior_id_lote,
                    int(id_registro)
                )

                if (
                    horario is None
                    or evento is None
                    or dispositivo is None
                ):
                    resultado_sync["ignorados"] += 1
                    continue

                # Converter horario do equipamento.
                data_hora = datetime.fromtimestamp(int(horario))

                # =====================================
                # 5. LOCALIZAR USUARIO NO MYSQL
                # =====================================

                id_usuario = None

                if usuario_idface:
                    cursor.execute(
                        """
                        SELECT id
                        FROM usuarios
                        WHERE id_idface = %s
                        """,
                        (usuario_idface,)
                    )

                    usuario = cursor.fetchone()

                    if usuario:
                        id_usuario = usuario[0]

                # =====================================
                # 6. INSERIR OU ATUALIZAR REGISTRO
                # =====================================

                cursor.execute(
                    """
                    INSERT INTO registros_acesso
                    (
                        id_idface,
                        id_usuario,
                        data_hora,
                        evento,
                        dispositivo_id
                    )
                    VALUES (%s, %s, %s, %s, %s)

                    ON DUPLICATE KEY UPDATE
                        id_usuario = VALUES(id_usuario),
                        data_hora = VALUES(data_hora),
                        evento = VALUES(evento),
                        dispositivo_id = VALUES(dispositivo_id)
                    """,
                    (
                        id_registro,
                        id_usuario,
                        data_hora,
                        evento,
                        dispositivo
                    )
                )

                if cursor.rowcount == 1:
                    resultado_sync["novos"] += 1

                elif cursor.rowcount == 2:
                    resultado_sync["atualizados"] += 1

                print(
                    f"Registro ID: {id_registro} | "
                    f"Usuario ID: {id_usuario} | "
                    f"Data: {data_hora.strftime('%d/%m/%Y %H:%M:%S')}"
                )

            # =====================================
            # 7. AVANCAR PARA O PROXIMO LOTE
            # =====================================

            ultimo_id = maior_id_lote

            if len(registros) < 50:
                continuar = False

        # =====================================
        # 8. CONFIRMAR ALTERACOES
        # =====================================

        conexao.commit()

        resultado_sync["sucesso"] = True

        print("\n=== RESULTADO ===")
        print("Novos registros:", resultado_sync["novos"])
        print("Registros atualizados:", resultado_sync["atualizados"])
        print("Registros ignorados:", resultado_sync["ignorados"])
        print("\nSincronizacao de registros concluida!")

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
            sincronizar_logs(cliente)

    except Exception as erro:
        print("Erro ao executar sincronizacao:", erro)
