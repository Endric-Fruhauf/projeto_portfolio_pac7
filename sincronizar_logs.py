
import requests
import mysql.connector
import config
from datetime import datetime


def sincronizar_logs():
    conexao = None
    cursor = None
    sessao = None

    resultado_sync = {
        "novos": 0,
        "atualizados": 0,
        "ignorados": 0,
        "sucesso": False
    }

    try:
        print("=== SINCRONIZACAO DE REGISTROS DE ACESSO ===\n")

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
            raise Exception("Erro na autenticacao do iDFace.")

        print("Autenticacao realizada com sucesso!")

        # 2. Conectar ao MySQL
        conexao = mysql.connector.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USUARIO,
            password=config.MYSQL_SENHA,
            database=config.MYSQL_BANCO
        )

        cursor = conexao.cursor()

        print("Conexao com MySQL realizada!\n")

        # 3. Descobrir o ultimo registro sincronizado
        cursor.execute(
            """
            SELECT COALESCE(MAX(id_idface), 0)
            FROM registros_acesso
            """
        )

        ultimo_id = cursor.fetchone()[0]

        print(f"Ultimo registro sincronizado: {ultimo_id}")

        # 4. Buscar registros novos em lotes de 50
        continuar = True

        while continuar:

            resposta = requests.post(
                f"http://{config.IDFACE_IP}/load_objects.fcgi?session={sessao}",
                json={
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
                },
                timeout=10
            )

            resposta.raise_for_status()

            registros = resposta.json().get("access_logs", [])

            print(f"\nRegistros encontrados neste lote: {len(registros)}")

            if not registros:
                break

            maior_id_lote = ultimo_id

            # 5. Processar registros recebidos
            for registro in registros:

                id_registro = registro.get("id")
                horario = registro.get("time")
                evento = registro.get("event")
                dispositivo = registro.get("device_id")
                usuario_idface = registro.get("user_id")

                if id_registro is None:
                    resultado_sync["ignorados"] += 1
                    continue

                maior_id_lote = max(maior_id_lote, int(id_registro))

                if (
                    horario is None
                    or evento is None
                    or dispositivo is None
                ):
                    resultado_sync["ignorados"] += 1
                    continue

                # Converter horario do equipamento
                data_hora = datetime.fromtimestamp(int(horario))

                # 6. Localizar usuario no MySQL
                id_usuario = None

                if usuario_idface:
                    cursor.execute(
                        """
                        SELECT id FROM usuarios
                        WHERE id_idface = %s
                        """,
                        (usuario_idface,)
                    )

                    usuario = cursor.fetchone()

                    if usuario:
                        id_usuario = usuario[0]

                # 7. Inserir registro no MySQL
                cursor.execute(
                    """
                    INSERT INTO registros_acesso
                    (id_idface, id_usuario, data_hora, evento, dispositivo_id)
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

            # Avancar para o proximo lote
            ultimo_id = maior_id_lote

            # Se vieram menos de 50, nao existem mais lotes
            if len(registros) < 50:
                continuar = False

        conexao.commit()

        resultado_sync["sucesso"] = True

        print("\n=== RESULTADO ===")
        print("Novos registros:", resultado_sync["novos"])
        print("Registros atualizados:", resultado_sync["atualizados"])
        print("Registros ignorados:", resultado_sync["ignorados"])
        print("\nSincronizacao concluida!")

    except requests.exceptions.RequestException as erro:
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
        # 8. Encerrar sessao do iDFace
        if sessao:
            try:
                requests.post(
                    f"http://{config.IDFACE_IP}/logout.fcgi?session={sessao}",
                    timeout=5
                )
            except requests.exceptions.RequestException:
                pass

        # 9. Encerrar conexao com MySQL
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()

    return resultado_sync


if __name__ == "__main__":
    sincronizar_logs()
