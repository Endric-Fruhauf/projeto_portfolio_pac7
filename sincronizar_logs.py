
import mysql.connector
import config

from datetime import datetime
from idface import IDFaceError


TAMANHO_LOTE = 50


def _converter_inteiro(valor):
    """Converte um valor para inteiro, retornando None se inválido."""
    if valor is None:
        return None

    try:
        return int(valor)
    except (TypeError, ValueError, OverflowError):
        return None


def _converter_data_hora(horario):
    """Converte o timestamp Unix para datetime local."""
    timestamp = _converter_inteiro(horario)

    if timestamp is None:
        return None

    try:
        return datetime.fromtimestamp(timestamp)
    except (ValueError, OverflowError, OSError):
        return None


def _localizar_usuario(cursor, usuario_idface):
    """
    Localiza o usuário pelo histórico de IDs do iDFace.
    O histórico tem prioridade sobre o vínculo atual.
    """
    if usuario_idface is None:
        return None

    cursor.execute(
        """
        SELECT id_usuario
        FROM usuarios_idface_historico
        WHERE id_idface = %s
        """,
        (usuario_idface,)
    )

    usuario = cursor.fetchone()

    if usuario:
        return usuario[0]

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
        return usuario[0]

    return None


def _buscar_evento_idface(idface, id_registro):
    """Busca novamente um evento específico no equipamento."""
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
                    "operator": "=",
                    "value": id_registro
                }
            ],
            "limit": 1
        }
    )

    registros = resposta.get("access_logs", [])

    if not registros:
        return None

    return registros[0]


def _salvar_pendente(cursor, registro, erro):
    """Insere ou atualiza um evento incompleto."""
    id_registro = _converter_inteiro(registro.get("id"))

    if id_registro is None:
        return False

    horario = _converter_inteiro(registro.get("time"))
    usuario_idface = _converter_inteiro(registro.get("user_id"))
    evento = _converter_inteiro(registro.get("event"))
    dispositivo = _converter_inteiro(registro.get("device_id"))
    identifier_id = _converter_inteiro(registro.get("identifier_id"))
    portal_id = _converter_inteiro(registro.get("portal_id"))

    cursor.execute(
        """
        INSERT INTO registros_acesso_pendentes
        (
            id_idface,
            horario,
            usuario_idface,
            evento,
            dispositivo_id,
            identifier_id,
            portal_id,
            ultima_tentativa,
            tentativas,
            erro
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), 1, %s)

        ON DUPLICATE KEY UPDATE
            horario = COALESCE(
                VALUES(horario),
                horario
            ),
            usuario_idface = COALESCE(
                VALUES(usuario_idface),
                usuario_idface
            ),
            evento = COALESCE(
                VALUES(evento),
                evento
            ),
            dispositivo_id = COALESCE(
                VALUES(dispositivo_id),
                dispositivo_id
            ),
            identifier_id = COALESCE(
                VALUES(identifier_id),
                identifier_id
            ),
            portal_id = COALESCE(
                VALUES(portal_id),
                portal_id
            ),
            ultima_tentativa = NOW(),
            tentativas = tentativas + 1,
            erro = VALUES(erro)
        """,
        (
            id_registro,
            horario,
            usuario_idface,
            evento,
            dispositivo,
            identifier_id,
            portal_id,
            str(erro)[:255] if erro else None
        )
    )

    return True


def _salvar_registro(cursor, registro, resultado_sync):
    """Insere ou atualiza um evento completo no MySQL."""
    id_registro = _converter_inteiro(registro.get("id"))

    if id_registro is None:
        resultado_sync["ignorados"] += 1
        return False

    data_hora = _converter_data_hora(registro.get("time"))

    if data_hora is None:
        return False

    usuario_idface = _converter_inteiro(
        registro.get("user_id")
    )

    evento = _converter_inteiro(registro.get("event"))
    dispositivo = _converter_inteiro(
        registro.get("device_id")
    )

    id_usuario = _localizar_usuario(
        cursor,
        usuario_idface
    )

    cursor.execute(
        """
        SELECT id_usuario, usuario_idface
        FROM registros_acesso
        WHERE id_idface = %s
        """,
        (id_registro,)
    )

    registro_existente = cursor.fetchone()

    cursor.execute(
        """
        INSERT INTO registros_acesso
        (
            id_idface,
            id_usuario,
            usuario_idface,
            data_hora,
            evento,
            dispositivo_id
        )
        VALUES (%s, %s, %s, %s, %s, %s)

        ON DUPLICATE KEY UPDATE
            id_usuario = COALESCE(
                registros_acesso.id_usuario,
                VALUES(id_usuario)
            ),
            usuario_idface = COALESCE(
                VALUES(usuario_idface),
                registros_acesso.usuario_idface
            ),
            data_hora = VALUES(data_hora),
            evento = COALESCE(
                VALUES(evento),
                registros_acesso.evento
            ),
            dispositivo_id = COALESCE(
                VALUES(dispositivo_id),
                registros_acesso.dispositivo_id
            )
        """,
        (
            id_registro,
            id_usuario,
            usuario_idface,
            data_hora,
            evento,
            dispositivo
        )
    )

    if registro_existente is None:
        resultado_sync["novos"] += 1
    else:
        resultado_sync["atualizados"] += 1

    cursor.execute(
        """
        DELETE FROM registros_acesso_pendentes
        WHERE id_idface = %s
        """,
        (id_registro,)
    )

    print(
        f"Registro ID: {id_registro} | "
        f"Usuario MySQL: {id_usuario} | "
        f"Usuario iDFace: {usuario_idface} | "
        f"Data: {data_hora.strftime('%d/%m/%Y %H:%M:%S')}"
    )

    return True


def _processar_pendentes(cursor, idface, resultado_sync):
    """Tenta recuperar os eventos que estão pendentes."""
    print("\n=== REPROCESSANDO EVENTOS PENDENTES ===")

    cursor.execute(
        """
        SELECT id_idface
        FROM registros_acesso_pendentes
        ORDER BY id_idface ASC
        """
    )

    pendentes = cursor.fetchall()

    print(
        f"Eventos aguardando processamento: {len(pendentes)}"
    )

    for (id_registro,) in pendentes:

        try:
            registro = _buscar_evento_idface(
                idface,
                id_registro
            )

        except IDFaceError:
            raise

        except Exception as erro:
            cursor.execute(
                """
                UPDATE registros_acesso_pendentes
                SET
                    ultima_tentativa = NOW(),
                    tentativas = tentativas + 1,
                    erro = %s
                WHERE id_idface = %s
                """,
                (str(erro)[:255], id_registro)
            )

            resultado_sync["ignorados"] += 1
            continue

        if registro is None:
            cursor.execute(
                """
                UPDATE registros_acesso_pendentes
                SET
                    ultima_tentativa = NOW(),
                    tentativas = tentativas + 1,
                    erro = 'Evento nao encontrado no iDFace'
                WHERE id_idface = %s
                """,
                (id_registro,)
            )

            resultado_sync["ignorados"] += 1
            continue

        data_hora = _converter_data_hora(
            registro.get("time")
        )

        if data_hora is None:
            _salvar_pendente(
                cursor,
                registro,
                "Horario ainda ausente ou invalido"
            )

            resultado_sync["ignorados"] += 1
            continue

        _salvar_registro(
            cursor,
            registro,
            resultado_sync
        )

    print("Reprocessamento de pendencias concluido.")


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
        # 2. REPROCESSAR EVENTOS PENDENTES
        # =====================================

        _processar_pendentes(
            cursor,
            idface,
            resultado_sync
        )

        conexao.commit()

        # =====================================
        # 3. DESCOBRIR ULTIMO EVENTO CONHECIDO
        # =====================================

        cursor.execute(
            """
            SELECT GREATEST(
                COALESCE(
                    (SELECT MAX(id_idface)
                     FROM registros_acesso),
                    0
                ),
                COALESCE(
                    (SELECT MAX(id_idface)
                     FROM registros_acesso_pendentes),
                    0
                )
            )
            """
        )

        ultimo_id = cursor.fetchone()[0]

        print(
            f"\nUltimo evento conhecido: {ultimo_id}"
        )

        # =====================================
        # 4. BUSCAR REGISTROS EM LOTES DE 50
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
                    "limit": TAMANHO_LOTE,
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
            # 5. PROCESSAR REGISTROS
            # =====================================

            for registro in registros:

                id_registro = _converter_inteiro(
                    registro.get("id")
                )

                if id_registro is None:
                    resultado_sync["ignorados"] += 1
                    continue

                maior_id_lote = max(
                    maior_id_lote,
                    id_registro
                )

                data_hora = _converter_data_hora(
                    registro.get("time")
                )

                if data_hora is None:

                    _salvar_pendente(
                        cursor,
                        registro,
                        "Horario ausente ou invalido"
                    )

                    resultado_sync["ignorados"] += 1

                    print(
                        f"Evento {id_registro} armazenado "
                        f"como pendente."
                    )

                    continue

                _salvar_registro(
                    cursor,
                    registro,
                    resultado_sync
                )

            # =====================================
            # 6. CONFIRMAR LOTE
            # =====================================

            conexao.commit()

            ultimo_id = maior_id_lote

            if len(registros) < TAMANHO_LOTE:
                continuar = False

        # =====================================
        # 7. ATUALIZAR VINCULOS ANTIGOS
        # =====================================

        print("\n=== RECUPERANDO VINCULOS HISTORICOS ===")

        cursor.execute(
            """
            UPDATE registros_acesso ra
            INNER JOIN usuarios_idface_historico uh
                ON uh.id_idface = ra.usuario_idface
            SET ra.id_usuario = uh.id_usuario
            WHERE ra.id_usuario IS NULL
            """
        )

        vinculados = cursor.rowcount

        print(
            f"Registros associados a usuarios: {vinculados}"
        )

        # =====================================
        # 8. CONFIRMAR ALTERACOES FINAIS
        # =====================================

        conexao.commit()

        resultado_sync["sucesso"] = True

        print("\n=== RESULTADO ===")
        print("Novos registros:", resultado_sync["novos"])
        print("Registros atualizados:", resultado_sync["atualizados"])
        print("Registros ignorados:", resultado_sync["ignorados"])
        print("Vinculos historicos recuperados:", vinculados)

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
