import re
import mysql.connector
import config

from idface import IDFaceError


def _registrar_idface_historico(cursor, id_usuario, id_idface):
    """
    Registra um ID do iDFace no histórico do usuário.

    Um mesmo ID do iDFace não pode pertencer a dois usuários diferentes.
    IDs antigos nunca são removidos do histórico.
    """

    if id_idface is None:
        return False

    id_usuario = int(id_usuario)
    id_idface = int(id_idface)

    cursor.execute(
        """
        SELECT id_usuario
        FROM usuarios_idface_historico
        WHERE id_idface = %s
        """,
        (id_idface,)
    )

    registro = cursor.fetchone()

    if registro:
        if int(registro[0]) != id_usuario:
            raise ValueError(
                f"O ID iDFace {id_idface} já está associado "
                f"ao usuário MySQL {registro[0]}, não ao usuário "
                f"{id_usuario}."
            )

        return False

    cursor.execute(
        """
        INSERT INTO usuarios_idface_historico
            (id_usuario, id_idface)
        VALUES (%s, %s)
        """,
        (id_usuario, id_idface)
    )

    return True


def _obter_foto_salva(cursor, id_usuario):
    cursor.execute(
        """
        SELECT timestamp_foto, imagem
        FROM fotos_faciais
        WHERE id_usuario = %s
        """,
        (id_usuario,)
    )

    return cursor.fetchone()


def _salvar_foto(cursor, id_usuario, timestamp, imagem):
    foto_existente = _obter_foto_salva(cursor, id_usuario)

    if foto_existente:
        timestamp_salvo, imagem_salva = foto_existente

        if int(timestamp) <= int(timestamp_salvo):
            return False

        cursor.execute(
            """
            UPDATE fotos_faciais
            SET timestamp_foto = %s,
                imagem = %s
            WHERE id_usuario = %s
            """,
            (timestamp, imagem, id_usuario)
        )

    else:
        cursor.execute(
            """
            INSERT INTO fotos_faciais
                (id_usuario, timestamp_foto, imagem)
            VALUES (%s, %s, %s)
            """,
            (id_usuario, timestamp, imagem)
        )

    return True


def _recuperar_usuario_por_matricula(cursor, registro):
    """
    Recupera a associação caso o processo tenha sido interrompido
    depois de criar o usuário no iDFace, mas antes de atualizar o MySQL.
    """

    if not registro:
        return None

    correspondencia = re.fullmatch(r"WBZ(\d{6})", str(registro))

    if not correspondencia:
        return None

    id_mysql = int(correspondencia.group(1))

    cursor.execute(
        """
        SELECT id, nome, categoria, ativo, id_idface
        FROM usuarios
        WHERE id = %s
        """,
        (id_mysql,)
    )

    return cursor.fetchone()


def _restaurar_fotos(idface, cursor, usuarios_ativos, fotos_restauradas):
    """
    Mantém as fotos do MySQL e do iDFace sincronizadas.
    A versão com timestamp mais recente é preservada.
    """

    usuarios_por_idface = {
        int(usuario["id_idface"]): usuario
        for usuario in usuarios_ativos
        if usuario["id_idface"] is not None
    }

    ids_idface = list(usuarios_por_idface.keys())

    if not ids_idface:
        return

    print("\n=== SINCRONIZACAO DE FOTOS FACIAIS ===")

    for inicio in range(0, len(ids_idface), 100):

        lote = ids_idface[inicio:inicio + 100]

        try:
            fotos_equipamento = idface.consultar_fotos_usuarios(lote)

            if not isinstance(fotos_equipamento, list):
                print(
                    "Resposta inválida ao consultar fotos do iDFace."
                )
                continue

        except IDFaceError as erro:
            print(
                "Não foi possível consultar um lote de fotos:",
                erro
            )
            continue

        fotos_recebidas = set()

        for foto in fotos_equipamento:

            id_idface = foto.get("id")

            if id_idface is None:
                continue

            id_idface = int(id_idface)
            fotos_recebidas.add(id_idface)

            usuario = usuarios_por_idface.get(id_idface)

            if not usuario:
                continue

            id_mysql = usuario["id"]

            imagem = foto.get("image")
            timestamp = foto.get("timestamp")

            if imagem and timestamp is not None:

                foto_salva = _obter_foto_salva(cursor, id_mysql)

                if (
                    foto_salva is None
                    or int(timestamp) > int(foto_salva[0])
                ):
                    _salvar_foto(
                        cursor,
                        id_mysql,
                        int(timestamp),
                        imagem
                    )

                    print(
                        f"Foto atualizada no MySQL: "
                        f"{usuario['nome']} | "
                        f"ID MySQL: {id_mysql}"
                    )

                elif int(foto_salva[0]) > int(timestamp):

                    try:
                        idface.restaurar_foto_usuario(
                            id_idface,
                            foto_salva[0],
                            foto_salva[1]
                        )

                        fotos_restauradas[0] += 1

                        print(
                            f"Foto restaurada no iDFace: "
                            f"{usuario['nome']} | "
                            f"ID iDFace: {id_idface}"
                        )

                    except IDFaceError as erro:
                        print(
                            f"Falha ao restaurar foto de "
                            f"{usuario['nome']}: {erro}"
                        )

            else:
                # O equipamento informou erro ou não possui foto.
                foto_salva = _obter_foto_salva(cursor, id_mysql)

                if foto_salva:
                    try:
                        idface.restaurar_foto_usuario(
                            id_idface,
                            foto_salva[0],
                            foto_salva[1]
                        )

                        fotos_restauradas[0] += 1

                        print(
                            f"Foto recuperada: {usuario['nome']} | "
                            f"ID iDFace: {id_idface}"
                        )

                    except IDFaceError as erro:
                        print(
                            f"Falha ao recuperar foto de "
                            f"{usuario['nome']}: {erro}"
                        )

        # Se algum usuário não apareceu na resposta, tentamos
        # recuperar sua foto usando a cópia armazenada no MySQL.
        for id_idface in lote:

            if id_idface in fotos_recebidas:
                continue

            usuario = usuarios_por_idface[id_idface]
            foto_salva = _obter_foto_salva(cursor, usuario["id"])

            if not foto_salva:
                continue

            try:
                idface.restaurar_foto_usuario(
                    id_idface,
                    foto_salva[0],
                    foto_salva[1]
                )

                fotos_restauradas[0] += 1

                print(
                    f"Foto restaurada após ausência no equipamento: "
                    f"{usuario['nome']}"
                )

            except IDFaceError as erro:
                print(
                    f"Falha ao restaurar foto de "
                    f"{usuario['nome']}: {erro}"
                )


def sincronizar_usuarios(idface):
    conexao = None
    cursor = None

    resultado_sync = {
        "novos": 0,
        "atualizados": 0,
        "restaurados": 0,
        "fotos_restauradas": 0,
        "excluidos": 0,
        "ignorados": 0,
        "sucesso": False
    }

    try:
        print("=== SINCRONIZACAO DE USUARIOS ===\n")

        usuarios_idface = idface.consultar_usuarios()
        privilegios = idface.consultar_privilegios()

        if not isinstance(usuarios_idface, list):
            raise ValueError(
                "Resposta inválida ao consultar usuários no iDFace."
            )

        if not isinstance(privilegios, list):
            raise ValueError(
                "Resposta inválida ao consultar privilégios no iDFace."
            )

        conexao = mysql.connector.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USUARIO,
            password=config.MYSQL_SENHA,
            database=config.MYSQL_BANCO
        )

        cursor = conexao.cursor()

        print(
            f"Usuários encontrados no iDFace: "
            f"{len(usuarios_idface)}"
        )

        # =====================================
        # 1. CONSULTAR USUÁRIOS DO MYSQL
        # =====================================

        cursor.execute(
            """
            SELECT id, id_idface, nome, categoria, ativo
            FROM usuarios
            WHERE id_idface IS NOT NULL
            """
        )

        registros_mysql = cursor.fetchall()

        usuarios_por_idface = {
            int(registro[1]): {
                "id": registro[0],
                "id_idface": registro[1],
                "nome": registro[2],
                "categoria": registro[3],
                "ativo": registro[4]
            }
            for registro in registros_mysql
        }

        # Contém somente IDs de contas autorizadas que continuam
        # presentes no equipamento.
        ids_presentes = set()

        # =====================================
        # 2. PROCESSAR USUÁRIOS DO IDFACE
        # =====================================

        for usuario in usuarios_idface:

            id_idface = usuario.get("id")
            nome_idface = usuario.get("name")

            if id_idface is None:
                resultado_sync["ignorados"] += 1
                continue

            id_idface = int(id_idface)

            existente = usuarios_por_idface.get(id_idface)

            # -------------------------------------------------
            # 2.1. USUÁRIO JÁ VINCULADO AO MYSQL
            # -------------------------------------------------

            if existente:

                # Registra ou confirma o ID no histórico.
                _registrar_idface_historico(
                    cursor,
                    existente["id"],
                    id_idface
                )

                if not existente["ativo"]:
                    # A conta foi desativada pelo site.
                    # Remove do equipamento, mas preserva o backup
                    # facial e os registros históricos no MySQL.

                    try:
                        idface.excluir_usuario(id_idface)

                        resultado_sync["excluidos"] += 1

                        print(
                            f"Conta inativa removida do iDFace: "
                            f"{existente['nome']}"
                        )

                    except IDFaceError as erro:
                        print(
                            f"Não foi possível remover a conta "
                            f"inativa {id_idface}: {erro}"
                        )

                    continue

                # O ID é considerado presente mesmo quando o
                # equipamento não retorna o nome do usuário.
                ids_presentes.add(id_idface)

                # O MySQL é a referência para o nome.
                if nome_idface and nome_idface != existente["nome"]:

                    try:
                        idface.editar_usuario(
                            id_idface,
                            existente["nome"]
                        )

                        resultado_sync["atualizados"] += 1

                        print(
                            f"Nome atualizado no iDFace: "
                            f"{existente['nome']} | "
                            f"ID: {id_idface}"
                        )

                    except IDFaceError as erro:
                        print(
                            f"Falha ao atualizar nome de "
                            f"{existente['nome']}: {erro}"
                        )

                continue

            # -------------------------------------------------
            # 2.2. TENTAR RECUPERAR O VÍNCULO PELA MATRÍCULA WBZ
            # -------------------------------------------------

            usuario_recuperado = _recuperar_usuario_por_matricula(
                cursor,
                usuario.get("registration")
            )

            if usuario_recuperado:

                (
                    id_mysql,
                    nome_mysql,
                    categoria_mysql,
                    ativo_mysql,
                    id_anterior
                ) = usuario_recuperado

                if not ativo_mysql:
                    # A matrícula pertence a uma conta desativada.
                    # O cadastro no equipamento não é autorizado.

                    try:
                        idface.excluir_usuario(id_idface)

                        resultado_sync["excluidos"] += 1

                        print(
                            f"Conta inativa identificada pela matrícula "
                            f"e removida: {nome_mysql}"
                        )

                    except IDFaceError as erro:
                        print(
                            f"Falha ao remover conta inativa "
                            f"{id_idface}: {erro}"
                        )

                    continue

                # Não permite que uma matrícula gere duas contas
                # simultâneas para o mesmo usuário.
                if (
                    id_anterior is not None
                    and int(id_anterior) != id_idface
                    and int(id_anterior) in ids_presentes
                ):
                    resultado_sync["ignorados"] += 1

                    print(
                        f"Possível conta duplicada no iDFace: "
                        f"{nome_mysql} | "
                        f"ID atual: {id_anterior} | "
                        f"ID encontrado: {id_idface}. "
                        f"Vínculo não alterado."
                    )

                    continue

                # Registra o ID anterior, caso ainda não esteja
                # presente no histórico.
                if id_anterior is not None:
                    _registrar_idface_historico(
                        cursor,
                        id_mysql,
                        id_anterior
                    )

                # Registra o novo ID antes de atualizar o vínculo atual.
                _registrar_idface_historico(
                    cursor,
                    id_mysql,
                    id_idface
                )

                cursor.execute(
                    """
                    UPDATE usuarios
                    SET id_idface = %s
                    WHERE id = %s
                      AND ativo = 1
                    """,
                    (id_idface, id_mysql)
                )

                if cursor.rowcount != 1:
                    raise ValueError(
                        f"Não foi possível atualizar o vínculo "
                        f"do usuário MySQL {id_mysql}."
                    )

                usuarios_por_idface[id_idface] = {
                    "id": id_mysql,
                    "id_idface": id_idface,
                    "nome": nome_mysql,
                    "categoria": categoria_mysql,
                    "ativo": ativo_mysql
                }

                ids_presentes.add(id_idface)

                resultado_sync["restaurados"] += 1

                print(
                    f"Vínculo recuperado pela matrícula: "
                    f"{nome_mysql} | "
                    f"MySQL: {id_mysql} | "
                    f"iDFace: {id_idface}"
                )

                # Corrige o nome do equipamento conforme o MySQL.
                if nome_idface and nome_idface != nome_mysql:

                    try:
                        idface.editar_usuario(
                            id_idface,
                            nome_mysql
                        )

                    except IDFaceError as erro:
                        print(
                            f"Falha ao atualizar nome de "
                            f"{nome_mysql}: {erro}"
                        )

                continue

            # -------------------------------------------------
            # 2.3. USUÁRIO DESCONHECIDO: REMOVER DO IDFACE
            # -------------------------------------------------

            # Não cria registros no MySQL a partir do equipamento.
            # Somente usuários cadastrados pelo site são autorizados.

            try:
                idface.excluir_usuario(id_idface)

                resultado_sync["excluidos"] += 1

                print(
                    f"Cadastro desconhecido removido do iDFace: "
                    f"{nome_idface or 'Nome não informado'} | "
                    f"ID: {id_idface}"
                )

            except IDFaceError as erro:
                resultado_sync["ignorados"] += 1

                print(
                    f"Não foi possível remover o cadastro "
                    f"desconhecido {id_idface}: {erro}"
                )

        conexao.commit()

        # =====================================
        # 3. RECARREGAR USUÁRIOS ATIVOS
        # =====================================

        cursor.execute(
            """
            SELECT id, id_idface, nome, categoria
            FROM usuarios
            WHERE ativo = 1
            """
        )

        usuarios_ativos = [
            {
                "id": registro[0],
                "id_idface": registro[1],
                "nome": registro[2],
                "categoria": registro[3]
            }
            for registro in cursor.fetchall()
        ]

        # =====================================
        # 4. RECRIAR CONTAS AUSENTES NO IDFACE
        # =====================================

        for usuario in usuarios_ativos:

            id_mysql = usuario["id"]
            id_anterior = usuario["id_idface"]

            if id_anterior is None:
                continue

            if int(id_anterior) in ids_presentes:
                continue

            print(
                f"\nConta ativa ausente no iDFace: "
                f"{usuario['nome']}"
            )

            novo_id_idface = None

            try:
                novo_id_idface = idface.cadastrar_usuario(
                    id_mysql,
                    usuario["nome"]
                )

                # Se o cadastro for administrativo, concede o papel
                # de administrador no equipamento.
                # ADM e MASTER usam o mesmo papel no iDFace.
                if usuario["categoria"] == "administrador":
                    idface.definir_administrador(
                        novo_id_idface,
                        True
                    )

                # Registra o novo ID no histórico.
                _registrar_idface_historico(
                    cursor,
                    id_mysql,
                    novo_id_idface
                )

                # Atualiza o vínculo atual no MySQL.
                cursor.execute(
                    """
                    UPDATE usuarios
                    SET id_idface = %s
                    WHERE id = %s
                      AND ativo = 1
                    """,
                    (novo_id_idface, id_mysql)
                )

                if cursor.rowcount != 1:
                    raise ValueError(
                        f"Não foi possível atualizar o vínculo "
                        f"do usuário {id_mysql}."
                    )

                conexao.commit()

                usuario["id_idface"] = novo_id_idface

                ids_presentes.add(int(novo_id_idface))

                resultado_sync["restaurados"] += 1

                print(
                    f"Conta recriada: {usuario['nome']} | "
                    f"MySQL: {id_mysql} | "
                    f"Novo iDFace: {novo_id_idface}"
                )

            except Exception as erro:

                if conexao and conexao.is_connected():
                    conexao.rollback()

                print(
                    f"Falha ao recriar {usuario['nome']}: {erro}"
                )

                # Se a criação ocorreu, mas alguma etapa posterior
                # falhou, tenta remover a conta incompleta.
                if novo_id_idface is not None:
                    try:
                        cursor.execute(
                            """
                            SELECT id_idface
                            FROM usuarios
                            WHERE id = %s
                            """,
                            (id_mysql,)
                        )

                        vinculo_atual = cursor.fetchone()

                        if (
                            vinculo_atual
                            and vinculo_atual[0] != novo_id_idface
                        ):
                            idface.excluir_usuario(novo_id_idface)

                    except Exception as erro_compensacao:
                        print(
                            "ATENÇÃO: não foi possível remover "
                            "a conta incompleta:",
                            erro_compensacao
                        )

        # =====================================
        # 5. RECARREGAR VÍNCULOS ATIVOS
        # =====================================

        cursor.execute(
            """
            SELECT id, id_idface, nome, categoria
            FROM usuarios
            WHERE ativo = 1
              AND id_idface IS NOT NULL
            """
        )

        usuarios_ativos = [
            {
                "id": registro[0],
                "id_idface": registro[1],
                "nome": registro[2],
                "categoria": registro[3]
            }
            for registro in cursor.fetchall()
        ]

        # =====================================
        # 6. CORRIGIR PERMISSÕES DO IDFACE
        # =====================================

        privilegios = idface.consultar_privilegios()

        if not isinstance(privilegios, list):
            raise ValueError(
                "Resposta inválida ao consultar privilégios no iDFace."
            )

        administradores_idface = {
            int(privilegio["user_id"])
            for privilegio in privilegios
            if int(privilegio.get("role", 0)) == 1
            and privilegio.get("user_id") is not None
        }

        # O MySQL é a referência para a permissão administrativa.
        for usuario in usuarios_ativos:

            id_idface = int(usuario["id_idface"])

            if id_idface not in ids_presentes:
                continue

            deve_ser_administrador = (
                usuario["categoria"] == "administrador"
            )

            possui_administrador = (
                id_idface in administradores_idface
            )

            if deve_ser_administrador != possui_administrador:

                idface.definir_administrador(
                    id_idface,
                    deve_ser_administrador
                )

                print(
                    f"Privilégio corrigido: {usuario['nome']} | "
                    f"Administrador: {deve_ser_administrador}"
                )

        # =====================================
        # 7. SINCRONIZAR FOTOS FACIAIS
        # =====================================

        contador_fotos = [0]

        _restaurar_fotos(
            idface,
            cursor,
            usuarios_ativos,
            contador_fotos
        )

        resultado_sync["fotos_restauradas"] = contador_fotos[0]

        conexao.commit()

        resultado_sync["sucesso"] = True

        # =====================================
        # 8. RESULTADO
        # =====================================

        print("\n=== RESULTADO DA SINCRONIZACAO ===")
        print("Novos usuários:", resultado_sync["novos"])
        print("Usuários atualizados:", resultado_sync["atualizados"])
        print("Contas restauradas:", resultado_sync["restaurados"])
        print("Fotos restauradas:", resultado_sync["fotos_restauradas"])
        print("Contas removidas:", resultado_sync["excluidos"])
        print("Usuários ignorados:", resultado_sync["ignorados"])
        print("Sincronização concluída!")

    except IDFaceError as erro:

        if conexao and conexao.is_connected():
            conexao.rollback()

        print("\nErro na comunicação com iDFace:")
        print(erro)

    except mysql.connector.Error as erro:

        if conexao and conexao.is_connected():
            conexao.rollback()

        print("\nErro no MySQL:")
        print(erro)

    except Exception as erro:

        if conexao and conexao.is_connected():
            conexao.rollback()

        print("\nErro inesperado na sincronização:")
        print(erro)

    finally:

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
        print("Erro ao executar sincronização:", erro)