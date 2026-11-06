
import re
import unicodedata
import mysql.connector
import config

from idface import IDFaceError


def _normalizar_nome_departamento(nome):
    """Normaliza o nome para comparar PADRÃO sem diferença de acento."""
    return "".join(
        caractere
        for caractere in unicodedata.normalize("NFKD", str(nome).casefold())
        if not unicodedata.combining(caractere)
    ).strip()


def _validar_usuarios_idface(usuarios):
    """
    Valida os registros recebidos do equipamento antes
    de qualquer alteração no MySQL ou no iDFace.
    """

    if not isinstance(usuarios, list):
        raise IDFaceError(
            "A consulta de usuários do iDFace não retornou uma lista."
        )

    ids_encontrados = set()

    for usuario in usuarios:

        if not isinstance(usuario, dict):
            raise IDFaceError(
                "O iDFace retornou um registro de usuário inválido."
            )

        id_idface = usuario.get("id")

        if id_idface is None or isinstance(id_idface, bool):
            raise IDFaceError(
                "O iDFace retornou um usuário sem ID válido."
            )

        try:
            id_idface = int(id_idface)

        except (ValueError, TypeError):
            raise IDFaceError(
                "O iDFace retornou um ID de usuário inválido."
            )

        if id_idface <= 0:
            raise IDFaceError(
                "O iDFace retornou um ID de usuário inválido."
            )

        if id_idface in ids_encontrados:
            raise IDFaceError(
                f"O iDFace retornou o ID {id_idface} mais de uma vez. "
                "A sincronização foi interrompida por segurança."
            )

        ids_encontrados.add(id_idface)


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

            if not isinstance(foto, dict):
                print("Registro de foto inválido recebido do iDFace.")
                continue

            id_idface = foto.get("id")

            if id_idface is None:
                continue

            try:
                id_idface = int(id_idface)

            except (ValueError, TypeError):
                print(
                    "Foto ignorada: o iDFace retornou um ID inválido."
                )
                continue

            fotos_recebidas.add(id_idface)

            usuario = usuarios_por_idface.get(id_idface)

            if not usuario:
                continue

            id_mysql = usuario["id"]

            imagem = foto.get("image")
            timestamp = foto.get("timestamp")

            if imagem and timestamp is not None:

                try:
                    timestamp = int(timestamp)

                except (ValueError, TypeError):
                    print(
                        f"Timestamp inválido na foto de "
                        f"{usuario['nome']}."
                    )
                    continue

                foto_salva = _obter_foto_salva(cursor, id_mysql)

                if (
                    foto_salva is None
                    or timestamp > int(foto_salva[0])
                ):
                    _salvar_foto(
                        cursor,
                        id_mysql,
                        timestamp,
                        imagem
                    )

                    print(
                        f"Foto atualizada no MySQL: "
                        f"{usuario['nome']} | "
                        f"ID MySQL: {id_mysql}"
                    )

                elif int(foto_salva[0]) > timestamp:

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
                    f"Foto restaurada após ausência na consulta: "
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
        "exclusoes_desconhecidos_bloqueadas": 0,
        "desconhecidos_registrados": 0,
        "desconhecidos": [],
        "usuarios_desativados_ausentes": 0,
        "administradores_ausentes": 0,
        "departamentos_verificados": 0,
        "departamentos_com_falha": 0,
        "sucesso": False
    }

    try:
        print("=== SINCRONIZACAO DE USUARIOS ===\n")

        # =====================================
        # 1. CONSULTAR E VALIDAR O IDFACE
        # =====================================

        usuarios_idface = idface.consultar_usuarios()
        privilegios = idface.consultar_privilegios()

        _validar_usuarios_idface(usuarios_idface)

        if not isinstance(privilegios, list):
            raise IDFaceError(
                "Resposta inválida ao consultar privilégios no iDFace."
            )

        if not all(isinstance(item, dict) for item in privilegios):
            raise IDFaceError(
                "O iDFace retornou registros de permissões inválidos."
            )

        ids_equipamento = {
            int(usuario["id"])
            for usuario in usuarios_idface
        }

        # =====================================
        # 2. CONECTAR AO MYSQL
        # =====================================

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
        # 3. CONSULTAR USUÁRIOS DO MYSQL
        # =====================================

        cursor.execute(
            """
            SELECT id, id_idface, nome, categoria, ativo
            FROM usuarios
            WHERE id_idface IS NOT NULL
            """
        )

        registros_mysql = cursor.fetchall()

        usuarios_por_idface = {}

        for registro in registros_mysql:

            id_idface = int(registro[1])

            if id_idface in usuarios_por_idface:
                raise RuntimeError(
                    f"O ID iDFace {id_idface} está vinculado "
                    "a mais de um usuário no MySQL. "
                    "Sincronização interrompida por segurança."
                )

            usuarios_por_idface[id_idface] = {
                "id": registro[0],
                "id_idface": registro[1],
                "nome": registro[2],
                "categoria": registro[3],
                "ativo": registro[4]
            }

        # =====================================
        # 4. VERIFICAR SEGURANÇA DA BASE MYSQL
        # =====================================

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM usuarios
            WHERE ativo = 1
            """
        )

        quantidade_usuarios_ativos = int(cursor.fetchone()[0])

        if quantidade_usuarios_ativos == 0:
            raise RuntimeError(
                "O MySQL não possui usuários ativos. "
                "A sincronização foi interrompida para evitar "
                "alterações indevidas no iDFace."
            )

        print(
            f"Usuários ativos no MySQL: "
            f"{quantidade_usuarios_ativos}"
        )

        # =====================================
        # 5. IDENTIFICAR USUÁRIOS DESCONHECIDOS
        # =====================================

        usuarios_desconhecidos = []

        for usuario in usuarios_idface:

            id_idface = int(usuario["id"])

            if id_idface in usuarios_por_idface:
                continue

            usuario_recuperado = _recuperar_usuario_por_matricula(
                cursor,
                usuario.get("registration")
            )

            if usuario_recuperado is None:

                desconhecido = {
                    "id": id_idface,
                    "nome": usuario.get("name") or "Nome não informado",
                    "matricula": (
                        usuario.get("registration")
                        or "Matrícula não informada"
                    )
                }

                usuarios_desconhecidos.append(desconhecido)

        resultado_sync["desconhecidos"] = usuarios_desconhecidos
        resultado_sync["desconhecidos_registrados"] = len(
            usuarios_desconhecidos
        )

        resultado_sync["exclusoes_desconhecidos_bloqueadas"] = len(
            usuarios_desconhecidos
        )

        if usuarios_desconhecidos:

            print("\n=== USUÁRIOS DESCONHECIDOS IDENTIFICADOS ===")

            for usuario in usuarios_desconhecidos:
                print(
                    f"Nome: {usuario['nome']} | "
                    f"ID iDFace: {usuario['id']} | "
                    f"Matrícula: {usuario['matricula']}"
                )

            print(
                f"\nTotal de desconhecidos registrados: "
                f"{len(usuarios_desconhecidos)}"
            )

            print(
                "Nenhum usuário desconhecido será excluído "
                "automaticamente."
            )

        else:
            print(
                "\nNenhum usuário desconhecido foi encontrado."
            )

        # Contém somente IDs de contas reconhecidas e autorizadas
        # que continuam presentes no equipamento.
        ids_presentes = set()

        # =====================================
        # 6. PROCESSAR USUÁRIOS DO IDFACE
        # =====================================

        for usuario in usuarios_idface:

            id_idface = int(usuario["id"])
            nome_idface = usuario.get("name")

            existente = usuarios_por_idface.get(id_idface)

            # ---------------------------------
            # 6.1. USUÁRIO JÁ VINCULADO AO MYSQL
            # ---------------------------------

            if existente:

                _registrar_idface_historico(
                    cursor,
                    existente["id"],
                    id_idface
                )

                if not existente["ativo"]:

                    # Contas administrativas não são removidas
                    # automaticamente pela sincronização.
                    if existente["categoria"] == "administrador":

                        resultado_sync["ignorados"] += 1

                        print(
                            f"Conta administrativa inativa preservada: "
                            f"{existente['nome']} | "
                            f"ID iDFace: {id_idface}"
                        )

                        continue

                    try:
                        idface.excluir_usuario(id_idface)

                        resultado_sync["excluidos"] += 1

                        print(
                            f"Conta inativa removida do iDFace: "
                            f"{existente['nome']} | "
                            f"ID: {id_idface}"
                        )

                    except IDFaceError as erro:
                        resultado_sync["ignorados"] += 1

                        print(
                            f"Não foi possível remover a conta "
                            f"inativa {id_idface}: {erro}"
                        )

                    continue

                ids_presentes.add(id_idface)

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

            # ---------------------------------
            # 6.2. RECUPERAR VÍNCULO PELA MATRÍCULA
            # ---------------------------------

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

                    # Contas administrativas inativas não podem
                    # ser removidas automaticamente do equipamento.
                    if categoria_mysql == "administrador":

                        resultado_sync["ignorados"] += 1

                        print(
                            f"Conta administrativa inativa identificada "
                            f"pela matrícula e preservada: {nome_mysql} | "
                            f"ID iDFace: {id_idface}"
                        )

                        continue

                    try:
                        idface.excluir_usuario(id_idface)

                        resultado_sync["excluidos"] += 1

                        print(
                            f"Conta inativa identificada pela matrícula "
                            f"e removida: {nome_mysql}"
                        )

                    except IDFaceError as erro:
                        resultado_sync["ignorados"] += 1

                        print(
                            f"Falha ao remover conta inativa "
                            f"{id_idface}: {erro}"
                        )

                    continue

                # A verificação usa a lista completa do equipamento,
                # evitando depender da ordem dos registros recebidos.
                if (
                    id_anterior is not None
                    and int(id_anterior) != id_idface
                    and int(id_anterior) in ids_equipamento
                ):
                    resultado_sync["ignorados"] += 1

                    print(
                        f"Possível conta duplicada no iDFace: "
                        f"{nome_mysql} | "
                        f"ID anterior: {id_anterior} | "
                        f"ID encontrado: {id_idface}. "
                        f"Vínculo não alterado."
                    )

                    continue

                if id_anterior is not None:
                    _registrar_idface_historico(
                        cursor,
                        id_mysql,
                        id_anterior
                    )

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

            # ---------------------------------
            # 6.3. USUÁRIO DESCONHECIDO
            # ---------------------------------

            # Usuários desconhecidos são somente registrados.
            # Nenhuma exclusão automática é realizada.
            resultado_sync["ignorados"] += 1

            print(
                f"Usuário desconhecido preservado no iDFace: "
                f"{nome_idface or 'Nome não informado'} | "
                f"ID: {id_idface} | "
                f"Matrícula: "
                f"{usuario.get('registration') or 'Não informada'}"
            )

        # =====================================
        # 7. IDENTIFICAR USUÁRIOS AUSENTES
        # =====================================

        print("\n=== VERIFICACAO DE USUARIOS AUSENTES ===")

        cursor.execute(
            """
            SELECT id, id_idface, nome, categoria
            FROM usuarios
            WHERE ativo = 1
              AND id_idface IS NOT NULL
            """
        )

        usuarios_vinculados_ativos = cursor.fetchall()

        for registro in usuarios_vinculados_ativos:

            id_mysql = registro[0]
            id_idface = int(registro[1])
            nome = registro[2]
            categoria = registro[3]

            if id_idface in ids_presentes:
                continue

            if categoria == "administrador":

                # Administradores e MASTER permanecem ativos no MySQL.
                # A divergência é registrada para análise administrativa.
                resultado_sync["administradores_ausentes"] += 1

                print(
                    f"ATENÇÃO: administrador ausente no iDFace: "
                    f"{nome} | MySQL: {id_mysql} | "
                    f"ID iDFace: {id_idface}. "
                    f"Conta mantida ativa no MySQL."
                )

                continue

            cursor.execute(
                """
                UPDATE usuarios
                SET ativo = 0
                WHERE id = %s
                  AND ativo = 1
                  AND categoria = 'membro'
                """,
                (id_mysql,)
            )

            if cursor.rowcount == 1:

                resultado_sync[
                    "usuarios_desativados_ausentes"
                ] += 1

                print(
                    f"Usuário ausente no iDFace desativado no MySQL: "
                    f"{nome} | MySQL: {id_mysql} | "
                    f"ID iDFace: {id_idface}. "
                    f"Cadastro e histórico preservados."
                )

        # =====================================
        # 8. CONFIRMAR ALTERAÇÕES NO MYSQL
        # =====================================

        conexao.commit()

        # =====================================
        # 9. RECARREGAR USUÁRIOS ATIVOS
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

        # Mantém somente usuários reconhecidos e presentes no equipamento.
        usuarios_presentes = [
            usuario
            for usuario in usuarios_ativos
            if int(usuario["id_idface"]) in ids_presentes
        ]

        # =====================================
        # 10. CORRIGIR PERMISSÕES DO IDFACE
        # =====================================

        privilegios = idface.consultar_privilegios()

        if not isinstance(privilegios, list):
            raise IDFaceError(
                "Resposta inválida ao consultar privilégios no iDFace."
            )

        administradores_idface = set()

        for privilegio in privilegios:

            if not isinstance(privilegio, dict):
                raise IDFaceError(
                    "O iDFace retornou um registro de permissão inválido."
                )

            if privilegio.get("role") is None:
                continue

            try:
                role = int(privilegio["role"])

                if role == 1 and privilegio.get("user_id") is not None:
                    administradores_idface.add(
                        int(privilegio["user_id"])
                    )

            except (ValueError, TypeError):
                raise IDFaceError(
                    "O iDFace retornou dados inválidos de permissões."
                )

        for usuario in usuarios_presentes:

            id_idface = int(usuario["id_idface"])

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
        # 11. SINCRONIZAR DEPARTAMENTO PADRÃO
        # =====================================

        print("\n=== SINCRONIZACAO DE DEPARTAMENTOS ===")

        try:
            departamentos = idface.consultar_departamentos()
            vinculos_departamentos = (
                idface.consultar_vinculos_departamentos()
            )

            if not isinstance(departamentos, list) or not all(
                isinstance(item, dict) for item in departamentos
            ):
                raise IDFaceError(
                    "O iDFace retornou uma lista de departamentos inválida."
                )

            if not isinstance(vinculos_departamentos, list) or not all(
                isinstance(item, dict) for item in vinculos_departamentos
            ):
                raise IDFaceError(
                    "O iDFace retornou uma lista de vínculos "
                    "de departamentos inválida."
                )

            grupos_padrao = [
                grupo
                for grupo in departamentos
                if _normalizar_nome_departamento(
                    grupo.get("name", "")
                ) == "padrao"
            ]

            if len(grupos_padrao) != 1:
                raise IDFaceError(
                    "Era esperado encontrar exatamente um departamento "
                    "chamado PADRÃO no iDFace, mas foram encontrados "
                    f"{len(grupos_padrao)}."
                )

            id_departamento_padrao = int(grupos_padrao[0]["id"])

            usuarios_com_departamento = set()

            for vinculo in vinculos_departamentos:
                try:
                    id_usuario_vinculo = int(vinculo["user_id"])
                    id_departamento_vinculo = int(vinculo["group_id"])
                except (KeyError, ValueError, TypeError):
                    raise IDFaceError(
                        "O iDFace retornou um vínculo de departamento "
                        "com identificadores inválidos."
                    )

                if id_departamento_vinculo == id_departamento_padrao:
                    usuarios_com_departamento.add(id_usuario_vinculo)

            for usuario in usuarios_presentes:

                id_idface = int(usuario["id_idface"])

                if id_idface in usuarios_com_departamento:
                    resultado_sync["departamentos_verificados"] += 1
                    continue

                try:
                    idface.associar_departamento_padrao(id_idface)

                    usuarios_com_departamento.add(id_idface)

                    resultado_sync["departamentos_verificados"] += 1

                    print(
                        f"Usuário associado ao departamento PADRÃO: "
                        f"{usuario['nome']} | ID iDFace: {id_idface}"
                    )

                except IDFaceError as erro:
                    resultado_sync["departamentos_com_falha"] += 1

                    print(
                        f"Falha ao associar departamento PADRÃO: "
                        f"{usuario['nome']} | ID iDFace: {id_idface} | "
                        f"Erro: {erro}"
                    )

                except Exception as erro:
                    resultado_sync["departamentos_com_falha"] += 1

                    print(
                        f"Erro inesperado ao sincronizar departamento de "
                        f"{usuario['nome']} | ID iDFace: {id_idface} | "
                        f"Erro: {erro}"
                    )

        except (IDFaceError, KeyError, ValueError, TypeError) as erro:

            quantidade_afetada = (
                len(usuarios_presentes)
                - resultado_sync["departamentos_verificados"]
                - resultado_sync["departamentos_com_falha"]
            )

            resultado_sync["departamentos_com_falha"] += max(
                quantidade_afetada,
                0
            )

            print(
                "Não foi possível consultar ou identificar o "
                f"departamento PADRÃO: {erro}"
            )

        # =====================================
        # 12. SINCRONIZAR FOTOS FACIAIS
        # =====================================

        contador_fotos = [0]

        _restaurar_fotos(
            idface,
            cursor,
            usuarios_presentes,
            contador_fotos
        )

        resultado_sync["fotos_restauradas"] = contador_fotos[0]

        conexao.commit()

        resultado_sync["sucesso"] = True

        # =====================================
        # 13. RESULTADO
        # =====================================

        print("\n=== RESULTADO DA SINCRONIZACAO ===")
        print("Novos usuários:", resultado_sync["novos"])
        print("Usuários atualizados:", resultado_sync["atualizados"])
        print("Contas restauradas:", resultado_sync["restaurados"])
        print("Fotos restauradas:", resultado_sync["fotos_restauradas"])
        print("Contas removidas:", resultado_sync["excluidos"])
        print("Usuários ignorados:", resultado_sync["ignorados"])

        print(
            "Usuários desconhecidos registrados:",
            resultado_sync["desconhecidos_registrados"]
        )

        print(
            "Usuários ausentes desativados no MySQL:",
            resultado_sync["usuarios_desativados_ausentes"]
        )

        print(
            "Administradores ausentes preservados:",
            resultado_sync["administradores_ausentes"]
        )

        print(
            "Departamentos PADRÃO verificados:",
            resultado_sync["departamentos_verificados"]
        )

        print(
            "Falhas na sincronização de departamentos:",
            resultado_sync["departamentos_com_falha"]
        )

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
