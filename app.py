from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from werkzeug.security import check_password_hash, generate_password_hash
from threading import Thread, Lock
from datetime import timedelta
import os
import time
import math

from idface import IDFaceClient, IDFaceError
from servidor import iniciar_servidor
import config


app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY
print("### WICKEDBOTZ APP.PY REVISADO CARREGADO ###", flush=True)

# =====================================
# CONFIGURACOES DE SEGURANCA
# =====================================

DEBUG = os.getenv("FLASK_DEBUG", "false").lower() in (
    "1",
    "true",
    "yes",
    "on"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8)
)

LIMITE_TENTATIVAS_LOGIN = 5
JANELA_TENTATIVAS_SEGUNDOS = 15 * 60
TEMPO_BLOQUEIO_SEGUNDOS = 15 * 60

_tentativas_login = {}
_lock_tentativas_login = Lock()


def verificar_bloqueio_login(ip):
    agora = time.monotonic()

    with _lock_tentativas_login:
        estado = _tentativas_login.get(ip)

        if not estado:
            return 0

        bloqueado_ate = estado.get("bloqueado_ate", 0)

        if bloqueado_ate > agora:
            return math.ceil(bloqueado_ate - agora)

        tentativas = [
            horario
            for horario in estado.get("tentativas", [])
            if agora - horario < JANELA_TENTATIVAS_SEGUNDOS
        ]

        estado["tentativas"] = tentativas

        if not tentativas:
            _tentativas_login.pop(ip, None)

        return 0


def registrar_falha_login(ip):
    agora = time.monotonic()

    with _lock_tentativas_login:
        estado = _tentativas_login.setdefault(
            ip,
            {
                "tentativas": [],
                "bloqueado_ate": 0
            }
        )

        estado["tentativas"] = [
            horario
            for horario in estado["tentativas"]
            if agora - horario < JANELA_TENTATIVAS_SEGUNDOS
        ]

        estado["tentativas"].append(agora)

        if len(estado["tentativas"]) >= LIMITE_TENTATIVAS_LOGIN:
            estado["bloqueado_ate"] = (
                agora + TEMPO_BLOQUEIO_SEGUNDOS
            )

            return TEMPO_BLOQUEIO_SEGUNDOS

        return 0


def limpar_tentativas_login(ip):
    with _lock_tentativas_login:
        _tentativas_login.pop(ip, None)


# =====================================
# CONEXAO COM O BANCO DE DADOS
# =====================================

def conectar_banco():
    return mysql.connector.connect(
        host=config.MYSQL_HOST,
        port=config.MYSQL_PORT,
        user=config.MYSQL_USUARIO,
        password=config.MYSQL_SENHA,
        database=config.MYSQL_BANCO
    )


# =====================================
# AUTENTICACAO
# =====================================

def administrador_logado():
    """Indica se existe uma sessão administrativa validada."""
    return "admin_id" in session


def perfil_logado():
    """Retorna o perfil carregado do MySQL na requisição atual."""
    return session.get("admin_perfil", "administrador")


def master_logado():
    """MASTER é um perfil do painel, nunca um papel separado no iDFace."""
    return administrador_logado() and perfil_logado() == "master"


@app.before_request
def diagnosticar_requisicao_exclusao_administrador():
    """Registra a chegada da requisição mesmo se ela terminar em 404/405."""
    if request.path.startswith("/administradores/excluir/"):
        print(
            f"[HTTP EXCLUSAO ADM] método={request.method} "
            f"caminho={request.path} endpoint={request.endpoint}",
            flush=True
        )
    return None


@app.before_request
def validar_sessao_administrativa():
    """
    Revalida a sessão no MySQL em toda requisição autenticada.

    A tabela administradores define ADM/MASTER. A tabela usuarios
    confirma que a conta continua ativa e na categoria administrador.
    Assim, uma sessão antiga não mantém privilégios após desativação,
    rebaixamento ou exclusão da conta.
    """
    if request.endpoint in ("login", "static", "logout"):
        return None

    id_administrador = session.get("admin_id")
    if id_administrador is None:
        return None

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                a.id,
                a.id_usuario,
                a.nome,
                a.perfil
            FROM administradores a
            INNER JOIN usuarios u ON u.id = a.id_usuario
            WHERE a.id = %s
              AND a.ativo = TRUE
              AND u.ativo = TRUE
              AND u.categoria = 'administrador'
            LIMIT 1
            """,
            (id_administrador,)
        )
        administrador = cursor.fetchone()

        if not administrador:
            session.clear()
            print(
                "Sessão encerrada: conta administrativa inexistente, "
                "inativa ou sem categoria administrativa.",
                flush=True
            )
            return redirect(url_for("login"))

        # O perfil da sessão é sempre atualizado com o valor atual do banco.
        session["admin_id"] = administrador["id"]
        session["admin_usuario_id"] = administrador["id_usuario"]
        session["admin_nome"] = administrador["nome"]
        session["admin_perfil"] = (
            administrador["perfil"] or "administrador"
        )

    except mysql.connector.Error as erro:
        print(
            f"Falha ao revalidar sessão administrativa: {erro}",
            flush=True
        )
        # Falha fechada: não autoriza uma operação com perfil não validado.
        return (
            "Não foi possível validar sua sessão no banco de dados. "
            "Tente novamente em alguns instantes.",
            503
        )

    finally:
        if cursor:
            cursor.close()
        if conexao and conexao.is_connected():
            conexao.close()


def bloquear_se_nao_master():
    if not administrador_logado():
        return redirect(url_for("login"))

    if not master_logado():
        print("Acesso negado: operação exclusiva para MASTER.")
        return redirect(url_for("painel"))

    return None


# =====================================
# PAGINA DE LOGIN
# =====================================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        ip = request.remote_addr or "IP_DESCONHECIDO"

        tempo_restante = verificar_bloqueio_login(ip)

        if tempo_restante > 0:
            minutos = math.ceil(tempo_restante / 60)

            return render_template(
                "login.html",
                erro=(
                    "Muitas tentativas de login. "
                    f"Tente novamente em aproximadamente {minutos} minuto(s)."
                )
            )

        usuario = request.form.get("usuario", "").strip()
        senha = request.form.get("senha", "")

        conexao = None
        cursor = None

        try:
            conexao = conectar_banco()
            cursor = conexao.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT
                    a.id,
                    a.id_usuario,
                    a.nome,
                    a.usuario,
                    a.senha_hash,
                    a.perfil
                FROM administradores a
                INNER JOIN usuarios u
                    ON u.id = a.id_usuario
                WHERE a.usuario = %s
                  AND a.ativo = TRUE
                  AND u.ativo = TRUE
                  AND u.categoria = 'administrador'
                LIMIT 1
                """,
                (usuario,)
            )

            administrador = cursor.fetchone()

            if administrador and check_password_hash(
                administrador["senha_hash"], senha
            ):
                limpar_tentativas_login(ip)

                session.clear()
                session.permanent = True
                session["admin_id"] = administrador["id"]
                session["admin_usuario_id"] = administrador["id_usuario"]
                session["admin_nome"] = administrador["nome"]
                session["admin_perfil"] = (
                    administrador["perfil"] or "administrador"
                )

                return redirect(url_for("painel"))

            tempo_bloqueio = registrar_falha_login(ip)

            if tempo_bloqueio > 0:
                return render_template(
                    "login.html",
                    erro=(
                        "Limite de tentativas atingido. "
                        "Seu acesso foi bloqueado por 15 minutos."
                    )
                )

            return render_template(
                "login.html",
                erro="Usuário ou senha incorretos."
            )

        except mysql.connector.Error as erro:
            print(f"Erro no banco de dados: {erro}")

            return render_template(
                "login.html",
                erro="Erro ao acessar o banco de dados."
            )

        finally:
            if cursor:
                cursor.close()

            if conexao and conexao.is_connected():
                conexao.close()

    return render_template("login.html")


# =====================================
# PAINEL ADMINISTRATIVO
# =====================================

@app.route("/painel")
def painel():

    if not administrador_logado():
        return redirect(url_for("login"))

    return render_template("painel.html")


# =====================================
# LISTAR USUARIOS
# =====================================

@app.route("/usuarios")
def usuarios():

    if not administrador_logado():
        return redirect(url_for("login"))

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        # Regulariza cadastros administrativos órfãos.
        #
        # Se o usuário ainda está marcado como administrador, mas não
        # possui mais registro correspondente em administradores, sua
        # conta administrativa foi removida.
        #
        # Nesse caso, mantemos o cadastro histórico no MySQL, mas
        # inativamos a conta e alteramos sua categoria para membro.
        # A sincronização automática tratará a remoção do iDFace.
        cursor.execute(
            """
            UPDATE usuarios u
            LEFT JOIN administradores a
                ON a.id_usuario = u.id
            SET
                u.categoria = 'membro',
                u.ativo = 0
            WHERE u.categoria = 'administrador'
              AND u.ativo = 1
              AND a.id IS NULL
            """
        )

        usuarios_regularizados = cursor.rowcount

        # IMPORTANTE:
        # Confirma a regularização no banco. Sem este commit,
        # a alteração poderia ser desfeita ao fechar a conexão.
        if usuarios_regularizados > 0:
            conexao.commit()

            print(
                "Cadastros administrativos órfãos regularizados: "
                f"{usuarios_regularizados}. "
                "Categoria alterada para membro, conta inativada "
                "e histórico preservado.",
                flush=True
            )

        # Lista:
        # 1. Membros ativos.
        # 2. Administradores ativos.
        # 3. Masters ativos.
        #
        # Uma conta administrativa só aparece se estiver ativa
        # nas duas tabelas: usuarios e administradores.
        #
        # Se a conta for excluída pela tela de administradores,
        # ela não aparecerá aqui, pois será inativada e seu registro
        # administrativo será removido.
        cursor.execute(
            """
            SELECT
                u.id,
                u.nome,
                u.categoria,
                u.id_idface,
                a.id AS id_administrador,
                a.perfil AS perfil_administrativo
            FROM usuarios u
            LEFT JOIN administradores a
                ON a.id_usuario = u.id
            WHERE u.ativo = 1
              AND (
                    u.categoria = 'membro'
                    OR (
                        u.categoria = 'administrador'
                        AND a.id IS NOT NULL
                        AND a.ativo = 1
                    )
              )
            ORDER BY u.nome ASC
            """
        )

        lista_usuarios = cursor.fetchall()

        return render_template(
            "usuarios.html",
            usuarios=lista_usuarios,
            perfil_logado=perfil_logado(),
            master_logado=master_logado()
        )

    except mysql.connector.Error as erro:
        if conexao:
            conexao.rollback()

        print(f"Erro ao consultar usuários: {erro}", flush=True)

        return render_template(
            "usuarios.html",
            usuarios=[],
            perfil_logado=perfil_logado(),
            master_logado=master_logado(),
            erro="Não foi possível carregar os usuários."
        )

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# REGISTROS DE ACESSO
# =====================================

@app.route("/registros-acesso")
def registros_acesso():

    if not administrador_logado():
        return redirect(url_for("login"))

    conexao = None
    cursor = None

    pesquisa = request.args.get("q", "").strip()
    data_inicio = request.args.get("data_inicio", "").strip()
    data_fim = request.args.get("data_fim", "").strip()

    registros = []

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        consulta = """
            SELECT
                r.id,
                r.id_idface,
                r.id_usuario,
                r.data_hora,
                r.evento,
                r.dispositivo_id,
                u.nome AS nome_usuario
            FROM registros_acesso r
            LEFT JOIN usuarios u
                ON r.id_usuario = u.id
            WHERE 1 = 1
        """

        parametros = []

        if pesquisa:
            consulta += """
                AND u.nome LIKE %s
            """
            parametros.append(f"%{pesquisa}%")

        if data_inicio:
            consulta += """
                AND DATE(r.data_hora) >= %s
            """
            parametros.append(data_inicio)

        if data_fim:
            consulta += """
                AND DATE(r.data_hora) <= %s
            """
            parametros.append(data_fim)

        consulta += """
            ORDER BY r.data_hora DESC, r.id DESC
        """

        cursor.execute(consulta, tuple(parametros))

        registros = cursor.fetchall()

        return render_template(
            "registros_acesso.html",
            registros=registros,
            pesquisa=pesquisa,
            data_inicio=data_inicio,
            data_fim=data_fim
        )

    except mysql.connector.Error as erro:
        print(f"Erro ao consultar registros de acesso: {erro}")

        return render_template(
            "registros_acesso.html",
            registros=[],
            pesquisa=pesquisa,
            data_inicio=data_inicio,
            data_fim=data_fim,
            erro="Não foi possível carregar os registros de acesso."
        )

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# CADASTRAR NOVO USUARIO
# =====================================

@app.route("/usuarios/novo", methods=["GET", "POST"])
def novo_usuario():

    if not administrador_logado():
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template(
            "novo_usuario.html",
            categoria="membro"
        )

    nome = request.form.get("nome", "").strip()
    categoria = request.form.get("categoria", "membro").strip()

    if categoria != "membro":
        return render_template(
            "novo_usuario.html",
            erro=(
                "Cadastros administrativos devem ser criados "
                "pela área de administradores."
            ),
            nome=nome,
            categoria="membro"
        )

    if not nome:
        return render_template(
            "novo_usuario.html",
            erro="Informe o nome do usuário.",
            nome=nome,
            categoria=categoria
        )

    conexao = None
    cursor = None
    id_idface = None
    id_usuario = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor()

        cursor.execute(
            """
            INSERT INTO usuarios (nome, categoria)
            VALUES (%s, %s)
            """,
            (nome, categoria)
        )

        id_usuario = cursor.lastrowid

        with IDFaceClient() as idface:
            id_idface = idface.cadastrar_usuario(
                id_usuario,
                nome
            )

            idface.definir_administrador(
                id_idface,
                False
            )

        cursor.execute(
            """
            UPDATE usuarios
            SET id_idface = %s
            WHERE id = %s
            """,
            (id_idface, id_usuario)
        )

        conexao.commit()

        print(
            f"Usuário cadastrado: {nome} | "
            f"MySQL: {id_usuario} | "
            f"iDFace: {id_idface}"
        )

        return redirect(url_for("usuarios"))

    except (mysql.connector.Error, IDFaceError) as erro:

        if conexao:
            conexao.rollback()

        if id_idface is not None:
            try:
                with IDFaceClient() as idface:
                    idface.excluir_usuario(id_idface)

            except IDFaceError as erro_compensacao:
                print(
                    "ATENÇÃO: falha ao remover o cadastro "
                    "incompleto do iDFace:",
                    erro_compensacao
                )

        print(f"Erro ao cadastrar usuário: {erro}")

        return render_template(
            "novo_usuario.html",
            erro=(
                "Não foi possível concluir o cadastro. "
                "Verifique a comunicação com o iDFace e o banco."
            ),
            nome=nome,
            categoria=categoria
        )

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# EDITAR USUARIO
# =====================================

@app.route("/usuarios/editar/<int:id_usuario>", methods=["GET", "POST"])
def editar_usuario(id_usuario):

    if not administrador_logado():
        return redirect(url_for("login"))

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                u.id,
                u.nome,
                u.categoria,
                u.id_idface,
                a.id AS id_administrador,
                a.usuario AS usuario_admin,
                a.perfil AS perfil_administrativo,
                a.ativo AS administrador_ativo
            FROM usuarios u
            LEFT JOIN administradores a
                ON a.id_usuario = u.id
            WHERE u.id = %s
              AND u.ativo = 1
            """,
            (id_usuario,)
        )

        usuario = cursor.fetchone()

        if not usuario:
            return redirect(url_for("usuarios"))

        # Administradores devem ser gerenciados na área própria.
        if usuario["categoria"] == "administrador":
            return redirect(url_for("administradores"))

        if request.method == "GET":
            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                perfil_logado=perfil_logado(),
                master_logado=master_logado(),
                usuario_admin=usuario.get("usuario_admin"),
                categoria_selecionada=None
            )

        nome = request.form.get("nome", "").strip()
        categoria = request.form.get("categoria", "").strip()

        usuario_admin = request.form.get("usuario_admin", "").strip()
        senha_admin = request.form.get("senha_admin", "")

        if not nome:
            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                perfil_logado=perfil_logado(),
                master_logado=master_logado(),
                usuario_admin=usuario_admin,
                categoria_selecionada=categoria,
                erro="Informe o nome do usuário."
            )

        if categoria not in ("membro", "administrador", "master"):
            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                perfil_logado=perfil_logado(),
                master_logado=master_logado(),
                usuario_admin=usuario_admin,
                categoria_selecionada=categoria,
                erro="Selecione uma categoria válida."
            )

        if categoria in ("administrador", "master") and not master_logado():
            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                perfil_logado=perfil_logado(),
                master_logado=master_logado(),
                usuario_admin=usuario_admin,
                categoria_selecionada="membro",
                erro="Somente um MASTER pode promover usuários."
            )

        if categoria in ("administrador", "master"):

            if not usuario_admin:
                return render_template(
                    "editar_usuario.html",
                    usuario=usuario,
                    perfil_logado=perfil_logado(),
                    master_logado=master_logado(),
                    usuario_admin=usuario_admin,
                    categoria_selecionada=categoria,
                    erro="Informe o nome de usuário para acesso ao painel."
                )

            if not senha_admin:
                return render_template(
                    "editar_usuario.html",
                    usuario=usuario,
                    perfil_logado=perfil_logado(),
                    master_logado=master_logado(),
                    usuario_admin=usuario_admin,
                    categoria_selecionada=categoria,
                    erro="Informe uma senha para acesso ao painel."
                )

            if len(senha_admin) < 8:
                return render_template(
                    "editar_usuario.html",
                    usuario=usuario,
                    perfil_logado=perfil_logado(),
                    master_logado=master_logado(),
                    usuario_admin=usuario_admin,
                    categoria_selecionada=categoria,
                    erro="A senha deve possuir pelo menos 8 caracteres."
                )

            cursor.execute(
                """
                SELECT id
                FROM administradores
                WHERE usuario = %s
                  AND id_usuario <> %s
                """,
                (usuario_admin, id_usuario)
            )

            if cursor.fetchone():
                return render_template(
                    "editar_usuario.html",
                    usuario=usuario,
                    perfil_logado=perfil_logado(),
                    master_logado=master_logado(),
                    usuario_admin=usuario_admin,
                    categoria_selecionada=categoria,
                    erro="Esse nome de usuário já está sendo utilizado."
                )

        if usuario["id_idface"] is None:
            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                perfil_logado=perfil_logado(),
                master_logado=master_logado(),
                usuario_admin=usuario_admin,
                categoria_selecionada=categoria,
                erro=(
                    "Este usuário ainda não está associado ao iDFace. "
                    "A edição está bloqueada até regularizarmos essa associação."
                )
            )

        nome_anterior = usuario["nome"]
        id_idface = usuario["id_idface"]

        # Guarda a permissão anterior para restaurá-la em caso de falha.
        era_administrador_no_idface = (
            usuario["categoria"] == "administrador"
        )

        categoria_banco = (
            "membro"
            if categoria == "membro"
            else "administrador"
        )

        perfil_administrativo = (
            "master"
            if categoria == "master"
            else "administrador"
        )

        id_administrador_existente = usuario.get("id_administrador")

        try:
            # Atualiza o equipamento antes de confirmar no MySQL.
            with IDFaceClient() as idface:
                idface.editar_usuario(
                    id_idface,
                    nome
                )

                idface.definir_administrador(
                    id_idface,
                    categoria_banco == "administrador"
                )

            cursor.execute(
                """
                UPDATE usuarios
                SET nome = %s,
                    categoria = %s
                WHERE id = %s
                  AND ativo = 1
                """,
                (nome, categoria_banco, id_usuario)
            )

            if categoria_banco == "administrador":

                senha_hash = generate_password_hash(senha_admin)

                if id_administrador_existente:

                    cursor.execute(
                        """
                        UPDATE administradores
                        SET nome = %s,
                            usuario = %s,
                            senha_hash = %s,
                            perfil = %s,
                            ativo = TRUE
                        WHERE id = %s
                        """,
                        (
                            nome,
                            usuario_admin,
                            senha_hash,
                            perfil_administrativo,
                            id_administrador_existente
                        )
                    )

                else:

                    cursor.execute(
                        """
                        INSERT INTO administradores
                            (
                                id_usuario,
                                nome,
                                usuario,
                                senha_hash,
                                perfil,
                                ativo
                            )
                        VALUES (%s, %s, %s, %s, %s, TRUE)
                        """,
                        (
                            id_usuario,
                            nome,
                            usuario_admin,
                            senha_hash,
                            perfil_administrativo
                        )
                    )

            else:

                # Rebaixamento: perde o painel, mas continua
                # ativo como membro e com acesso físico.
                if id_administrador_existente:
                    cursor.execute(
                        """
                        UPDATE administradores
                        SET ativo = FALSE
                        WHERE id = %s
                        """,
                        (id_administrador_existente,)
                    )

            conexao.commit()

            print(
                f"Usuário atualizado: {nome} | "
                f"Categoria: {categoria} | "
                f"MySQL: {id_usuario} | "
                f"iDFace: {id_idface}"
            )

            return redirect(url_for("usuarios"))

        except (IDFaceError, mysql.connector.Error) as erro:

            conexao.rollback()

            print(f"Erro ao atualizar usuário: {erro}")

            # Restaura os dados e a permissão que existiam antes.
            try:
                with IDFaceClient() as idface:
                    idface.editar_usuario(
                        id_idface,
                        nome_anterior
                    )

                    idface.definir_administrador(
                        id_idface,
                        era_administrador_no_idface
                    )

            except IDFaceError as erro_compensacao:
                print(
                    "ATENÇÃO: não foi possível restaurar "
                    "os dados anteriores no iDFace:",
                    erro_compensacao
                )

            usuario["nome"] = nome

            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                perfil_logado=perfil_logado(),
                master_logado=master_logado(),
                usuario_admin=usuario_admin,
                categoria_selecionada=categoria,
                erro=(
                    "Não foi possível concluir a atualização. "
                    "Verifique a comunicação com o iDFace e o banco de dados."
                )
            )

    except mysql.connector.Error as erro:
        print(f"Erro ao consultar usuário: {erro}")

        return redirect(url_for("usuarios"))

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# EXCLUIR USUARIO
# =====================================

@app.route("/usuarios/excluir/<int:id_usuario>", methods=["POST"])
def excluir_usuario(id_usuario):

    if not administrador_logado():
        return redirect(url_for("login"))

    conexao = None
    cursor = None
    usuario = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, nome, id_idface, categoria
            FROM usuarios
            WHERE id = %s
              AND ativo = 1
            FOR UPDATE
            """,
            (id_usuario,)
        )

        usuario = cursor.fetchone()

        if not usuario:
            return redirect(url_for("usuarios"))

        if usuario["categoria"] == "administrador":
            print(
                "Exclusão bloqueada: o cadastro pertence "
                "à categoria administrador."
            )
            return redirect(url_for("usuarios"))

        if usuario["id_idface"] is not None:
            with IDFaceClient() as idface:
                idface.excluir_usuario(
                    usuario["id_idface"]
                )

        cursor.execute(
            """
            UPDATE usuarios
            SET ativo = 0
            WHERE id = %s
            """,
            (id_usuario,)
        )

        conexao.commit()

        print(
            f"Usuário excluído: {usuario['nome']} | "
            f"MySQL: {id_usuario} | "
            f"iDFace: {usuario['id_idface']} | "
            "Histórico preservado."
        )

        return redirect(url_for("usuarios"))

    except IDFaceError as erro:

        if conexao:
            conexao.rollback()

        print(f"Erro ao excluir usuário do iDFace: {erro}")

        return redirect(url_for("usuarios"))

    except mysql.connector.Error as erro:

        if conexao:
            conexao.rollback()

        print(f"Erro ao excluir usuário do MySQL: {erro}")

        if usuario and usuario["id_idface"] is not None:
            print(
                "ATENÇÃO: o usuário pode ter sido removido "
                "do iDFace, mas sua inativação no MySQL falhou. "
                "Verifique a sincronização antes de tentar novamente."
            )

        return redirect(url_for("usuarios"))

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# ADMINISTRADORES
# =====================================

@app.route("/administradores")
def administradores():

    if not administrador_logado():
        return redirect(url_for("login"))

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                id,
                id_usuario,
                nome,
                usuario,
                perfil,
                ativo,
                data_cadastro
            FROM administradores
            ORDER BY nome ASC
            """
        )

        lista_administradores = cursor.fetchall()

        return render_template(
            "administradores.html",
            administradores=lista_administradores,
            perfil_logado=perfil_logado(),
            master_logado=master_logado()
        )

    except mysql.connector.Error as erro:
        print(f"Erro ao consultar administradores: {erro}")

        return render_template(
            "administradores.html",
            administradores=[],
            perfil_logado=perfil_logado(),
            master_logado=master_logado(),
            erro="Não foi possível carregar os administradores."
        )

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# CADASTRAR ADMINISTRADOR
# =====================================

@app.route("/administradores/novo", methods=["GET", "POST"])
def novo_administrador():

    resposta_bloqueio = bloquear_se_nao_master()
    if resposta_bloqueio:
        return resposta_bloqueio

    if request.method == "GET":
        return render_template(
            "novo_administrador.html",
            perfil_logado=perfil_logado(),
            master_logado=master_logado()
        )

    nome = request.form.get("nome", "").strip()
    usuario = request.form.get("usuario", "").strip()
    senha = request.form.get("senha", "")
    confirmar_senha = request.form.get("confirmar_senha", "")

    if not nome or not usuario or not senha or not confirmar_senha:
        return render_template(
            "novo_administrador.html",
            erro="Preencha todos os campos.",
            nome=nome,
            usuario=usuario,
            perfil_logado=perfil_logado(),
            master_logado=master_logado()
        )

    if len(senha) < 8:
        return render_template(
            "novo_administrador.html",
            erro="A senha deve possuir pelo menos 8 caracteres.",
            nome=nome,
            usuario=usuario,
            perfil_logado=perfil_logado(),
            master_logado=master_logado()
        )

    if senha != confirmar_senha:
        return render_template(
            "novo_administrador.html",
            erro="As senhas informadas não coincidem.",
            nome=nome,
            usuario=usuario,
            perfil_logado=perfil_logado(),
            master_logado=master_logado()
        )

    conexao = None
    cursor = None
    id_usuario = None
    id_idface = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor()

        cursor.execute(
            "SELECT id FROM administradores WHERE usuario = %s",
            (usuario,)
        )

        if cursor.fetchone():
            return render_template(
                "novo_administrador.html",
                erro="Esse nome de usuário já está sendo utilizado.",
                nome=nome,
                usuario=usuario
            )

        cursor.execute(
            """
            INSERT INTO usuarios (nome, categoria)
            VALUES (%s, 'administrador')
            """,
            (nome,)
        )

        id_usuario = cursor.lastrowid

        with IDFaceClient() as idface:
            id_idface = idface.cadastrar_usuario(id_usuario, nome)
            idface.definir_administrador(id_idface, True)

        cursor.execute(
            """
            UPDATE usuarios
            SET id_idface = %s
            WHERE id = %s
            """,
            (id_idface, id_usuario)
        )

        senha_hash = generate_password_hash(senha)

        cursor.execute(
            """
            INSERT INTO administradores
                (id_usuario, nome, usuario, senha_hash, perfil, ativo)
            VALUES (%s, %s, %s, %s, 'administrador', TRUE)
            """,
            (id_usuario, nome, usuario, senha_hash)
        )

        conexao.commit()

        print(
            f"Administrador cadastrado: {nome} | "
            f"Usuário: {usuario} | "
            f"MySQL: {id_usuario} | "
            f"iDFace: {id_idface}"
        )

        return redirect(url_for("administradores"))

    except mysql.connector.IntegrityError as erro:
        if conexao:
            conexao.rollback()

        if id_idface is not None:
            try:
                with IDFaceClient() as idface:
                    idface.excluir_usuario(id_idface)
            except IDFaceError as erro_compensacao:
                print(
                    "ATENÇÃO: não foi possível remover o cadastro "
                    "incompleto do iDFace:",
                    erro_compensacao
                )

        print(f"Erro de integridade ao cadastrar administrador: {erro}")

        return render_template(
            "novo_administrador.html",
            erro=(
                "Não foi possível concluir o cadastro. "
                "Verifique se o nome de usuário já está em uso."
            ),
            nome=nome,
            usuario=usuario
        )

    except (mysql.connector.Error, IDFaceError) as erro:
        if conexao:
            conexao.rollback()

        if id_idface is not None:
            try:
                with IDFaceClient() as idface:
                    idface.excluir_usuario(id_idface)
            except IDFaceError as erro_compensacao:
                print(
                    "ATENÇÃO: não foi possível remover o cadastro "
                    "incompleto do iDFace:",
                    erro_compensacao
                )

        print(f"Erro ao cadastrar administrador: {erro}")

        return render_template(
            "novo_administrador.html",
            erro=(
                "Não foi possível concluir o cadastro. "
                "Verifique a comunicação com o iDFace e o banco de dados."
            ),
            nome=nome,
            usuario=usuario
        )

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# EDITAR ADMINISTRADOR
# =====================================

@app.route(
    "/administradores/editar/<int:id_administrador>",
    methods=["GET", "POST"]
)
def editar_administrador(id_administrador):

    resposta_bloqueio = bloquear_se_nao_master()
    if resposta_bloqueio:
        return resposta_bloqueio

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, id_usuario, nome, usuario, perfil, ativo
            FROM administradores
            WHERE id = %s
            """,
            (id_administrador,)
        )

        administrador = cursor.fetchone()

        if not administrador:
            return redirect(url_for("administradores"))

        if request.method == "GET":
            return render_template(
                "editar_administrador.html",
                administrador=administrador,
                perfil_logado=perfil_logado(),
                master_logado=master_logado()
            )

        nome = request.form.get("nome", "").strip()
        usuario = request.form.get("usuario", "").strip()
        senha = request.form.get("senha", "")
        confirmar_senha = request.form.get("confirmar_senha", "")

        if not nome or not usuario:
            return render_template(
                "editar_administrador.html",
                administrador=administrador,
                perfil_logado=perfil_logado(),
                master_logado=master_logado(),
                erro="Nome e usuário são obrigatórios."
            )

        if senha and len(senha) < 8:
            return render_template(
                "editar_administrador.html",
                administrador=administrador,
                perfil_logado=perfil_logado(),
                master_logado=master_logado(),
                erro="A nova senha deve possuir pelo menos 8 caracteres."
            )

        if senha and senha != confirmar_senha:
            return render_template(
                "editar_administrador.html",
                administrador=administrador,
                perfil_logado=perfil_logado(),
                master_logado=master_logado(),
                erro="As senhas informadas não coincidem."
            )

        if senha:
            senha_hash = generate_password_hash(senha)

            cursor.execute(
                """
                UPDATE administradores
                SET nome = %s,
                    usuario = %s,
                    senha_hash = %s
                WHERE id = %s
                """,
                (nome, usuario, senha_hash, id_administrador)
            )

        else:
            cursor.execute(
                """
                UPDATE administradores
                SET nome = %s,
                    usuario = %s
                WHERE id = %s
                """,
                (nome, usuario, id_administrador)
            )

        cursor.execute(
            """
            UPDATE usuarios
            SET nome = %s
            WHERE id = %s
            """,
            (nome, administrador["id_usuario"])
        )

        conexao.commit()

        if id_administrador == session.get("admin_id"):
            session["admin_nome"] = nome

        print(f"Administrador atualizado: {usuario}")

        return redirect(url_for("administradores"))

    except mysql.connector.IntegrityError as erro:
        if conexao:
            conexao.rollback()

        print(f"Erro de integridade ao editar administrador: {erro}")

        return render_template(
            "editar_administrador.html",
            administrador=administrador,
            perfil_logado=perfil_logado(),
            master_logado=master_logado(),
            erro="Esse nome de usuário já está sendo utilizado."
        )

    except mysql.connector.Error as erro:
        if conexao:
            conexao.rollback()

        print(f"Erro ao editar administrador: {erro}")

        return render_template(
            "editar_administrador.html",
            administrador=administrador,
            perfil_logado=perfil_logado(),
            master_logado=master_logado(),
            erro="Não foi possível atualizar o administrador."
        )

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# EXCLUIR ADMINISTRADOR
# =====================================

@app.route(
    "/administradores/excluir/<int:id_administrador>",
    methods=["POST"]
)
def excluir_administrador(id_administrador):

    print(
        f"[ROTA EXCLUIR ADMINISTRADOR] POST recebido para "
        f"administradores.id={id_administrador}",
        flush=True
    )

    resposta_bloqueio = bloquear_se_nao_master()
    if resposta_bloqueio:
        return resposta_bloqueio

    # Impede que o MASTER exclua a própria conta.
    if id_administrador == session.get("admin_id"):
        print(
            "Exclusão bloqueada: tentativa de autoexclusão."
        )
        return redirect(url_for("administradores"))

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        # Bloqueia os registros administrativos para evitar
        # alterações concorrentes durante a exclusão.
        cursor.execute(
            """
            SELECT id, ativo
            FROM administradores
            FOR UPDATE
            """
        )

        administradores_bloqueados = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                a.id,
                a.id_usuario,
                a.nome,
                a.ativo,
                u.id_idface
            FROM administradores a
            INNER JOIN usuarios u
                ON u.id = a.id_usuario
            WHERE a.id = %s
            FOR UPDATE
            """,
            (id_administrador,)
        )

        administrador = cursor.fetchone()

        if not administrador:
            conexao.rollback()
            print("Exclusão cancelada: administrador não encontrado.")
            return redirect(url_for("administradores"))

        # Impede excluir o último administrador ativo.
        # Administradores já inativos podem ser excluídos.
        if administrador["ativo"]:
            total_ativos = sum(
                1
                for admin in administradores_bloqueados
                if admin["ativo"]
            )

            if total_ativos <= 1:
                conexao.rollback()

                print(
                    "Exclusão bloqueada: não é permitido "
                    "excluir o último administrador ativo."
                )

                return redirect(url_for("administradores"))

        id_usuario = administrador["id_usuario"]
        id_idface = administrador["id_idface"]
        nome = administrador["nome"]

        # 1. Desativa integralmente o cadastro do usuário.
        # O cadastro histórico permanece no banco.
        cursor.execute(
            """
            UPDATE usuarios
            SET categoria = 'membro',
                ativo = 0
            WHERE id = %s
            """,
            (id_usuario,)
        )

        if cursor.rowcount == 0:
            conexao.rollback()

            print(
                "Exclusão cancelada: cadastro correspondente "
                "não foi localizado na tabela usuarios."
            )

            return redirect(url_for("administradores"))

        # 2. Remove a conta administrativa.
        # Isso impede o acesso ao painel.
        cursor.execute(
            """
            DELETE FROM administradores
            WHERE id = %s
              AND id_usuario = %s
            """,
            (id_administrador, id_usuario)
        )

        if cursor.rowcount == 0:
            conexao.rollback()

            print(
                "Exclusão cancelada: não foi possível remover "
                "o registro administrativo."
            )

            return redirect(url_for("administradores"))

        # 3. Confirma as alterações no MySQL.
        # Os registros de acesso e o histórico de IDs não são apagados.
        conexao.commit()

        print(
            f"Administrador excluído integralmente: {nome} | "
            f"MySQL: {id_usuario} | "
            "Categoria: membro | "
            "Ativo: 0 | "
            "Conta administrativa removida | "
            "Histórico preservado."
        )

        # 4. Tenta remover a identificação física do iDFace.
        # Se o equipamento estiver indisponível, a sincronização
        # automática deverá remover a identidade posteriormente.
        if id_idface is not None:

            try:
                with IDFaceClient() as idface:
                    idface.excluir_usuario(id_idface)

                print(
                    f"Identificação removida do iDFace: {id_idface}"
                )

            except IDFaceError as erro_idface:
                print(
                    "ATENÇÃO: a conta foi excluída do MySQL, "
                    "mas não foi possível remover a identificação "
                    "do iDFace neste momento. "
                    "A sincronização automática deverá tentar "
                    "removê-la posteriormente. "
                    f"Erro: {erro_idface}"
                )

        else:
            print(
                "ATENÇÃO: o administrador não possuía ID associado "
                "ao iDFace. O cadastro foi inativado no MySQL."
            )

        return redirect(url_for("administradores"))

    except mysql.connector.Error as erro:

        if conexao:
            conexao.rollback()

        print(f"Erro ao excluir administrador: {erro}")

        return redirect(url_for("administradores"))

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# ENCERRAR SESSAO
# =====================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =====================================
# INICIAR SINCRONIZACAO AUTOMATICA
# =====================================

def iniciar_sincronizacao():

    print("\nIniciando sincronização automática do Wickedbotz...")

    thread = Thread(
        target=iniciar_servidor,
        name="Wickedbotz-Sincronizacao",
        daemon=True
    )

    thread.start()

    print("Sincronização executada em segundo plano!\n")


# =====================================
# INICIAR APLICACAO
# =====================================

if __name__ == "__main__":

    if (
        not DEBUG
        or os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    ):
        iniciar_sincronizacao()

    app.run(debug=DEBUG)