from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import check_password_hash, generate_password_hash
from threading import Thread, Lock
from datetime import timedelta
import os
import time
import math
import secrets
import hmac
import base64
import binascii

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
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
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


def obter_foto_facial_data_uri(cursor, id_usuario):
    """Retorna a foto facial local como Data URI, sem consultar o iDFace."""
    cursor.execute(
        """
        SELECT imagem
        FROM fotos_faciais
        WHERE id_usuario = %s
        LIMIT 1
        """,
        (id_usuario,)
    )

    resultado = cursor.fetchone()
    if not resultado or not resultado.get("imagem"):
        return None

    imagem = resultado["imagem"]

    if isinstance(imagem, bytes):
        imagem = imagem.decode("ascii", errors="ignore")

    imagem = imagem.strip()
    if not imagem:
        return None

    if imagem.startswith("data:image/"):
        return imagem

    imagem = "".join(imagem.split())

    try:
        dados = base64.b64decode(imagem, validate=True)
    except (binascii.Error, ValueError, TypeError):
        print(
            f"Foto facial inválida no banco para o usuário {id_usuario}.",
            flush=True
        )
        return None

    if dados.startswith(b"\xff\xd8\xff"):
        mime = "image/jpeg"
    elif dados.startswith(b"\x89PNG\r\n\x1a\n"):
        mime = "image/png"
    elif dados[:4] == b"RIFF" and dados[8:12] == b"WEBP":
        mime = "image/webp"
    else:
        mime = "image/jpeg"

    return f"data:{mime};base64,{imagem}"


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

    csrf_token = session.get("csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        session["csrf_token"] = csrf_token

    return render_template(
        "painel.html",
        master_logado=master_logado(),
        csrf_token=csrf_token
    )


def registrar_abertura_remota(
    id_administrador,
    nome_administrador,
    resultado,
    detalhe,
    id_dispositivo=None
):
    """
    Registra a tentativa de abertura remota em tabela separada.
    Não altera registros_acesso, que permanece reservado aos eventos
    recebidos do iDFace.
    """
    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor()

        cursor.execute(
            """
            INSERT INTO aberturas_remotas (
                id_administrador,
                nome_administrador,
                data_hora,
                resultado,
                detalhe,
                id_dispositivo
            )
            VALUES (%s, %s, NOW(), %s, %s, %s)
            """,
            (
                id_administrador,
                nome_administrador,
                resultado,
                detalhe[:500] if detalhe else None,
                str(id_dispositivo) if id_dispositivo is not None else None
            )
        )

        conexao.commit()

    except mysql.connector.Error as erro:
        print(
            f"Falha ao registrar auditoria da abertura remota: {erro}",
            flush=True
        )

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


@app.route("/painel/abrir-porta", methods=["POST"])
def abrir_porta_remota():

    if not administrador_logado():
        return redirect(url_for("login"))

    token_sessao = session.get("csrf_token", "")
    token_formulario = request.form.get("csrf_token", "")

    if (
        not token_sessao
        or not token_formulario
        or not hmac.compare_digest(token_sessao, token_formulario)
    ):
        return "Solicitação inválida. Atualize a página e tente novamente.", 400

    conexao = None
    cursor = None
    administrador = None

    try:
        # A permissão é consultada novamente no MySQL.
        # Não confiamos somente no perfil armazenado na sessão.
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                a.id,
                a.nome,
                a.perfil
            FROM administradores a
            INNER JOIN usuarios u ON u.id = a.id_usuario
            WHERE a.id = %s
              AND a.ativo = TRUE
              AND u.ativo = TRUE
              AND u.categoria = 'administrador'
              AND a.perfil = 'master'
            LIMIT 1
            """,
            (session.get("admin_id"),)
        )

        administrador = cursor.fetchone()

    except mysql.connector.Error as erro:
        print(
            f"Erro ao validar permissão de abertura remota: {erro}",
            flush=True
        )
        flash(
            "Não foi possível validar sua permissão no banco de dados.",
            "erro"
        )
        return redirect(url_for("painel"))

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()

    if not administrador:
        flash(
            "A abertura remota é permitida somente para contas MASTER ativas.",
            "erro"
        )
        return redirect(url_for("painel"))

    id_dispositivo = None

    try:
        with IDFaceClient() as idface:

            # Descobre o identificador da SecBox conectada ao iDFace.
            # Assim não presumimos um ID fixo que pode variar por equipamento.
            estado_portas = idface.requisicao(
                "doors_state.fcgi",
                {}
            )

            # Diagnóstico temporário: registra somente a estrutura retornada
            # pelo equipamento, sem expor sessão, senha ou credenciais.
            print(
                "[DIAGNOSTICO SECOBOX] Resposta completa de "
                f"doors_state.fcgi: {estado_portas!r}",
                flush=True
            )
            print(
                "[DIAGNOSTICO SECOBOX] Tipo da resposta: "
                f"{type(estado_portas).__name__}; "
                "chaves: "
                f"{list(estado_portas.keys()) if isinstance(estado_portas, dict) else 'N/A'}",
                flush=True
            )

            if not isinstance(estado_portas, dict):
                raise IDFaceError(
                    "O iDFace retornou um formato inesperado ao consultar "
                    "doors_state.fcgi. Consulte o log [DIAGNOSTICO SECOBOX] "
                    "do servidor."
                )

            sec_boxes = estado_portas.get("sec_boxes", [])
            print(
                "[DIAGNOSTICO SECOBOX] sec_boxes="
                f"{sec_boxes!r}; quantidade="
                f"{len(sec_boxes) if isinstance(sec_boxes, list) else 'não é lista'}",
                flush=True
            )

            if not isinstance(sec_boxes, list):
                raise IDFaceError(
                    "O iDFace retornou sec_boxes em um formato inesperado. "
                    "Consulte o log [DIAGNOSTICO SECOBOX] do servidor."
                )

            # A documentação oficial da Control iD apresenta duas entradas
            # no retorno de doors_state.fcgi para equipamentos com SecBox.
            # No exemplo oficial de acionamento do módulo externo, o ID usado
            # é 65793. Portanto, não devemos exigir que a lista tenha apenas
            # um item nem escolher simplesmente o primeiro ID retornado.
            sec_boxes_validas = [
                sec_box for sec_box in sec_boxes
                if isinstance(sec_box, dict) and sec_box.get("id") is not None
            ]

            sec_boxes_acionaveis = [
                sec_box for sec_box in sec_boxes_validas
                if str(sec_box.get("id")) == "65793"
            ]

            if len(sec_boxes_acionaveis) != 1:
                ids_encontrados = [
                    sec_box.get("id") for sec_box in sec_boxes_validas
                ]
                raise IDFaceError(
                    "Não foi possível identificar de forma inequívoca a SecBox "
                    "documentada para acionamento (ID 65793). "
                    f"IDs retornados pelo iDFace: {ids_encontrados!r}. "
                    "O comando não foi enviado."
                )

            id_dispositivo = sec_boxes_acionaveis[0].get("id")

            print(
                "[DIAGNOSTICO SECOBOX] SecBox selecionada para acionamento: "
                f"ID {id_dispositivo}",
                flush=True
            )

            resposta = idface.requisicao(
                "execute_actions.fcgi",
                {
                    "actions": [
                        {
                            "action": "sec_box",
                            "parameters": (
                                f"id={id_dispositivo}, reason=3"
                            )
                        }
                    ]
                }
            )

            acoes = resposta.get("actions", []) if isinstance(
                resposta, dict
            ) else []

            acao_negada = any(
                isinstance(acao, dict)
                and str(acao.get("status", "")).lower() == "denied"
                for acao in acoes
            )

            if acao_negada:
                raise IDFaceError(
                    "O iDFace recusou o acionamento da SecBox."
                )

        detalhe = (
            "Comando de abertura remota enviado ao iDFace."
        )

        registrar_abertura_remota(
            administrador["id"],
            administrador["nome"],
            "sucesso",
            detalhe,
            id_dispositivo
        )

        flash(
            "Comando de abertura enviado ao iDFace. "
            "Porta Aberta.",
            "sucesso"
        )

    except Exception as erro:
        detalhe = str(erro) or "Falha não identificada no acionamento."

        print(
            f"Falha na abertura remota solicitada por "
            f"{administrador['nome']}: {detalhe}",
            flush=True
        )

        registrar_abertura_remota(
            administrador["id"],
            administrador["nome"],
            "falha",
            detalhe,
            id_dispositivo
        )

        flash(
            "Não foi possível enviar o comando de abertura ao iDFace. "
            "Verifique a conexão e os registros do servidor.",
            "erro"
        )

    return redirect(url_for("painel"))


# =====================================
# LISTAR USUARIOS
# =====================================

@app.route("/usuarios")
def usuarios():

    if not administrador_logado():
        return redirect(url_for("login"))

    conexao = None
    cursor = None

    pesquisa = request.args.get("q", "").strip()
    filtro_categoria = request.args.get(
        "categoria",
        "todos"
    ).strip().lower()

    categorias_validas = (
        "todos",
        "membro",
        "administrador",
        "master"
    )

    if filtro_categoria not in categorias_validas:
        filtro_categoria = "todos"

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

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

        if usuarios_regularizados > 0:
            conexao.commit()

            print(
                "Cadastros administrativos órfãos regularizados: "
                f"{usuarios_regularizados}. "
                "Categoria alterada para membro, conta inativada "
                "e histórico preservado.",
                flush=True
            )

        consulta = """
            SELECT
                u.id,
                u.nome,
                u.categoria,
                u.id_idface,
                a.id AS id_administrador,
                a.usuario AS usuario_admin,
                a.perfil AS perfil_administrativo,
                a.data_cadastro
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
        """

        parametros = []

        if filtro_categoria == "membro":
            consulta += """
                AND u.categoria = 'membro'
            """

        elif filtro_categoria == "administrador":
            consulta += """
                AND u.categoria = 'administrador'
                AND a.perfil = 'administrador'
            """

        elif filtro_categoria == "master":
            consulta += """
                AND u.categoria = 'administrador'
                AND a.perfil = 'master'
            """

        if pesquisa:
            consulta += """
                AND u.nome LIKE %s
            """
            parametros.append(f"%{pesquisa}%")

        consulta += """
            ORDER BY
                CASE
                    WHEN u.categoria = 'administrador'
                         AND a.perfil = 'master' THEN 1
                    WHEN u.categoria = 'administrador'
                         AND a.perfil = 'administrador' THEN 2
                    ELSE 3
                END,
                u.nome ASC
        """

        cursor.execute(consulta, tuple(parametros))

        lista_usuarios = cursor.fetchall()

        return render_template(
            "usuarios.html",
            usuarios=lista_usuarios,
            perfil_logado=perfil_logado(),
            master_logado=master_logado(),
            pesquisa=pesquisa,
            filtro_categoria=filtro_categoria
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
            pesquisa=pesquisa,
            filtro_categoria=filtro_categoria,
            erro="Não foi possível carregar os usuários."
        )

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
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

        # Eventos de acesso registrados pelo equipamento iDFace.
        consulta_faciais = """
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

        parametros_faciais = []

        if pesquisa:
            consulta_faciais += " AND u.nome LIKE %s"
            parametros_faciais.append(f"%{pesquisa}%")

        if data_inicio:
            consulta_faciais += " AND DATE(r.data_hora) >= %s"
            parametros_faciais.append(data_inicio)

        if data_fim:
            consulta_faciais += " AND DATE(r.data_hora) <= %s"
            parametros_faciais.append(data_fim)

        cursor.execute(consulta_faciais, tuple(parametros_faciais))
        registros_faciais = cursor.fetchall()

        for registro in registros_faciais:
            nome = registro.get("nome_usuario") or "Usuário não identificado"
            evento = registro.get("evento")

            registros.append({
                **registro,
                "tipo_registro": "facial",
                "origem": "Acesso facial",
                "identificador": f"FAC-{registro['id']}",
                "nome_exibicao": nome,
                "resultado_exibicao": (
                    f"Evento {evento}" if evento is not None else "-"
                ),
                "detalhe_exibicao": None
            })

        # Comandos de abertura remota solicitados por administradores.
        consulta_remotas = """
            SELECT
                a.id,
                a.id_administrador,
                a.nome_administrador,
                a.data_hora,
                a.resultado,
                a.detalhe,
                a.id_dispositivo
            FROM aberturas_remotas a
            WHERE 1 = 1
        """

        parametros_remotas = []

        if pesquisa:
            consulta_remotas += " AND a.nome_administrador LIKE %s"
            parametros_remotas.append(f"%{pesquisa}%")

        if data_inicio:
            consulta_remotas += " AND DATE(a.data_hora) >= %s"
            parametros_remotas.append(data_inicio)

        if data_fim:
            consulta_remotas += " AND DATE(a.data_hora) <= %s"
            parametros_remotas.append(data_fim)

        cursor.execute(consulta_remotas, tuple(parametros_remotas))
        registros_remotos = cursor.fetchall()

        for registro in registros_remotos:
            sucesso = (registro.get("resultado") or "").lower() == "sucesso"
            nome = (
                registro.get("nome_administrador")
                or "Administrador não identificado"
            )

            registros.append({
                "id": registro["id"],
                "id_administrador": registro["id_administrador"],
                "data_hora": registro["data_hora"],
                "dispositivo_id": registro.get("id_dispositivo"),
                "evento": None,
                "nome_usuario": nome,
                "tipo_registro": "remoto",
                "origem": "Abertura remota",
                "identificador": f"REM-{registro['id']}",
                "nome_exibicao": nome,
                "resultado_exibicao": (
                    "Comando enviado" if sucesso else "Falha no comando"
                ),
                "detalhe_exibicao": registro.get("detalhe")
            })

        # Une os dois tipos de registro em ordem cronológica decrescente.
        registros.sort(
            key=lambda item: (
                item.get("data_hora") is not None,
                item.get("data_hora")
            ),
            reverse=True
        )

        return render_template(
            "registros_acesso.html",
            registros=registros,
            pesquisa=pesquisa,
            data_inicio=data_inicio,
            data_fim=data_fim
        )

    except mysql.connector.Error as erro:
        print(f"Erro ao consultar histórico de acessos: {erro}", flush=True)

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


# CADASTRAR NOVO USUARIO
# =====================================

@app.route("/usuarios/novo", methods=["GET", "POST"])
def novo_usuario():

    if not administrador_logado():
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template(
            "novo_usuario.html",
            categoria="membro",
            master_logado=master_logado()
        )

    nome = request.form.get("nome", "").strip()
    categoria = request.form.get("categoria", "membro").strip()

    usuario_admin = request.form.get("usuario_admin", "").strip()
    senha_admin = request.form.get("senha_admin", "")
    confirmar_senha = request.form.get("confirmar_senha", "")

    eh_master = master_logado()

    def renderizar_erro(mensagem, categoria_form=None):
        return render_template(
            "novo_usuario.html",
            erro=mensagem,
            nome=nome,
            usuario_admin=usuario_admin,
            categoria=(
                categoria_form
                if categoria_form is not None
                else categoria
            ),
            master_logado=eh_master
        )

    if not nome:
        return renderizar_erro(
            "Informe o nome do usuário.",
            "membro" if not eh_master else categoria
        )

    if categoria not in ("membro", "administrador", "master"):
        return renderizar_erro(
            "Selecione uma categoria válida.",
            "membro"
        )

    if categoria in ("administrador", "master") and not eh_master:
        return renderizar_erro(
            "Somente um MASTER pode cadastrar administradores ou outros MASTER.",
            "membro"
        )

    categoria_banco = (
        "administrador"
        if categoria in ("administrador", "master")
        else "membro"
    )

    perfil_administrativo = (
        "master"
        if categoria == "master"
        else "administrador"
    )

    if categoria_banco == "administrador":

        if not usuario_admin or not senha_admin or not confirmar_senha:
            return renderizar_erro(
                "Preencha o usuário, a senha e a confirmação da senha."
            )

        if len(senha_admin) < 8:
            return renderizar_erro(
                "A senha deve possuir pelo menos 8 caracteres."
            )

        if senha_admin != confirmar_senha:
            return renderizar_erro(
                "As senhas informadas não coincidem."
            )

    conexao = None
    cursor = None
    id_idface = None
    id_usuario = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor()

        if categoria_banco == "administrador":
            cursor.execute(
                """
                SELECT id
                FROM administradores
                WHERE usuario = %s
                """,
                (usuario_admin,)
            )

            if cursor.fetchone():
                return renderizar_erro(
                    "Esse nome de usuário já está sendo utilizado."
                )

        cursor.execute(
            """
            INSERT INTO usuarios (nome, categoria)
            VALUES (%s, %s)
            """,
            (nome, categoria_banco)
        )

        id_usuario = cursor.lastrowid

        with IDFaceClient() as idface:
            id_idface = idface.cadastrar_usuario(
                id_usuario,
                nome
            )

            idface.definir_administrador(
                id_idface,
                categoria_banco == "administrador"
            )

        cursor.execute(
            """
            UPDATE usuarios
            SET id_idface = %s
            WHERE id = %s
            """,
            (id_idface, id_usuario)
        )

        if categoria_banco == "administrador":
            senha_hash = generate_password_hash(senha_admin)

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

        conexao.commit()

        if categoria == "master":
            descricao_categoria = "MASTER"
        elif categoria == "administrador":
            descricao_categoria = "Administrador"
        else:
            descricao_categoria = "Membro"

        print(
            f"Usuário cadastrado: {nome} | "
            f"Categoria: {descricao_categoria} | "
            f"MySQL: {id_usuario} | "
            f"iDFace: {id_idface}"
        )

        return redirect(url_for("usuarios"))

    except mysql.connector.IntegrityError as erro:

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

        print(
            f"Erro de integridade ao cadastrar usuário: {erro}",
            flush=True
        )

        return renderizar_erro(
            (
                "Não foi possível concluir o cadastro. "
                "Verifique se o nome de usuário já está em uso."
            )
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
                    "ATENÇÃO: falha ao remover o cadastro "
                    "incompleto do iDFace:",
                    erro_compensacao
                )

        print(f"Erro ao cadastrar usuário: {erro}", flush=True)

        return renderizar_erro(
            (
                "Não foi possível concluir o cadastro. "
                "Verifique a comunicação com o iDFace e o banco de dados."
            )
        )

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# ATUALIZAR FOTO FACIAL
# =====================================

@app.route("/usuarios/<int:id_usuario>/foto-facial", methods=["POST"])
def atualizar_foto_facial(id_usuario):
    """Atualiza a foto facial no iDFace e mantém uma cópia no MySQL."""

    if not administrador_logado():
        return redirect(url_for("login"))

    arquivo = request.files.get("foto_facial")

    if not arquivo or not arquivo.filename:
        flash("Selecione uma foto JPG para enviar.", "erro")
        return redirect(url_for("editar_usuario", id_usuario=id_usuario))

    # O endpoint de imagem do iDFace recebe a foto em formato binário.
    # Para manter compatibilidade com o formato já utilizado pelo projeto,
    # este envio aceita JPEG (JPG) e limita o arquivo a 5 MB.
    tamanho_maximo = 5 * 1024 * 1024
    imagem_bytes = arquivo.stream.read(tamanho_maximo + 1)

    if not imagem_bytes:
        flash("O arquivo selecionado está vazio.", "erro")
        return redirect(url_for("editar_usuario", id_usuario=id_usuario))

    if len(imagem_bytes) > tamanho_maximo:
        flash("A foto deve ter no máximo 5 MB.", "erro")
        return redirect(url_for("editar_usuario", id_usuario=id_usuario))

    if not (
        imagem_bytes.startswith(b"\xff\xd8\xff")
        and b"\xff\xd9" in imagem_bytes[-32:]
    ):
        flash("Formato inválido. Envie uma imagem JPG/JPEG válida.", "erro")
        return redirect(url_for("editar_usuario", id_usuario=id_usuario))

    conexao = None
    cursor = None
    foto_anterior = None
    id_idface = None
    nome_usuario = None
    timestamp_novo = int(time.time())
    imagem_base64 = base64.b64encode(imagem_bytes).decode("ascii")

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                u.id,
                u.nome,
                u.id_idface,
                u.categoria,
                u.ativo,
                a.id AS id_administrador,
                a.ativo AS administrador_ativo
            FROM usuarios u
            LEFT JOIN administradores a
                ON a.id_usuario = u.id
            WHERE u.id = %s
              AND u.ativo = 1
            LIMIT 1
            FOR UPDATE
            """,
            (id_usuario,)
        )

        usuario = cursor.fetchone()

        if not usuario or usuario["id_idface"] is None:
            conexao.rollback()
            flash("Usuário não encontrado ou sem vínculo com o iDFace.", "erro")
            return redirect(url_for("usuarios"))

        if usuario["categoria"] == "administrador":
            if (
                not master_logado()
                or not usuario["id_administrador"]
                or not usuario["administrador_ativo"]
            ):
                conexao.rollback()
                flash("Você não tem permissão para alterar esta foto facial.", "erro")
                return redirect(url_for("usuarios"))

        cursor.execute(
            """
            SELECT timestamp_foto, imagem
            FROM fotos_faciais
            WHERE id_usuario = %s
            LIMIT 1
            """,
            (id_usuario,)
        )
        foto_anterior = cursor.fetchone()

        # Garante timestamp crescente mesmo se duas fotos forem enviadas
        # dentro do mesmo segundo. O iDFace usa esse valor para versionar a imagem.
        if foto_anterior and foto_anterior.get("timestamp_foto") is not None:
            timestamp_novo = max(
                timestamp_novo,
                int(foto_anterior["timestamp_foto"]) + 1
            )

        id_idface = usuario["id_idface"]
        nome_usuario = usuario["nome"]

        # Primeiro atualiza o equipamento. Só grava a nova cópia local
        # depois que o iDFace confirmar o recebimento da imagem.
        with IDFaceClient() as idface:
            idface.restaurar_foto_usuario(
                id_idface,
                timestamp_novo,
                imagem_base64
            )

        if foto_anterior:
            cursor.execute(
                """
                UPDATE fotos_faciais
                SET timestamp_foto = %s,
                    imagem = %s
                WHERE id_usuario = %s
                """,
                (timestamp_novo, imagem_base64, id_usuario)
            )
        else:
            cursor.execute(
                """
                INSERT INTO fotos_faciais
                    (id_usuario, timestamp_foto, imagem)
                VALUES (%s, %s, %s)
                """,
                (id_usuario, timestamp_novo, imagem_base64)
            )

        conexao.commit()

        print(
            f"Foto facial atualizada: {nome_usuario} | "
            f"MySQL: {id_usuario} | iDFace: {id_idface}",
            flush=True
        )

        flash("Foto facial atualizada com sucesso no iDFace e no MySQL.", "sucesso")
        return redirect(url_for("editar_usuario", id_usuario=id_usuario))

    except (IDFaceError, mysql.connector.Error) as erro:
        if conexao:
            conexao.rollback()

        print(
            f"Erro ao atualizar foto facial do usuário {id_usuario}: {erro}",
            flush=True
        )

        # Se o iDFace já recebeu a nova foto, tenta restaurar a versão
        # anterior caso a gravação no MySQL tenha falhado.
        if id_idface is not None and foto_anterior:
            try:
                with IDFaceClient() as idface:
                    idface.restaurar_foto_usuario(
                        id_idface,
                        foto_anterior["timestamp_foto"],
                        foto_anterior["imagem"]
                    )
            except IDFaceError as erro_compensacao:
                print(
                    "ATENÇÃO: não foi possível restaurar a foto anterior "
                    f"no iDFace: {erro_compensacao}",
                    flush=True
                )

        flash(
            "Não foi possível atualizar a foto facial. "
            "Verifique a comunicação com o iDFace e o banco de dados.",
            "erro"
        )
        return redirect(url_for("editar_usuario", id_usuario=id_usuario))

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# EDITAR USUARIO / ADMINISTRADOR / MASTER
# =====================================

@app.route("/usuarios/editar/<int:id_usuario>", methods=["GET", "POST"])
def editar_usuario(id_usuario):

    if not administrador_logado():
        return redirect(url_for("login"))

    conexao = None
    cursor = None
    usuario = None

    eh_master = master_logado()
    idface_alterado = False
    nome_anterior = None
    permissao_anterior = False

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
                u.ativo,
                a.id AS id_administrador,
                a.usuario AS usuario_admin,
                a.perfil AS perfil_administrativo,
                a.ativo AS administrador_ativo,
                a.senha_hash
            FROM usuarios u
            LEFT JOIN administradores a
                ON a.id_usuario = u.id
            WHERE u.id = %s
              AND u.ativo = 1
            LIMIT 1
            FOR UPDATE
            """,
            (id_usuario,)
        )

        usuario = cursor.fetchone()

        if not usuario:
            return redirect(url_for("usuarios"))

        foto_facial = obter_foto_facial_data_uri(cursor, id_usuario)

        eh_administrador = usuario["categoria"] == "administrador"
        possui_vinculo_administrativo = bool(
            usuario["id_administrador"]
        )

        if eh_administrador:
            if (
                not eh_master
                or not possui_vinculo_administrativo
                or not usuario["administrador_ativo"]
            ):
                return redirect(url_for("usuarios"))

        elif possui_vinculo_administrativo:
            return redirect(url_for("usuarios"))

        if request.method == "GET":
            categoria_selecionada = (
                usuario["perfil_administrativo"]
                if eh_administrador
                else "membro"
            )

            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                perfil_logado=perfil_logado(),
                master_logado=eh_master,
                usuario_admin=usuario.get("usuario_admin") or "",
                categoria_selecionada=categoria_selecionada,
                eh_administrador=eh_administrador,
                conta_administrativa_existente=eh_administrador,
                foto_facial=foto_facial
            )

        nome = request.form.get("nome", "").strip()
        usuario_admin = request.form.get(
            "usuario_admin",
            ""
        ).strip()
        senha_admin = request.form.get("senha_admin", "")
        confirmar_senha = request.form.get(
            "confirmar_senha",
            ""
        )

        # Somente MASTER pode modificar o cargo.
        if eh_master:
            categoria = request.form.get(
                "categoria",
                "membro"
            ).strip().lower()
        else:
            categoria = (
                "administrador"
                if eh_administrador
                else "membro"
            )

        def renderizar_erro(mensagem, categoria_form=None):
            usuario["nome"] = nome or usuario["nome"]
            usuario["usuario_admin"] = usuario_admin

            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                perfil_logado=perfil_logado(),
                master_logado=eh_master,
                usuario_admin=usuario_admin,
                categoria_selecionada=(
                    categoria_form
                    if categoria_form is not None
                    else categoria
                ),
                eh_administrador=eh_administrador,
                conta_administrativa_existente=eh_administrador,
                foto_facial=foto_facial,
                erro=mensagem
            )

        if not nome:
            return renderizar_erro(
                "Informe o nome do usuário."
            )

        if categoria not in ("membro", "administrador", "master"):
            return renderizar_erro(
                "Selecione um cargo válido.",
                (
                    usuario["perfil_administrativo"]
                    if eh_administrador
                    else "membro"
                )
            )

        if not eh_master and categoria != (
            "administrador" if eh_administrador else "membro"
        ):
            return renderizar_erro(
                "Somente um MASTER pode alterar o cargo de uma conta."
            )

        categoria_banco = (
            "membro"
            if categoria == "membro"
            else "administrador"
        )

        sera_administrador = categoria_banco == "administrador"

        perfil_administrativo = (
            "master"
            if categoria == "master"
            else "administrador"
        )

        if sera_administrador:
            if not usuario_admin:
                return renderizar_erro(
                    "Informe o nome de usuário para acesso ao painel.",
                    categoria
                )

            if not eh_administrador and not senha_admin:
                return renderizar_erro(
                    "Informe uma senha para a nova conta administrativa.",
                    categoria
                )

            if senha_admin:
                if len(senha_admin) < 8:
                    return renderizar_erro(
                        "A senha deve possuir pelo menos 8 caracteres.",
                        categoria
                    )

                if senha_admin != confirmar_senha:
                    return renderizar_erro(
                        "As senhas informadas não coincidem.",
                        categoria
                    )

            elif confirmar_senha:
                return renderizar_erro(
                    "Para confirmar uma nova senha, informe também a senha.",
                    categoria
                )

            cursor.execute(
                """
                SELECT id
                FROM administradores
                WHERE usuario = %s
                  AND id_usuario <> %s
                LIMIT 1
                """,
                (usuario_admin, id_usuario)
            )

            if cursor.fetchone():
                return renderizar_erro(
                    "Esse nome de usuário já está sendo utilizado.",
                    categoria
                )

        if usuario["id_idface"] is None:
            return renderizar_erro(
                (
                    "Este usuário ainda não está associado ao iDFace. "
                    "A edição está bloqueada até regularizarmos essa associação."
                ),
                categoria
            )

        id_administrador_existente = usuario.get(
            "id_administrador"
        )

        perfil_anterior = (
            usuario.get("perfil_administrativo")
            if eh_administrador
            else None
        )

        id_administrador_logado = session.get("admin_id")

        # Impede que o administrador atual rebaixe a própria conta.
        if (
            eh_administrador
            and id_administrador_existente == id_administrador_logado
            and (
                not sera_administrador
                or perfil_administrativo != perfil_anterior
            )
        ):
            return renderizar_erro(
                "Você não pode rebaixar ou alterar o próprio perfil administrativo.",
                perfil_anterior
            )

        # Protege o último administrador ativo.
        if eh_administrador and not sera_administrador:
            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM administradores a
                INNER JOIN usuarios u
                    ON u.id = a.id_usuario
                WHERE a.ativo = TRUE
                  AND u.ativo = TRUE
                  AND u.categoria = 'administrador'
                """
            )

            total_administradores = cursor.fetchone()["total"]

            if total_administradores <= 1:
                return renderizar_erro(
                    "Não é possível rebaixar o último administrador ativo.",
                    perfil_anterior
                )

        # Protege o último MASTER, inclusive quando ele seria
        # transformado em administrador comum.
        if (
            eh_administrador
            and perfil_anterior == "master"
            and perfil_administrativo != "master"
        ):
            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM administradores a
                INNER JOIN usuarios u
                    ON u.id = a.id_usuario
                WHERE a.ativo = TRUE
                  AND u.ativo = TRUE
                  AND u.categoria = 'administrador'
                  AND a.perfil = 'master'
                """
            )

            total_masters = cursor.fetchone()["total"]

            if total_masters <= 1:
                return renderizar_erro(
                    "Não é possível rebaixar o último MASTER ativo.",
                    "master"
                )

        nome_anterior = usuario["nome"]
        permissao_anterior = eh_administrador
        id_idface = usuario["id_idface"]

        try:
            # Marca a alteração antes da primeira operação no iDFace.
            # Assim, se a segunda operação falhar, o nome também será restaurado.
            with IDFaceClient() as idface:
                idface_alterado = True

                idface.editar_usuario(id_idface, nome)

                idface.definir_administrador(
                    id_idface,
                    sera_administrador
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

            if sera_administrador:
                if id_administrador_existente:
                    if senha_admin:
                        senha_hash = generate_password_hash(
                            senha_admin
                        )

                        cursor.execute(
                            """
                            UPDATE administradores
                            SET nome = %s,
                                usuario = %s,
                                senha_hash = %s,
                                perfil = %s,
                                ativo = TRUE
                            WHERE id = %s
                              AND id_usuario = %s
                            """,
                            (
                                nome,
                                usuario_admin,
                                senha_hash,
                                perfil_administrativo,
                                id_administrador_existente,
                                id_usuario
                            )
                        )
                    else:
                        cursor.execute(
                            """
                            UPDATE administradores
                            SET nome = %s,
                                usuario = %s,
                                perfil = %s,
                                ativo = TRUE
                            WHERE id = %s
                              AND id_usuario = %s
                            """,
                            (
                                nome,
                                usuario_admin,
                                perfil_administrativo,
                                id_administrador_existente,
                                id_usuario
                            )
                        )

                else:
                    senha_hash = generate_password_hash(
                        senha_admin
                    )

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

            elif id_administrador_existente:
                cursor.execute(
                    """
                    DELETE FROM administradores
                    WHERE id = %s
                      AND id_usuario = %s
                    """,
                    (
                        id_administrador_existente,
                        id_usuario
                    )
                )

                if cursor.rowcount == 0:
                    raise mysql.connector.Error(
                        "Não foi possível remover o vínculo administrativo."
                    )

            conexao.commit()

            # Atualiza a sessão caso o MASTER tenha editado o próprio nome.
            if (
                id_administrador_existente
                and id_administrador_existente == id_administrador_logado
                and sera_administrador
            ):
                session["admin_nome"] = nome
                session["admin_perfil"] = perfil_administrativo

            print(
                f"Usuário atualizado: {nome} | "
                f"Categoria: {categoria} | "
                f"MySQL: {id_usuario} | "
                f"iDFace: {id_idface}",
                flush=True
            )

            return redirect(url_for("usuarios"))

        except (IDFaceError, mysql.connector.Error) as erro:
            conexao.rollback()

            print(
                f"Erro ao atualizar usuário: {erro}",
                flush=True
            )

            # Restaura o nome e a permissão que existiam antes da operação.
            if idface_alterado:
                try:
                    with IDFaceClient() as idface:
                        idface.editar_usuario(
                            id_idface,
                            nome_anterior
                        )
                        idface.definir_administrador(
                            id_idface,
                            permissao_anterior
                        )

                except IDFaceError as erro_compensacao:
                    print(
                        "ATENÇÃO: não foi possível restaurar "
                        "os dados anteriores no iDFace:",
                        erro_compensacao,
                        flush=True
                    )

            return renderizar_erro(
                (
                    "Não foi possível concluir a atualização. "
                    "Verifique a comunicação com o iDFace e o banco de dados."
                ),
                categoria
            )

    except mysql.connector.IntegrityError as erro:
        if conexao:
            conexao.rollback()

        print(
            f"Erro de integridade ao editar usuário: {erro}",
            flush=True
        )

        if usuario:
            usuario["nome"] = request.form.get(
                "nome",
                usuario["nome"]
            ).strip()

            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                perfil_logado=perfil_logado(),
                master_logado=eh_master,
                usuario_admin=request.form.get(
                    "usuario_admin",
                    usuario.get("usuario_admin") or ""
                ).strip(),
                categoria_selecionada=request.form.get(
                    "categoria",
                    usuario.get("perfil_administrativo") or "membro"
                ),
                eh_administrador=(
                    usuario["categoria"] == "administrador"
                ),
                conta_administrativa_existente=(
                    usuario["categoria"] == "administrador"
                ),
                foto_facial=foto_facial,
                erro="Esse nome de usuário já está sendo utilizado."
            )

        return redirect(url_for("usuarios"))

    except mysql.connector.Error as erro:
        if conexao:
            conexao.rollback()

        print(
            f"Erro ao consultar usuário para edição: {erro}",
            flush=True
        )

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

    return redirect(url_for("usuarios"))


# =====================================
# COMPATIBILIDADE COM A ROTA ANTIGA
# =====================================

@app.route(
    "/administradores/editar/<int:id_administrador>",
    methods=["GET", "POST"]
)
def editar_administrador(id_administrador):

    if not administrador_logado():
        return redirect(url_for("login"))

    if not master_logado():
        return redirect(url_for("painel"))

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor()

        cursor.execute(
            """
            SELECT id_usuario
            FROM administradores
            WHERE id = %s
              AND ativo = TRUE
            LIMIT 1
            """,
            (id_administrador,)
        )

        resultado = cursor.fetchone()

        if not resultado:
            return redirect(url_for("usuarios"))

        id_usuario = resultado[0]

        return redirect(
            url_for(
                "editar_usuario",
                id_usuario=id_usuario
            )
        )

    except mysql.connector.Error as erro:
        print(
            f"Erro ao localizar administrador para edição: {erro}",
            flush=True
        )
        return redirect(url_for("usuarios"))

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

    if id_administrador == session.get("admin_id"):
        print(
            "Exclusão bloqueada: tentativa de autoexclusão."
        )
        return redirect(url_for("usuarios"))

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

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
                a.perfil,
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
            return redirect(url_for("usuarios"))

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

                return redirect(url_for("usuarios"))

            if administrador["perfil"] == "master":
                cursor.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM administradores a
                    INNER JOIN usuarios u
                        ON u.id = a.id_usuario
                    WHERE a.ativo = TRUE
                      AND u.ativo = TRUE
                      AND u.categoria = 'administrador'
                      AND a.perfil = 'master'
                    """
                )

                total_masters = cursor.fetchone()["total"]

                if total_masters <= 1:
                    conexao.rollback()

                    print(
                        "Exclusão bloqueada: não é permitido "
                        "excluir o último MASTER ativo."
                    )

                    return redirect(url_for("usuarios"))

        id_usuario = administrador["id_usuario"]
        id_idface = administrador["id_idface"]
        nome = administrador["nome"]

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

            return redirect(url_for("usuarios"))

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

            return redirect(url_for("usuarios"))

        conexao.commit()

        print(
            f"Administrador excluído integralmente: {nome} | "
            f"MySQL: {id_usuario} | "
            "Categoria: membro | "
            "Ativo: 0 | "
            "Conta administrativa removida | "
            "Histórico preservado."
        )

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

        return redirect(url_for("usuarios"))

    except mysql.connector.Error as erro:

        if conexao:
            conexao.rollback()

        print(f"Erro ao excluir administrador: {erro}")

        return redirect(url_for("usuarios"))

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
