
from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from werkzeug.security import check_password_hash, generate_password_hash
from threading import Thread
import os

from idface import IDFaceClient, IDFaceError
from servidor import iniciar_servidor
import config


app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY


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
    return "admin_id" in session


def contar_administradores_ativos(cursor):
    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM administradores
        WHERE ativo = TRUE
        """
    )

    resultado = cursor.fetchone()
    return resultado["total"]


# =====================================
# PAGINA DE LOGIN
# =====================================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        usuario = request.form.get("usuario", "").strip()
        senha = request.form.get("senha", "")

        conexao = None
        cursor = None

        try:
            conexao = conectar_banco()
            cursor = conexao.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT id, nome, usuario, senha_hash
                FROM administradores
                WHERE usuario = %s AND ativo = TRUE
                """,
                (usuario,)
            )

            administrador = cursor.fetchone()

            if administrador and check_password_hash(
                administrador["senha_hash"], senha
            ):
                session.clear()
                session["admin_id"] = administrador["id"]
                session["admin_nome"] = administrador["nome"]

                return redirect(url_for("painel"))

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

        cursor.execute(
            """
            SELECT id, nome, categoria, id_idface
            FROM usuarios
            ORDER BY nome ASC
            """
        )

        lista_usuarios = cursor.fetchall()

        return render_template(
            "usuarios.html",
            usuarios=lista_usuarios
        )

    except mysql.connector.Error as erro:
        print(f"Erro ao consultar usuários: {erro}")

        return render_template(
            "usuarios.html",
            usuarios=[],
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
    categoria = request.form.get("categoria", "").strip()

    if not nome:
        return render_template(
            "novo_usuario.html",
            erro="Informe o nome do usuário.",
            nome=nome,
            categoria=categoria
        )

    if categoria not in ["membro", "administrador"]:
        return render_template(
            "novo_usuario.html",
            erro="Selecione uma categoria válida.",
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
                categoria == "administrador"
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
            SELECT id, nome, categoria, id_idface
            FROM usuarios
            WHERE id = %s
            """,
            (id_usuario,)
        )

        usuario = cursor.fetchone()

        if not usuario:
            return redirect(url_for("usuarios"))

        if request.method == "GET":
            return render_template(
                "editar_usuario.html",
                usuario=usuario
            )

        nome = request.form.get("nome", "").strip()
        categoria = request.form.get("categoria", "").strip()

        if not nome:
            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                erro="Informe o nome do usuário."
            )

        if categoria not in ["membro", "administrador"]:
            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                erro="Selecione uma categoria válida."
            )

        if usuario["id_idface"] is None:
            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                erro=(
                    "Este usuário ainda não está associado ao iDFace. "
                    "A edição está bloqueada até regularizarmos essa associação."
                )
            )

        nome_anterior = usuario["nome"]
        categoria_anterior = usuario["categoria"]
        id_idface = usuario["id_idface"]

        try:
            with IDFaceClient() as idface:

                idface.editar_usuario(
                    id_idface,
                    nome
                )

                idface.definir_administrador(
                    id_idface,
                    categoria == "administrador"
                )

            cursor.execute(
                """
                UPDATE usuarios
                SET nome = %s, categoria = %s
                WHERE id = %s
                """,
                (nome, categoria, id_usuario)
            )

            conexao.commit()

            print(
                f"Usuário atualizado: {nome} | "
                f"MySQL: {id_usuario} | "
                f"iDFace: {id_idface}"
            )

            return redirect(url_for("usuarios"))

        except (IDFaceError, mysql.connector.Error) as erro:

            conexao.rollback()

            print(f"Erro ao atualizar usuário: {erro}")

            try:
                with IDFaceClient() as idface:

                    idface.editar_usuario(
                        id_idface,
                        nome_anterior
                    )

                    idface.definir_administrador(
                        id_idface,
                        categoria_anterior == "administrador"
                    )

            except IDFaceError as erro_compensacao:
                print(
                    "ATENÇÃO: não foi possível restaurar "
                    "os dados anteriores no iDFace:",
                    erro_compensacao
                )

            usuario["nome"] = nome
            usuario["categoria"] = categoria

            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                erro=(
                    "Não foi possível concluir a atualização. "
                    "Verifique o equipamento e o banco de dados."
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
            SELECT id, nome, id_idface
            FROM usuarios
            WHERE id = %s
            """,
            (id_usuario,)
        )

        usuario = cursor.fetchone()

        if not usuario:
            return redirect(url_for("usuarios"))

        if usuario["id_idface"] is not None:

            with IDFaceClient() as idface:
                idface.excluir_usuario(
                    usuario["id_idface"]
                )

        cursor.execute(
            """
            DELETE FROM usuarios
            WHERE id = %s
            """,
            (id_usuario,)
        )

        conexao.commit()

        print(
            f"Usuário excluído: {usuario['nome']} | "
            f"MySQL: {id_usuario} | "
            f"iDFace: {usuario['id_idface']}"
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
                "do iDFace, mas sua exclusão no MySQL falhou. "
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
                nome,
                usuario,
                ativo,
                data_cadastro
            FROM administradores
            ORDER BY nome ASC
            """
        )

        lista_administradores = cursor.fetchall()

        return render_template(
            "administradores.html",
            administradores=lista_administradores
        )

    except mysql.connector.Error as erro:

        print(f"Erro ao consultar administradores: {erro}")

        return render_template(
            "administradores.html",
            administradores=[],
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

    if not administrador_logado():
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("novo_administrador.html")

    nome = request.form.get("nome", "").strip()
    usuario = request.form.get("usuario", "").strip()
    senha = request.form.get("senha", "")
    confirmar_senha = request.form.get("confirmar_senha", "")

    if not nome or not usuario or not senha:
        return render_template(
            "novo_administrador.html",
            erro="Preencha todos os campos.",
            nome=nome,
            usuario=usuario
        )

    if len(senha) < 8:
        return render_template(
            "novo_administrador.html",
            erro="A senha deve possuir pelo menos 8 caracteres.",
            nome=nome,
            usuario=usuario
        )

    if senha != confirmar_senha:
        return render_template(
            "novo_administrador.html",
            erro="As senhas informadas não coincidem.",
            nome=nome,
            usuario=usuario
        )

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor()

        senha_hash = generate_password_hash(senha)

        cursor.execute(
            """
            INSERT INTO administradores
                (nome, usuario, senha_hash, ativo)
            VALUES (%s, %s, %s, TRUE)
            """,
            (nome, usuario, senha_hash)
        )

        conexao.commit()

        print(f"Administrador cadastrado: {usuario}")

        return redirect(url_for("administradores"))

    except mysql.connector.IntegrityError as erro:

        if conexao:
            conexao.rollback()

        print(f"Erro de integridade ao cadastrar administrador: {erro}")

        return render_template(
            "novo_administrador.html",
            erro="Esse nome de usuário já está sendo utilizado.",
            nome=nome,
            usuario=usuario
        )

    except mysql.connector.Error as erro:

        if conexao:
            conexao.rollback()

        print(f"Erro ao cadastrar administrador: {erro}")

        return render_template(
            "novo_administrador.html",
            erro="Não foi possível cadastrar o administrador.",
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

    if not administrador_logado():
        return redirect(url_for("login"))

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, nome, usuario, ativo
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
                administrador=administrador
            )

        nome = request.form.get("nome", "").strip()
        usuario = request.form.get("usuario", "").strip()
        senha = request.form.get("senha", "")
        confirmar_senha = request.form.get("confirmar_senha", "")

        if not nome or not usuario:
            return render_template(
                "editar_administrador.html",
                administrador=administrador,
                erro="Nome e usuário são obrigatórios."
            )

        if senha and len(senha) < 8:
            return render_template(
                "editar_administrador.html",
                administrador=administrador,
                erro="A nova senha deve possuir pelo menos 8 caracteres."
            )

        if senha and senha != confirmar_senha:
            return render_template(
                "editar_administrador.html",
                administrador=administrador,
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
            erro="Esse nome de usuário já está sendo utilizado."
        )

    except mysql.connector.Error as erro:

        if conexao:
            conexao.rollback()

        print(f"Erro ao editar administrador: {erro}")

        return render_template(
            "editar_administrador.html",
            administrador=administrador,
            erro="Não foi possível atualizar o administrador."
        )

    finally:
        if cursor:
            cursor.close()

        if conexao and conexao.is_connected():
            conexao.close()


# =====================================
# ATIVAR / DESATIVAR ADMINISTRADOR
# =====================================

@app.route(
    "/administradores/status/<int:id_administrador>",
    methods=["POST"]
)
def alterar_status_administrador(id_administrador):

    if not administrador_logado():
        return redirect(url_for("login"))

    # Impede que o administrador desative a própria conta.
    if id_administrador == session.get("admin_id"):
        return redirect(url_for("administradores"))

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, ativo
            FROM administradores
            WHERE id = %s
            """,
            (id_administrador,)
        )

        administrador = cursor.fetchone()

        if not administrador:
            return redirect(url_for("administradores"))

        novo_status = not bool(administrador["ativo"])

        # Impede desativar o último administrador ativo.
        if not novo_status:
            total_ativos = contar_administradores_ativos(cursor)

            if total_ativos <= 1:
                return redirect(url_for("administradores"))

        cursor.execute(
            """
            UPDATE administradores
            SET ativo = %s
            WHERE id = %s
            """,
            (novo_status, id_administrador)
        )

        conexao.commit()

        print(
            f"Status do administrador {id_administrador}: "
            f"{'ativo' if novo_status else 'inativo'}"
        )

        return redirect(url_for("administradores"))

    except mysql.connector.Error as erro:

        if conexao:
            conexao.rollback()

        print(f"Erro ao alterar status do administrador: {erro}")

        return redirect(url_for("administradores"))

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

    if not administrador_logado():
        return redirect(url_for("login"))

    # Impede que o administrador exclua a própria conta.
    if id_administrador == session.get("admin_id"):
        return redirect(url_for("administradores"))

    conexao = None
    cursor = None

    try:
        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, nome, ativo
            FROM administradores
            WHERE id = %s
            """,
            (id_administrador,)
        )

        administrador = cursor.fetchone()

        if not administrador:
            return redirect(url_for("administradores"))

        # Impede excluir o último administrador ativo.
        if administrador["ativo"]:
            total_ativos = contar_administradores_ativos(cursor)

            if total_ativos <= 1:
                return redirect(url_for("administradores"))

        cursor.execute(
            """
            DELETE FROM administradores
            WHERE id = %s
            """,
            (id_administrador,)
        )

        conexao.commit()

        print(
            f"Administrador excluído: {administrador['nome']}"
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
        not app.debug
        or os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    ):
        iniciar_sincronizacao()

    app.run(debug=True)
