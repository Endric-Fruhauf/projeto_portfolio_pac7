
from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from werkzeug.security import check_password_hash
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

        # Pesquisa pelo nome do usuário
        if pesquisa:
            consulta += """
                AND u.nome LIKE %s
            """
            parametros.append(f"%{pesquisa}%")

        # Filtro pela data inicial
        if data_inicio:
            consulta += """
                AND DATE(r.data_hora) >= %s
            """
            parametros.append(data_inicio)

        # Filtro pela data final
        if data_fim:
            consulta += """
                AND DATE(r.data_hora) <= %s
            """
            parametros.append(data_fim)

        # Ordenar do mais recente para o mais antigo
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

        # 1. Criar o cadastro no MySQL.
        cursor.execute(
            """
            INSERT INTO usuarios (nome, categoria)
            VALUES (%s, %s)
            """,
            (nome, categoria)
        )

        id_usuario = cursor.lastrowid

        # 2. Criar o usuário no iDFace.
        with IDFaceClient() as idface:

            id_idface = idface.cadastrar_usuario(
                id_usuario,
                nome
            )

            # 3. Configurar o privilégio no equipamento.
            idface.definir_administrador(
                id_idface,
                categoria == "administrador"
            )

        # 4. Associar os identificadores.
        cursor.execute(
            """
            UPDATE usuarios
            SET id_idface = %s
            WHERE id = %s
            """,
            (id_idface, id_usuario)
        )

        # 5. Confirmar o cadastro no MySQL.
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
