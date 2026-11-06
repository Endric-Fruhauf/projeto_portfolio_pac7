import os
import base64
import unicodedata
import requests
import config


class IDFaceError(Exception):
    """Erro na comunicação ou operação com o iDFace."""
    pass


class IDFaceClient:

    def __init__(self):
        self.base_url = f"https://{config.IDFACE_IP}"

        diretorio_projeto = os.path.dirname(os.path.abspath(__file__))

        self.certificado = os.path.join(
            diretorio_projeto,
            "certificados",
            "idface_certificado.pem"
        )

        self.session = None

        if not os.path.isfile(self.certificado):
            raise IDFaceError(
                f"Certificado do iDFace não encontrado: {self.certificado}"
            )

    @staticmethod
    def _validar_lista_resposta(resultado, campo, operacao):
        """
        Valida se a resposta contém o campo esperado
        e se seu conteúdo é uma lista de objetos.
        """

        if not isinstance(resultado, dict):
            raise IDFaceError(
                f"Resposta inválida do iDFace durante {operacao}."
            )

        if campo not in resultado:
            raise IDFaceError(
                f"O iDFace não retornou o campo '{campo}' durante {operacao}."
            )

        dados = resultado[campo]

        if not isinstance(dados, list):
            raise IDFaceError(
                f"O campo '{campo}' retornado pelo iDFace "
                f"não é uma lista válida durante {operacao}."
            )

        if not all(isinstance(item, dict) for item in dados):
            raise IDFaceError(
                f"O iDFace retornou registros inválidos durante {operacao}."
            )

        return dados

    @staticmethod
    def _validar_lista_ids(resultado, campo, operacao):
        """
        Valida listas de IDs numéricos retornadas pelo iDFace.
        """

        if not isinstance(resultado, dict):
            raise IDFaceError(
                f"Resposta inválida do iDFace durante {operacao}."
            )

        if campo not in resultado:
            raise IDFaceError(
                f"O iDFace não retornou o campo '{campo}' durante {operacao}."
            )

        ids = resultado[campo]

        if not isinstance(ids, list):
            raise IDFaceError(
                f"O campo '{campo}' não é uma lista válida durante {operacao}."
            )

        if not all(
            isinstance(item, int) and not isinstance(item, bool)
            for item in ids
        ):
            raise IDFaceError(
                f"O iDFace retornou IDs inválidos durante {operacao}."
            )

        return ids

    @staticmethod
    def _normalizar_nome_departamento(nome):
        """
        Normaliza o nome para comparar departamentos
        sem diferenças de maiúsculas, minúsculas ou acentos.
        """

        nome = str(nome or "").strip().casefold()

        return "".join(
            caractere
            for caractere in unicodedata.normalize("NFD", nome)
            if unicodedata.category(caractere) != "Mn"
        )

    def conectar(self):
        try:
            resposta = requests.post(
                f"{self.base_url}/login.fcgi",
                json={
                    "login": config.IDFACE_USUARIO,
                    "password": config.IDFACE_SENHA
                },
                verify=self.certificado,
                timeout=10
            )

            resposta.raise_for_status()

            resultado = resposta.json()

            if not isinstance(resultado, dict):
                raise IDFaceError(
                    "O iDFace retornou uma resposta inválida durante o login."
                )

            self.session = resultado.get("session")

            if not self.session:
                raise IDFaceError(
                    "O iDFace não retornou uma sessão válida."
                )

        except requests.exceptions.SSLError as erro:
            raise IDFaceError(
                f"Falha na validação SSL do iDFace: {erro}"
            )

        except requests.exceptions.RequestException as erro:
            raise IDFaceError(
                f"Não foi possível conectar ao iDFace: {erro}"
            )

        except ValueError:
            raise IDFaceError(
                "O iDFace retornou uma resposta inválida durante o login."
            )

    def desconectar(self):
        if self.session:
            try:
                requests.post(
                    f"{self.base_url}/logout.fcgi",
                    params={"session": self.session},
                    verify=self.certificado,
                    timeout=5
                )

            except requests.exceptions.RequestException:
                pass

            finally:
                self.session = None

    def requisicao(self, endpoint, dados):
        if not self.session:
            raise IDFaceError("Não existe uma sessão ativa.")

        try:
            resposta = requests.post(
                f"{self.base_url}/{endpoint}",
                params={"session": self.session},
                json=dados,
                verify=self.certificado,
                timeout=10
            )

            if not resposta.ok:
                corpo_resposta = (resposta.text or "").strip()

                if len(corpo_resposta) > 1000:
                    corpo_resposta = corpo_resposta[:1000] + "..."

                if not corpo_resposta:
                    corpo_resposta = "(resposta vazia)"

                raise IDFaceError(
                    f"Erro HTTP {resposta.status_code} "
                    f"{resposta.reason} na operação {endpoint}. "
                    f"Resposta do iDFace: {corpo_resposta}"
                )

            resultado = resposta.json()

            if not isinstance(resultado, dict):
                raise IDFaceError(
                    f"Resposta inválida do iDFace em {endpoint}."
                )

            if "error" in resultado:
                raise IDFaceError(str(resultado["error"]))

            return resultado

        except IDFaceError:
            raise

        except requests.exceptions.SSLError as erro:
            raise IDFaceError(
                f"Falha na validação SSL durante {endpoint}: {erro}"
            )

        except requests.exceptions.RequestException as erro:
            raise IDFaceError(
                f"Erro na operação {endpoint}: {erro}"
            )

        except ValueError:
            raise IDFaceError(
                f"Resposta inválida do iDFace em {endpoint}."
            )

    def consultar_usuarios(self):
        resultado = self.requisicao(
            "load_objects.fcgi",
            {"object": "users"}
        )

        return self._validar_lista_resposta(
            resultado,
            "users",
            "consulta de usuários"
        )

    def consultar_privilegios(self):
        resultado = self.requisicao(
            "load_objects.fcgi",
            {"object": "user_roles"}
        )

        return self._validar_lista_resposta(
            resultado,
            "user_roles",
            "consulta de permissões"
        )

    def consultar_departamentos(self):
        """
        Consulta os departamentos cadastrados no iDFace.

        Na API Control iD, os departamentos são representados
        pelo objeto 'groups'.
        """

        resultado = self.requisicao(
            "load_objects.fcgi",
            {"object": "groups"}
        )

        return self._validar_lista_resposta(
            resultado,
            "groups",
            "consulta de departamentos"
        )

    def associar_departamento_padrao(self, id_idface):
        """
        Associa o usuário ao departamento PADRÃO.

        O ID do departamento é consultado dinamicamente,
        evitando depender de um ID fixo no equipamento.

        Também verifica se o vínculo já existe para
        evitar associações duplicadas.
        """

        try:
            id_idface = int(id_idface)

        except (ValueError, TypeError):
            raise IDFaceError(
                "O ID do usuário é inválido para associação ao departamento."
            )

        departamentos = self.consultar_departamentos()

        nome_padrao = self._normalizar_nome_departamento("PADRÃO")

        departamentos_padrao = [
            departamento
            for departamento in departamentos
            if self._normalizar_nome_departamento(
                departamento.get("name")
            ) == nome_padrao
        ]

        if not departamentos_padrao:
            raise IDFaceError(
                "O departamento PADRÃO não foi encontrado no iDFace. "
                "Verifique se ele existe no equipamento."
            )

        if len(departamentos_padrao) > 1:
            raise IDFaceError(
                "Foi encontrado mais de um departamento PADRÃO no iDFace. "
                "Não foi possível determinar qual deve ser utilizado."
            )

        try:
            id_departamento = int(departamentos_padrao[0]["id"])

        except (KeyError, ValueError, TypeError):
            raise IDFaceError(
                "O iDFace retornou um ID inválido para o departamento PADRÃO."
            )

        resultado = self.requisicao(
            "load_objects.fcgi",
            {"object": "user_groups"}
        )

        vinculos = self._validar_lista_resposta(
            resultado,
            "user_groups",
            "consulta de vínculos entre usuários e departamentos"
        )

        ja_associado = any(
            str(vinculo.get("user_id")) == str(id_idface)
            and str(vinculo.get("group_id")) == str(id_departamento)
            for vinculo in vinculos
        )

        if ja_associado:
            return True

        self.requisicao(
            "create_objects.fcgi",
            {
                "object": "user_groups",
                "values": [
                    {
                        "user_id": id_idface,
                        "group_id": id_departamento
                    }
                ]
            }
        )

        return True

    def consultar_fotos_usuarios(self, ids_usuarios):
        """
        Consulta fotos faciais de até 100 usuários por requisição.
        Retorna os dados em Base64 e o timestamp de cada foto.
        """

        if not self.session:
            raise IDFaceError("Não existe uma sessão ativa.")

        if not ids_usuarios:
            return []

        try:
            resposta = requests.post(
                f"{self.base_url}/user_get_image_list.fcgi",
                params={"session": self.session},
                json={"user_ids": ids_usuarios},
                verify=self.certificado,
                timeout=30
            )

            resposta.raise_for_status()

            resultado = resposta.json()

            if not isinstance(resultado, dict):
                raise IDFaceError(
                    "Resposta inválida ao consultar fotos faciais."
                )

            if "error" in resultado:
                raise IDFaceError(str(resultado["error"]))

            return self._validar_lista_resposta(
                resultado,
                "user_images",
                "consulta de fotos faciais"
            )

        except IDFaceError:
            raise

        except requests.exceptions.SSLError as erro:
            raise IDFaceError(
                f"Falha na validação SSL ao consultar fotos: {erro}"
            )

        except requests.exceptions.RequestException as erro:
            raise IDFaceError(
                f"Erro ao consultar fotos faciais: {erro}"
            )

        except ValueError:
            raise IDFaceError(
                "Resposta inválida ao consultar fotos faciais."
            )

    def restaurar_foto_usuario(
        self,
        id_idface,
        timestamp,
        imagem_base64
    ):
        """
        Restaura a foto facial de um usuário já cadastrado.
        A imagem é enviada em binário, conforme a API Control iD.
        """

        if not self.session:
            raise IDFaceError("Não existe uma sessão ativa.")

        if not imagem_base64:
            raise IDFaceError("A cópia da foto facial está vazia.")

        try:
            imagem_bytes = base64.b64decode(
                imagem_base64,
                validate=True
            )

            if not imagem_bytes:
                raise IDFaceError("A imagem facial está vazia.")

            resposta = requests.post(
                f"{self.base_url}/user_set_image.fcgi",
                params={
                    "session": self.session,
                    "user_id": int(id_idface),
                    "timestamp": int(timestamp),
                    "match": 0
                },
                data=imagem_bytes,
                headers={
                    "Content-Type": "application/octet-stream"
                },
                verify=self.certificado,
                timeout=30
            )

            resposta.raise_for_status()

            return True

        except IDFaceError:
            raise

        except (ValueError, TypeError) as erro:
            raise IDFaceError(
                f"A cópia da foto facial está inválida: {erro}"
            )

        except requests.exceptions.RequestException as erro:
            raise IDFaceError(
                f"Erro ao restaurar foto facial: {erro}"
            )

    def cadastrar_usuario(self, usuario_id, nome):
        """
        Cria no iDFace um usuário previamente cadastrado no MySQL.

        Após a criação, associa automaticamente o usuário
        ao departamento PADRÃO.

        A matrícula interna permite recuperar o vínculo posteriormente.
        """

        matricula_interna = f"WBZ{usuario_id:06d}"

        resultado = self.requisicao(
            "create_objects.fcgi",
            {
                "object": "users",
                "values": [
                    {
                        "registration": matricula_interna,
                        "name": nome
                    }
                ]
            }
        )

        ids = self._validar_lista_ids(
            resultado,
            "ids",
            "cadastro de usuário"
        )

        if not ids:
            raise IDFaceError(
                "O iDFace não retornou o ID do usuário cadastrado."
            )

        id_novo_usuario = ids[0]

        try:
            self.associar_departamento_padrao(id_novo_usuario)

        except IDFaceError as erro:
            """
            Se a associação falhar, tenta remover o usuário
            recém-criado para não deixar um cadastro incompleto.
            """

            try:
                self.requisicao(
                    "destroy_objects.fcgi",
                    {
                        "object": "users",
                        "where": {
                            "users": {
                                "id": id_novo_usuario
                            }
                        }
                    }
                )

            except IDFaceError as erro_remocao:
                raise IDFaceError(
                    "O usuário foi criado no iDFace, mas não foi possível "
                    "associá-lo ao departamento PADRÃO. Também houve falha "
                    "ao tentar remover o cadastro incompleto. "
                    f"Erro da associação: {erro}. "
                    f"Erro da remoção: {erro_remocao}"
                )

            raise IDFaceError(
                "O cadastro no iDFace foi cancelado porque não foi possível "
                "associar o usuário ao departamento PADRÃO. "
                f"Motivo: {erro}"
            )

        return id_novo_usuario

    def editar_usuario(self, id_idface, nome):
        resultado = self.requisicao(
            "modify_objects.fcgi",
            {
                "object": "users",
                "values": {"name": nome},
                "where": {"users": {"id": id_idface}}
            }
        )

        if resultado.get("changes", 0) == 0:
            raise IDFaceError(
                "Nenhum usuário foi alterado no iDFace."
            )

    def definir_administrador(self, id_idface, administrador):
        """
        Define a permissão administrativa no iDFace.

        O equipamento possui somente dois níveis relevantes:
        usuário normal e administrador.

        ADM e MASTER recebem o mesmo papel no equipamento.
        A distinção entre eles permanece no MySQL.
        """

        privilegios = self.consultar_privilegios()

        try:
            possui_role_administrativa = any(
                int(privilegio.get("user_id", -1)) == int(id_idface)
                and int(privilegio.get("role", 0)) == 1
                for privilegio in privilegios
            )

        except (ValueError, TypeError):
            raise IDFaceError(
                "O iDFace retornou dados inválidos de permissões."
            )

        if administrador and possui_role_administrativa:
            return

        if not administrador and not possui_role_administrativa:
            return

        if administrador:
            self.requisicao(
                "create_objects.fcgi",
                {
                    "object": "user_roles",
                    "values": [
                        {
                            "user_id": id_idface,
                            "role": 1
                        }
                    ]
                }
            )

        else:
            self.requisicao(
                "destroy_objects.fcgi",
                {
                    "object": "user_roles",
                    "where": {
                        "user_roles": {
                            "user_id": id_idface,
                            "role": 1
                        }
                    }
                }
            )

    def excluir_usuario(self, id_idface):
        """
        Remove os privilégios e o cadastro do usuário no iDFace.
        Não altera registros ou históricos do MySQL.
        """

        self.requisicao(
            "destroy_objects.fcgi",
            {
                "object": "user_roles",
                "where": {"user_roles": {"user_id": id_idface}}
            }
        )

        self.requisicao(
            "destroy_objects.fcgi",
            {
                "object": "user_groups",
                "where": {"user_groups": {"user_id": id_idface}}
            }
        )

        resultado = self.requisicao(
            "destroy_objects.fcgi",
            {
                "object": "users",
                "where": {"users": {"id": id_idface}}
            }
        )

        if resultado.get("changes", 0) == 0:
            raise IDFaceError(
                "Nenhum usuário foi excluído do iDFace."
            )

    def __enter__(self):
        self.conectar()
        return self

    def __exit__(self, tipo, valor, traceback):
        self.desconectar()

