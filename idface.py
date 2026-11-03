
import requests
import config


class IDFaceError(Exception):
    """Erro na comunicação ou operação com o iDFace."""
    pass


class IDFaceClient:

    def __init__(self):
        self.base_url = f"http://{config.IDFACE_IP}"
        self.session = None

    def conectar(self):
        try:
            resposta = requests.post(
                f"{self.base_url}/login.fcgi",
                json={
                    "login": config.IDFACE_USUARIO,
                    "password": config.IDFACE_SENHA
                },
                timeout=10
            )

            resposta.raise_for_status()

            self.session = resposta.json().get("session")

            if not self.session:
                raise IDFaceError(
                    "O iDFace não retornou uma sessão válida."
                )

        except requests.exceptions.RequestException as erro:
            raise IDFaceError(
                f"Não foi possível conectar ao iDFace: {erro}"
            )

    def desconectar(self):
        if self.session:
            try:
                requests.post(
                    f"{self.base_url}/logout.fcgi",
                    params={"session": self.session},
                    timeout=5
                )
            except requests.exceptions.RequestException:
                pass

            self.session = None

    def requisicao(self, endpoint, dados):
        if not self.session:
            raise IDFaceError("Não existe uma sessão ativa.")

        try:
            resposta = requests.post(
                f"{self.base_url}/{endpoint}",
                params={"session": self.session},
                json=dados,
                timeout=10
            )

            resposta.raise_for_status()

            resultado = resposta.json()

            if "error" in resultado:
                raise IDFaceError(str(resultado["error"]))

            return resultado

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

        return resultado.get("users", [])

    def cadastrar_usuario(self, usuario_id, nome):
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

        ids = resultado.get("ids", [])

        if not ids:
            raise IDFaceError(
                "O iDFace não retornou o ID do usuário cadastrado."
            )

        return ids[0]

    def editar_usuario(self, id_idface, nome):
        resultado = self.requisicao(
            "modify_objects.fcgi",
            {
                "object": "users",
                "values": {
                    "name": nome
                },
                "where": {
                    "users": {
                        "id": id_idface
                    }
                }
            }
        )

        if resultado.get("changes", 0) == 0:
            raise IDFaceError(
                "Nenhum usuário foi alterado no iDFace."
            )

    def definir_administrador(self, id_idface, administrador):
        # Remove os privilégios administrativos anteriores.
        self.requisicao(
            "destroy_objects.fcgi",
            {
                "object": "user_roles",
                "where": {
                    "user_roles": {
                        "user_id": id_idface
                    }
                }
            }
        )

        # Cria o privilégio somente para administradores.
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

    def excluir_usuario(self, id_idface):
        # Remove primeiro o vínculo administrativo.
        self.requisicao(
            "destroy_objects.fcgi",
            {
                "object": "user_roles",
                "where": {
                    "user_roles": {
                        "user_id": id_idface
                    }
                }
            }
        )

        # Remove o cadastro do equipamento.
        resultado = self.requisicao(
            "destroy_objects.fcgi",
            {
                "object": "users",
                "where": {
                    "users": {
                        "id": id_idface
                    }
                }
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
