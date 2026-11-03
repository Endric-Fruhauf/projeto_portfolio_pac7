
import requests
import config

IP = config.IDFACE_IP
BASE_URL = f"http://{IP}"


def cadastrar_usuario():
    dados_usuario = {
        "registration": "TESTE001",
        "name": "Usuario Teste"
    }

    sessao = None

    try:
        # 1. Autenticacao
        resposta = requests.post(
            f"{BASE_URL}/login.fcgi",
            json={
                "login": config.IDFACE_USUARIO,
                "password": config.IDFACE_SENHA
            },
            timeout=10
        )

        resposta.raise_for_status()
        resultado = resposta.json()

        sessao = resultado.get("session")

        if not sessao:
            print("Nao foi possivel obter a sessao.")
            return

        print("Autenticacao realizada com sucesso!")

        # 2. Verificar se a matricula ja existe
        consulta = requests.post(
            f"{BASE_URL}/load_objects.fcgi?session={sessao}",
            json={"object": "users"},
            timeout=10
        )

        consulta.raise_for_status()

        usuarios = consulta.json().get("users", [])

        for pessoa in usuarios:
            if pessoa.get("registration") == dados_usuario["registration"]:
                print("A matricula TESTE001 ja existe.")
                print("Nenhum cadastro foi realizado.")
                return

        # 3. Cadastrar usuario
        cadastro = requests.post(
            f"{BASE_URL}/create_objects.fcgi?session={sessao}",
            json={
                "object": "users",
                "values": [dados_usuario]
            },
            timeout=10
        )

        cadastro.raise_for_status()

        resultado_cadastro = cadastro.json()
        ids = resultado_cadastro.get("ids", [])

        if ids:
            print("\nUsuario cadastrado com sucesso!")
            print("ID gerado pelo iDFace:", ids[0])
            print("Nome:", dados_usuario["name"])
            print("Matricula:", dados_usuario["registration"])
        else:
            print("\nResposta recebida, mas sem ID de cadastro.")
            print(resultado_cadastro)

    except requests.exceptions.RequestException as erro:
        print("\nErro na comunicacao:", erro)

    except ValueError:
        print("\nA resposta da API nao e um JSON valido.")

    finally:
        # 4. Encerrar sessao
        if sessao:
            try:
                requests.post(
                    f"{BASE_URL}/logout.fcgi?session={sessao}",
                    timeout=5
                )
            except requests.exceptions.RequestException:
                pass


if __name__ == "__main__":
    cadastrar_usuario()
