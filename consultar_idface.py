
import requests
import msvcrt

IP = "192.168.0.129"
BASE_URL = f"http://{IP}"


def digitar_senha():
    print("Senha do iDFace: ", end="", flush=True)
    senha = ""

    while True:
        tecla = msvcrt.getwch()

        if tecla == "\r":
            print()
            break

        elif tecla == "\b":
            if senha:
                senha = senha[:-1]
                print("\b \b", end="", flush=True)

        elif tecla in ("\x00", "\xe0"):
            msvcrt.getwch()

        else:
            senha += tecla
            print("*", end="", flush=True)

    return senha


def consultar_usuarios():
    usuario = input("Usuário do iDFace: ")
    senha = digitar_senha()

    try:
        # Autenticação
        resposta = requests.post(
            f"{BASE_URL}/login.fcgi",
            json={
                "login": usuario,
                "password": senha
            },
            timeout=10
        )

        resposta.raise_for_status()
        resultado = resposta.json()

        sessao = resultado.get("session")

        if not sessao:
            print("Não foi possível obter a sessão.")
            return

        print("\nAutenticação realizada com sucesso!")

        # Consulta de usuários
        consulta = requests.post(
            f"{BASE_URL}/load_objects.fcgi?session={sessao}",
            json={
                "object": "users"
            },
            timeout=10
        )

        consulta.raise_for_status()

        dados = consulta.json()

        print("\nConsulta realizada!")
        print("Resposta da API:")

        usuarios = dados.get("users", [])

        print("Quantidade de usuários:", len(usuarios))

        for usuario in usuarios:
            print(
                "ID:", usuario.get("id"),
                "| Nome:", usuario.get("name")
            )

    except requests.exceptions.RequestException as erro:
        print("\nErro na comunicação:", erro)

    except ValueError:
        print("\nA resposta da API não é um JSON válido.")


if __name__ == "__main__":
    consultar_usuarios()
