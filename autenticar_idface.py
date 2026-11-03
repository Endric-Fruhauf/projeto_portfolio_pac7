
import requests
import config

URL = f"http://{config.IDFACE_IP}/login.fcgi"


def autenticar():
    dados = {
        "login": config.IDFACE_USUARIO,
        "password": config.IDFACE_SENHA
    }

    try:
        resposta = requests.post(
            URL,
            json=dados,
            timeout=10
        )

        print("\nStatus HTTP:", resposta.status_code)

        resposta.raise_for_status()

        try:
            resultado = resposta.json()

            if "session" in resultado:
                print("Autenticacao realizada com sucesso!")
                print("Sessao recebida corretamente.")
            else:
                print("Autenticacao nao confirmada.")
                print("Resposta:", resultado)

        except ValueError:
            print("Resposta nao esta em formato JSON.")
            print(resposta.text[:500])

    except requests.exceptions.RequestException as erro:
        print("Erro na comunicacao:", erro)


if __name__ == "__main__":
    autenticar()
