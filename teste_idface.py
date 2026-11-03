
import requests
import config

URL = f"http://{config.IDFACE_IP}"

try:
    resposta = requests.get(URL, timeout=5)

    print("Conexao estabelecida!")
    print("Status HTTP:", resposta.status_code)
    print("Servidor respondeu corretamente.")

except requests.exceptions.RequestException as erro:
    print("Erro na comunicacao:")
    print(erro)
