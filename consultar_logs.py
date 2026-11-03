
import requests
import config
from datetime import datetime

IP = config.IDFACE_IP
BASE_URL = f"http://{IP}"


def consultar_logs():
    usuario = config.IDFACE_USUARIO
    senha = config.IDFACE_SENHA

    sessao = None

    try:
        # 1. Autenticacao
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
            print("Nao foi possivel obter a sessao.")
            return

        print("Autenticacao realizada com sucesso!")

        # 2. Consultar registros de acesso
        consulta = requests.post(
            f"{BASE_URL}/load_objects.fcgi?session={sessao}",
            json={
                "object": "access_logs",
                "fields": [
                    "id",
                    "time",
                    "event",
                    "device_id",
                    "user_id",
                    "identifier_id",
                    "portal_id"
                ],
                "limit": 50,
                "order": [
                    "descending",
                    "id"
                ]
            },
            timeout=10
        )

        consulta.raise_for_status()
        dados = consulta.json()

        logs = dados.get("access_logs", [])

        print("\nConsulta realizada!")
        print("Quantidade de registros:", len(logs))

        # 3. Traducao dos eventos
        eventos = {
            1: "Equipamento invalido",
            2: "Parametros invalidos",
            3: "Nao identificado",
            4: "Identificacao pendente",
            5: "Tempo esgotado",
            6: "Acesso negado",
            7: "Acesso concedido",
            8: "Acesso pendente",
            9: "Usuario nao e administrador",
            10: "Acesso via API",
            11: "Acesso por botoeira",
            12: "Acesso pela interface web",
            14: "Sem resposta",
            15: "Acesso pela interfonia"
        }

        if not logs:
            print("\nNenhum registro de acesso encontrado.")
            return

        print("\n--- REGISTROS DE ACESSO ---")

        for log in logs:
            horario = datetime.fromtimestamp(
                int(log["time"])
            ).strftime("%d/%m/%Y %H:%M:%S")

            evento = eventos.get(
                log.get("event"),
                "Evento desconhecido"
            )

            print("\nID:", log.get("id"))
            print("Data/Hora:", horario)
            print("Evento:", evento)
            print("Usuario ID:", log.get("user_id"))
            print("Dispositivo ID:", log.get("device_id"))

    except requests.exceptions.RequestException as erro:
        print("\nErro na comunicacao:", erro)

    except (ValueError, KeyError, TypeError) as erro:
        print("\nErro ao interpretar a resposta:", erro)

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
    consultar_logs()
