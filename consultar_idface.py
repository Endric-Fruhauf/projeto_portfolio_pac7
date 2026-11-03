
import requests
import json
import config

BASE_URL = f"http://{config.IDFACE_IP}"


def consultar_objeto(sessao, objeto):
    resposta = requests.post(
        f"{BASE_URL}/load_objects.fcgi?session={sessao}",
        json={"object": objeto},
        timeout=10
    )

    resposta.raise_for_status()
    return resposta.json().get(objeto, [])


def consultar_idface():
    sessao = None

    try:
        print("Conectando ao iDFace...")

        resposta = requests.post(
            f"{BASE_URL}/login.fcgi",
            json={
                "login": config.IDFACE_USUARIO,
                "password": config.IDFACE_SENHA
            },
            timeout=10
        )

        resposta.raise_for_status()
        sessao = resposta.json().get("session")

        if not sessao:
            print("Não foi possível autenticar.")
            return

        print("Autenticação realizada com sucesso!")

        usuarios = consultar_objeto(sessao, "users")
        privilegios = consultar_objeto(sessao, "user_roles")

        print("\n========== USUÁRIOS ==========")
        print(json.dumps(
            usuarios,
            indent=4,
            ensure_ascii=False
        ))

        print("\n========== PRIVILÉGIOS ==========")
        print(json.dumps(
            privilegios,
            indent=4,
            ensure_ascii=False
        ))

        print("\n========== RESUMO ==========")

        for usuario in usuarios:
            usuario_id = usuario.get("id")

            administrador = any(
                privilegio.get("user_id") == usuario_id
                and privilegio.get("role") == 1
                for privilegio in privilegios
            )

            categoria = (
                "ADMINISTRADOR"
                if administrador
                else "MEMBRO"
            )

            print(
                f"ID: {usuario_id} | "
                f"Nome: {usuario.get('name')} | "
                f"Categoria: {categoria}"
            )

    except requests.exceptions.RequestException as erro:
        print("\nErro na comunicação:", erro)

    except ValueError:
        print("\nResposta inválida da API.")

    finally:
        if sessao:
            try:
                requests.post(
                    f"{BASE_URL}/logout.fcgi?session={sessao}",
                    timeout=5
                )
                print("\nSessão encerrada.")
            except requests.exceptions.RequestException:
                pass


if __name__ == "__main__":
    consultar_idface()
