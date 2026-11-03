
import time

from sincronizar_usuarios import sincronizar_usuarios
from sincronizar_logs import sincronizar_logs


def iniciar_servidor():
    print("=== SERVIDOR WICKEDBOTZ ===")
    print("Sincronizacao automatica iniciada!")
    print("Intervalo: 5 segundos\n")

    while True:
        try:
            print("\n--- Nova sincronizacao ---")

            sincronizar_usuarios()
            sincronizar_logs()

            print("\nProxima sincronizacao em 5 segundos...")

        except Exception as erro:
            print(f"Erro no servidor: {erro}")

        time.sleep(5)


if __name__ == "__main__":
    iniciar_servidor()
