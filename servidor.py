
import time

from idface import IDFaceClient
from sincronizar_usuarios import sincronizar_usuarios
from sincronizar_logs import sincronizar_logs


def iniciar_servidor():
    print("=== SERVIDOR WICKEDBOTZ ===")
    print("Sincronizacao automatica iniciada!")
    print("Intervalo: 20 segundos\n")

    while True:
        try:
            print("\n--- Nova sincronizacao ---")

            # Abre uma unica sessao HTTPS para todo o ciclo.
            with IDFaceClient() as idface:

                sincronizar_usuarios(idface)
                sincronizar_logs(idface)

            # A sessao e encerrada automaticamente aqui.
            print("\nSessao do iDFace encerrada.")
            print("Proxima sincronizacao em 20 segundos...")

        except Exception as erro:
            print(f"Erro no servidor: {erro}")

        time.sleep(20)


if __name__ == "__main__":
    iniciar_servidor()
