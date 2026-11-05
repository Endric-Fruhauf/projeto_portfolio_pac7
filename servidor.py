
import time

from idface import IDFaceClient
from sincronizar_usuarios import sincronizar_usuarios
from sincronizar_logs import sincronizar_logs


def iniciar_servidor():
    print("=== SERVIDOR WICKEDBOTZ ===")
    print("Sincronizacao automatica iniciada!")
    print("Intervalo: 20 segundos\n")

    while True:
        print("\n--- Nova sincronizacao ---")

        try:
            with IDFaceClient() as idface:

                # Sincronizacao de usuarios
                try:
                    print("\n=== SINCRONIZACAO DE USUARIOS ===")
                    resultado_usuarios = sincronizar_usuarios(idface)
                    print("Resultado usuarios:", resultado_usuarios)

                except Exception as erro:
                    print(f"Erro na sincronizacao de usuarios: {erro}")

                # Sincronizacao de registros de acesso
                try:
                    print("\n=== SINCRONIZACAO DE REGISTROS ===")
                    resultado_logs = sincronizar_logs(idface)
                    print("Resultado registros:", resultado_logs)

                except Exception as erro:
                    print(f"Erro na sincronizacao de registros: {erro}")

            print("\nSessao do iDFace encerrada.")

        except Exception as erro:
            print(f"Erro ao conectar ou manter sessao com iDFace: {erro}")

        print("Proxima sincronizacao em 20 segundos...")
        time.sleep(20)


if __name__ == "__main__":
    iniciar_servidor()
