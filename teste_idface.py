
from idface import IDFaceClient, IDFaceError


def testar_conexao():
    try:
        with IDFaceClient() as idface:
            print("Conexão com iDFace estabelecida!")

            usuarios = idface.consultar_usuarios()

            print(f"\nUsuários encontrados: {len(usuarios)}")

            for usuario in usuarios:
                print(
                    f"ID: {usuario.get('id')} | "
                    f"Nome: {usuario.get('name')} | "
                    f"ID iDFace: {usuario.get('id')}"
                )

        print("\nTeste concluído com sucesso!")

    except IDFaceError as erro:
        print("\nFalha no teste:", erro)


if __name__ == "__main__":
    testar_conexao()
