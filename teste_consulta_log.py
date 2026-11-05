
from idface import IDFaceClient


try:
    with IDFaceClient() as idface:

        # Busca o evento mais recente.
        resposta = idface.requisicao(
            "load_objects.fcgi",
            {
                "object": "access_logs",
                "fields": ["id"],
                "limit": 1,
                "order": ["descending", "id"]
            }
        )

        registros = resposta.get("access_logs", [])

        if not registros:
            print("Nenhum registro encontrado no iDFace.")

        else:
            id_registro = registros[0]["id"]

            print("Evento encontrado:", id_registro)

            # Consulta o mesmo evento utilizando igualdade.
            resposta = idface.requisicao(
                "load_objects.fcgi",
                {
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
                    "where": [
                        {
                            "object": "access_logs",
                            "field": "id",
                            "operator": "=",
                            "value": id_registro
                        }
                    ],
                    "limit": 1
                }
            )

            resultado = resposta.get("access_logs", [])

            print("\nResultado da consulta individual:")

            if resultado:
                print(resultado[0])
                print("\nTESTE APROVADO!")
            else:
                print("\nTESTE FALHOU: evento não encontrado.")

except Exception as erro:
    print("\nERRO NO TESTE:")
    print(erro)
