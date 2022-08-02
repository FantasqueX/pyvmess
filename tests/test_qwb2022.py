from uuid import UUID

import pyvmess


def test_qwb2022():
    client_uuid = UUID("b831381d-6324-4d53-ad4f-8cda48b30811")
    with open("tests/data/client.bin", "rb") as f:
        client_data = f.read()

    client_package = pyvmess.ClientVmessPackage(client_uuid, client_data)

    timestamp = client_package.auth(1615528982 + 100)
    assert timestamp == 1615528982

    client_package.decode_header()

    client_package.decode_body()

    with open("tests/data/client.text", "rb") as f:
        client_text = f.read()
    assert client_text == b"".join(client_package.body_data)

    with open("tests/data/server.bin", "rb") as f:
        server_data = f.read()

    server_package = pyvmess.ServerVmessPackage(
        client_package.response_header,
        client_package.body_iv,
        client_package.body_key,
        client_package.option,
        client_package.security,
        server_data,
    )

    server_package.decode_header()

    server_package.decode_body()

    with open("tests/data/server.text", "rb") as f:
        server_text = f.read()
    assert server_text == b"".join(server_package.body_data)
