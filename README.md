# Pyvmess

[![PyPI - Version](https://img.shields.io/pypi/v/pyvmess.svg)](https://pypi.org/project/pyvmess)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pyvmess.svg)](https://pypi.org/project/pyvmess)
[![code style - black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![imports - isort](https://img.shields.io/badge/imports-isort-ef8336.svg)](https://github.com/pycqa/isort)
[![License - MIT](https://img.shields.io/badge/license-MIT-9400d3.svg)](https://spdx.org/licenses/)
-----

Pyvmess is a naive implementation to parse raw [vmess](https://www.v2fly.org/developer/protocols/vmess.html) package in Python. Note: As vmess is such a complicated protocol, it's quite hard to implement full feature decoder. There are quite a lot of cases which are covered by Pyvmess.

As this package is likely to be outdated, you can refer to vmess source code [server code](https://github.com/v2fly/v2ray-core/blob/master/proxy/vmess/encoding/server.go) and [client code](https://github.com/v2fly/v2ray-core/blob/master/proxy/vmess/encoding/client.go) if needed. 

**Table of Contents**

- [Installation](#installation)
- [Usage](#usage)
- [Build](#build)
- [Tests](#tests)
- [License](#license)

## Installation

```console
pip install pyvmess
```

## Usage

Let's take one challenge dieyingchongchong from qwb2022 as an example. Pyvmess can parse meta data from header and decode data from body. The following example can be found in test cases.

```python
from uuid import UUID

import pyvmess


client_uuid = UUID("b831381d-6324-4d53-ad4f-8cda48b30811")
with open("data/client.bin", "rb") as f:
    client_data = f.read()

client_package = pyvmess.ClientVmessPackage(client_uuid, client_data)

timestamp = client_package.auth(1615528982 + 100)

client_package.decode_header()

client_package.decode_body()

print(b"".join(client_package.body_data).decode())

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

print(b"".join(server_package.body_data).decode())
```

## Build

Pyvmess uses hatch as the project manager. You can use hatch or any other build tools compliant with PEP517 such as [build](https://packaging.python.org/en/latest/key_projects/#build).

```shell
# hatch
hatch build
```

```shell
# build
python -m build
```

# Tests

Pyvmess uses pytest for testing. You can run tests as follows.

```shell
hatch run test
```

## License

`pyvmess` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
