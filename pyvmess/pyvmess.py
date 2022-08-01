# SPDX-FileCopyrightText: 2022-present Letu Ren <fantasquex@gmail.com>
#
# SPDX-License-Identifier: MIT
"""The main module of pyvmess"""
import hmac
import time
from hashlib import md5
from ipaddress import ip_address
from itertools import count
from typing import Dict
from uuid import UUID

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import SHAKE128
from fnvhash import fnv1a_32


class Reader:
    """Helper class for convenient reading"""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.total_size = len(data)

    def read(self, size: int) -> bytes:
        """Read some bytes, or raise exception if overflow is detected."""
        if self.pos + size > self.total_size:
            raise Exception("Read too much data")
        old_pos = self.pos
        self.pos += size
        return self.data[old_pos : self.pos]

    def is_finish(self) -> bool:
        """Return true if all data has been read."""
        return self.pos == self.total_size


class ClientVmessPackage:
    """Class to process client-side vmess package"""

    def __init__(self, client_uuid: UUID, data: bytes):
        self.client_uuid = client_uuid
        self.data = data
        self.timestamp = -1
        self.auth_len = 16
        self.header_len = -1
        self.version = -1
        self.body_iv = b""
        self.body_key = b""
        self.response_header = 0
        self.option = {
            "S": False,
            "R": False,
            "M": False,
            "P": False,
            "A": False,
        }
        self.security = -1
        self.padding = -1
        self.command = -1
        self.port = -1
        self.address_type = -1
        self.address = b""
        self.body_data = []

    def __str__(self):
        result = {}
        result["timestamp"] = self.timestamp
        result["header_len"] = self.header_len
        result["version"] = self.version
        result["body_iv"] = self.body_iv
        result["body_key"] = self.body_key
        result["response_header"] = self.response_header
        result["option"] = self.option
        match self.security:
            case 5:
                result["security"] = "None"
            case 1:
                result["security"] = "Legacy"
            case 3:
                result["security"] = "AES-128-GCM"
            case 4:
                result["security"] = "ChaCha20-Poly1305"
            case _:
                result["security"] = "Unknown"
        match self.command:
            case 1:
                result["command"] = "TCP"
            case 2:
                result["command"] = "UDP"
            case 3:
                result["command"] = "Unknown"
        result["port"] = self.port
        match self.address_type:
            case 1:
                result["address"] = str(ip_address(self.address))
            case 2:
                result["address"] = self.address.decode()
            case 3:
                result["address"] = str(ip_address(self.address))
        result["body_data"] = self.body_data
        return str(result)

    def auth(self, start_time=int(time.time())) -> int:
        """Check auth section and get timestamp"""
        auth_data = self.data[: self.auth_len]
        for timestamp in reversed(range(start_time + 30)):
            msg = timestamp.to_bytes(8, byteorder="big")
            res = hmac.new(key=self.client_uuid.bytes, msg=msg, digestmod=md5).digest()
            if res == auth_data:
                self.timestamp = timestamp
                return timestamp
        raise Exception("Auth failed!")

    def decode_header(self):
        """Parse header section"""
        if self.timestamp == -1:
            raise Exception("Please auth() of set timestamp first")
        header_iv = md5(self.timestamp.to_bytes(8, byteorder="big") * 4).digest()
        header_key = md5(
            self.client_uuid.bytes + b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
        ).digest()
        header_cipher = AES.new(
            key=header_key, mode=AES.MODE_CFB, IV=header_iv, segment_size=128
        )
        header = header_cipher.decrypt(self.data[self.auth_len :])
        header_reader = Reader(header)
        self.version = header_reader.read(1)[0]
        assert self.version == 1
        self.body_iv = header_reader.read(16)
        self.body_key = header_reader.read(16)
        self.response_header = header_reader.read(1)[0]
        option = header_reader.read(1)[0]
        self.option["S"] = option & 0x01 != 0
        self.option["R"] = option & 0x02 != 0
        self.option["M"] = option & 0x04 != 0
        self.option["P"] = option & 0x08 != 0
        self.option["A"] = option & 0x10 != 0
        assert option >> 5 == 0
        tmp = header_reader.read(1)[0]
        self.padding = tmp >> 4
        self.security = tmp & 0xF
        assert self.security in (5, 1, 3, 5)
        header_reader.read(1)
        self.command = header_reader.read(1)[0]
        assert self.command in (1, 2, 3)
        if self.command == 3:
            raise Exception("Mux hasn't been implemented")
        self.port = int.from_bytes(header_reader.read(2), byteorder="big")
        self.address_type = header_reader.read(1)[0]
        match self.address_type:
            case 1:
                self.address = header_reader.read(4)
            case 2:
                tmp = header_reader.read(1)[0]
                self.address = header_reader.read(tmp)
            case 3:
                self.address = header_reader.read(16)
            case _:
                raise Exception("Unknown address type")
        header_reader.read(self.padding)
        tmp = fnv1a_32(header_reader.data[: header_reader.pos])
        checksum = int.from_bytes(header_reader.read(4), byteorder="big")
        if tmp != checksum:
            raise Exception("FNV1a hash doesn't match")
        self.header_len = header_reader.pos

    def decode_body(self):
        """Parse body section"""
        body_reader = Reader(self.data[self.auth_len + self.header_len :])
        shake = SHAKE128.new()
        if self.option["M"]:
            shake.update(self.body_iv)

        for i in count():
            if body_reader.is_finish():
                break
            match self.security:
                case 3:
                    nonce = i.to_bytes(2, byteorder="big") + self.body_iv[2:12]
                    body_cipher = AES.new(self.body_key, AES.MODE_GCM, nonce=nonce)
                case 4:
                    nonce = i.to_bytes(2, byteorder="big") + self.body_iv[2:12]
                    key = (
                        md5(self.body_key).digest()
                        + md5(md5(self.body_key).digest()).digest()
                    )
                    body_cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                case _:
                    raise Exception("Unsupported security option!")
            if self.option["P"]:
                padding = int.from_bytes(shake.read(2), byteorder="big") % 64
            fake_length = int.from_bytes(body_reader.read(2), byteorder="big")
            real_length = fake_length ^ int.from_bytes(shake.read(2), byteorder="big")
            if self.option["P"]:
                body_raw_data = body_reader.read(real_length)[: real_length - padding]
            else:
                body_raw_data = body_reader.read(real_length)
            body_data = body_cipher.decrypt_and_verify(
                body_raw_data[:-16], body_raw_data[-16:]
            )
            self.body_data.append(body_data)


class ServerVmessPackage:
    """Class to process client-side vmess package"""

    def __init__(
        self,
        response_header: int,
        client_iv: bytes,
        client_key: bytes,
        option: Dict,
        security: int,
        data: bytes,
    ):
        self.response_header = response_header
        self.server_iv = md5(client_iv).digest()
        self.server_key = md5(client_key).digest()
        self.option = option
        self.security = security
        self.header_len = 4
        self.body_data = []
        self.data = data

    def decode_header(self):
        """Parse header section"""
        header_cipher = AES.new(
            key=self.server_key, mode=AES.MODE_CFB, iv=self.server_iv, segment_size=128
        )
        header = header_cipher.decrypt(self.data)
        if header[0] != self.response_header:
            raise Exception("Response header doesn't match!")
        if header[1] != 0:
            raise Exception("Option should be zero!")
        if header[2] != 0:
            raise Exception("Command hasn't been implemented")
        assert header[3] == 0

    def decode_body(self):
        """Parse body section"""
        body_reader = Reader(self.data[self.header_len :])
        shake = SHAKE128.new()
        if self.option["M"]:
            shake.update(self.server_iv)

        for i in count():
            if body_reader.is_finish():
                break
            match self.security:
                case 3:
                    nonce = i.to_bytes(2, byteorder="big") + self.server_iv[2:12]
                    body_cipher = AES.new(self.server_key, AES.MODE_GCM, nonce=nonce)
                case 4:
                    nonce = i.to_bytes(2, byteorder="big") + self.server_iv[2:12]
                    key = (
                        md5(self.server_key).digest()
                        + md5(md5(self.server_key).digest()).digest()
                    )
                    body_cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                case _:
                    raise Exception("Unsupported security option!")
            if self.option["P"]:
                padding = int.from_bytes(shake.read(2), byteorder="big") % 64
            fake_length = int.from_bytes(body_reader.read(2), byteorder="big")
            real_length = fake_length ^ int.from_bytes(shake.read(2), byteorder="big")
            if self.option["P"]:
                body_raw_data = body_reader.read(real_length)[: real_length - padding]
            else:
                body_raw_data = body_reader.read(real_length)
            body_data = body_cipher.decrypt_and_verify(
                body_raw_data[:-16], body_raw_data[-16:]
            )
            self.body_data.append(body_data)
