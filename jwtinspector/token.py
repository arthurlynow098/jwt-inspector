"""Leitura, assinatura e verificação de JWT com HMAC, só com a biblioteca padrão.

Um JWT é header.payload.assinatura, cada parte em base64url sem padding.
Header e payload são só codificados, NÃO criptografados. Qualquer pessoa
com o token consegue ler o que tem dentro.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


class MalformedToken(ValueError):
    pass


def b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode(token: str) -> tuple[dict, dict, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise MalformedToken("um JWT tem 3 partes separadas por ponto")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise MalformedToken("header ou payload não são JSON em base64url") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise MalformedToken("header e payload precisam ser objetos JSON")
    return header, payload, parts[2]


def sign(payload: dict, secret: str, alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), HMAC_ALGS[alg]).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def verify(token: str, secret: str, allowed: tuple[str, ...] = ("HS256",)) -> bool:
    """Confere a assinatura. A lista de algoritmos aceitos é decidida pelo servidor,
    nunca pelo que vem escrito no próprio token."""
    header, _, sig = decode(token)
    alg = header.get("alg")
    if alg not in allowed or alg not in HMAC_ALGS:
        return False
    h, p, _ = token.strip().split(".")
    expected = hmac.new(secret.encode(), f"{h}.{p}".encode(), HMAC_ALGS[alg]).digest()
    try:
        return hmac.compare_digest(expected, b64url_decode(sig))
    except ValueError:
        return False
