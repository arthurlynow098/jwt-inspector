"""Auditoria da configuração de um token, olhando só o que está dentro dele."""
from __future__ import annotations

import time
from dataclasses import dataclass

SENSITIVE = ("senha", "password", "secret", "segredo", "cpf", "cartao", "card", "cvv", "api_key")


@dataclass
class Finding:
    severity: str  # critica, alta, media, info
    title: str
    detail: str


def audit(header: dict, payload: dict, now: float | None = None, max_hours: float = 24) -> list[Finding]:
    now = time.time() if now is None else now
    out: list[Finding] = []
    alg = str(header.get("alg", "")).upper()

    if alg in ("", "NONE"):
        out.append(Finding("critica", "algoritmo none",
                           "token sem assinatura, o servidor nunca deveria aceitar"))
    elif alg.startswith("HS"):
        out.append(Finding("info", f"assinatura simétrica {alg}",
                           "quem verifica também consegue assinar, o segredo precisa ter 256 bits aleatórios e ficar só no servidor"))
    elif alg.startswith(("RS", "ES", "PS")) or alg == "EDDSA":
        out.append(Finding("info", f"assinatura assimétrica {alg}", "bom para quando vários serviços só precisam verificar"))

    for key in ("jku", "x5u"):
        if key in header:
            out.append(Finding("alta", f"cabeçalho {key}",
                               f"aponta a chave para uma URL ({header[key]}), o servidor deve ignorar ou usar lista fixa"))
    if "jwk" in header:
        out.append(Finding("alta", "chave embutida no cabeçalho (jwk)", "o servidor nunca deve confiar numa chave que veio no próprio token"))
    kid = str(header.get("kid", ""))
    if any(ch in kid for ch in ("/", "\\", "..", "'", ";")):
        out.append(Finding("media", "kid com caracteres estranhos", f"{kid!r}, o servidor deve tratar o kid como dado e validar"))

    exp = payload.get("exp")
    if exp is None:
        out.append(Finding("alta", "sem exp", "o token vale para sempre se vazar"))
    else:
        if exp < now:
            out.append(Finding("info", "expirado", f"venceu há {(now - exp) / 3600:.1f} h"))
        iat = payload.get("iat", now)
        hours = (exp - iat) / 3600
        if hours > max_hours:
            out.append(Finding("media", "validade longa", f"{hours:.0f} h de vida, para access token o comum é minutos ou poucas horas"))
    if "iat" in payload and payload["iat"] > now + 60:
        out.append(Finding("media", "iat no futuro", "relógio errado ou token forjado"))
    for claim in ("iss", "aud"):
        if claim not in payload:
            out.append(Finding("media", f"sem {claim}", "o servidor não consegue conferir quem emitiu ou para quem é"))

    leaked = [k for k in payload if any(word in k.lower() for word in SENSITIVE)]
    if leaked:
        out.append(Finding("alta", "dado sensível no payload",
                           f"campos {', '.join(leaked)} ficam legíveis para qualquer um com o token"))
    return out
