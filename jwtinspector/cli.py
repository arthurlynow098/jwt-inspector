from __future__ import annotations

import argparse
import getpass
import json
import sys
from datetime import datetime

from .audit import audit
from .token import MalformedToken, decode, verify

ICON = {"critica": "[!!!]", "alta": "[!! ]", "media": "[!  ]", "info": "[ i ]"}
ORDER = ["critica", "alta", "media", "info"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jwtinspector", description="Decodifica um JWT e audita a configuração dele.")
    p.add_argument("token", nargs="?", help="o token (ou passe por stdin)")
    p.add_argument("--verificar", action="store_true", help="pede o segredo HMAC e confere a assinatura")
    p.add_argument("--algs", default="HS256", help="algoritmos aceitos na verificação, separados por vírgula")
    return p


def human(ts) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return str(ts)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    token = args.token or sys.stdin.read().strip()
    try:
        header, payload, _ = decode(token)
    except MalformedToken as exc:
        print(f"  token inválido, {exc}", file=sys.stderr)
        return 2

    print("\n  HEADER")
    print("  " + json.dumps(header, ensure_ascii=False, indent=2).replace("\n", "\n  "))
    print("\n  PAYLOAD")
    print("  " + json.dumps(payload, ensure_ascii=False, indent=2).replace("\n", "\n  "))
    for claim in ("iat", "nbf", "exp"):
        if claim in payload:
            print(f"  {claim} = {human(payload[claim])}")

    findings = sorted(audit(header, payload), key=lambda f: ORDER.index(f.severity))
    print(f"\n  AUDITORIA ({len(findings)} item(ns))")
    for f in findings:
        print(f"  {ICON[f.severity]} {f.title}")
        print(f"        {f.detail}")

    if args.verificar:
        secret = getpass.getpass("\n  segredo HMAC (não aparece na tela) ")
        ok = verify(token, secret, tuple(a.strip().upper() for a in args.algs.split(",")))
        print("  assinatura VÁLIDA" if ok else "  assinatura INVÁLIDA ou algoritmo não permitido")
    print()
    return 1 if any(f.severity == "critica" for f in findings) else 0
