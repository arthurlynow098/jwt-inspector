import pytest

from jwtinspector.audit import audit
from jwtinspector.token import MalformedToken, b64url_encode, decode, sign, verify

AGORA = 1_800_000_000
SEGREDO = "um-segredo-de-teste-com-tamanho-ok"


def titulos(header, payload):
    return {f.title for f in audit(header, payload, now=AGORA)}


def test_sign_decode_verify():
    tok = sign({"sub": "arthur", "exp": AGORA + 600}, SEGREDO)
    header, payload, _ = decode(tok)
    assert header["alg"] == "HS256" and payload["sub"] == "arthur"
    assert verify(tok, SEGREDO)
    assert not verify(tok, "segredo-errado")


def test_payload_alterado_invalida_assinatura():
    tok = sign({"sub": "arthur", "admin": False}, SEGREDO)
    h, _, s = tok.split(".")
    novo_payload = b64url_encode(b'{"sub":"arthur","admin":true}')
    adulterado = f"{h}.{novo_payload}.{s}"
    assert not verify(adulterado, SEGREDO)


def test_servidor_decide_o_algoritmo():
    tok = sign({"sub": "x"}, SEGREDO, alg="HS512")
    assert not verify(tok, SEGREDO, allowed=("HS256",))
    assert verify(tok, SEGREDO, allowed=("HS512",))


def test_alg_none_e_critico():
    t = titulos({"alg": "none"}, {"exp": AGORA + 60, "iss": "a", "aud": "b"})
    assert "algoritmo none" in t


def test_sem_exp_e_validade_longa():
    assert "sem exp" in titulos({"alg": "HS256"}, {"iss": "a", "aud": "b"})
    longa = titulos({"alg": "HS256"}, {"iat": AGORA, "exp": AGORA + 30 * 24 * 3600, "iss": "a", "aud": "b"})
    assert "validade longa" in longa


def test_dado_sensivel_no_payload():
    t = titulos({"alg": "HS256"}, {"exp": AGORA + 60, "cpf": "000", "senha": "x"})
    assert "dado sensível no payload" in t


def test_jku_no_header():
    assert "cabeçalho jku" in titulos({"alg": "RS256", "jku": "https://exemplo.example/k.json"}, {"exp": AGORA + 60})


def test_token_bem_configurado_so_tem_info():
    f = audit({"alg": "HS256"}, {"iss": "api", "aud": "web", "iat": AGORA, "exp": AGORA + 900}, now=AGORA)
    assert {x.severity for x in f} == {"info"}


def test_token_malformado():
    with pytest.raises(MalformedToken):
        decode("isso.nao")
