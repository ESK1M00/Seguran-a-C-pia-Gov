"""
Teste automatizado do FLUXO COMPLETO exigido no trabalho:

  Gerar certificado -> Selecionar PDF -> Assinar -> Validar -> Detectar alterações

Execute a partir da pasta do projeto:
    python -m pytest testes -v        (ou)        python testes/teste_fluxo_completo.py
"""
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from seguranca.assinatura import assinar_pdf  # noqa: E402
from seguranca.certificados import DadosTitular, gerar_certificado_completo  # noqa: E402
from seguranca.integridade import adulterar_bytes, alterar_incrementalmente  # noqa: E402
from seguranca.validacao import validar_pdf_assinado  # noqa: E402

SENHA = "senha-de-teste-123"
PDF_EXEMPLO = RAIZ / "exemplos" / "contrato_exemplo.pdf"


def _preparar():
    gerado = gerar_certificado_completo(
        DadosTitular(nome_comum="Aluno Teste", organizacao="UniRV", pais="BR"),
        senha_pfx=SENHA,
        dias_validade=30,
        tamanho_bits=2048,
    )
    assinado = assinar_pdf(PDF_EXEMPLO.read_bytes(), gerado.pacote_pfx, SENHA, "Teste", "Rio Verde")
    return gerado, assinado.pdf_assinado


def teste_certificado_rsa_2048_autoassinado():
    gerado, _ = _preparar()
    cert = gerado.certificado
    assert cert.public_key().key_size >= 2048
    assert cert.issuer == cert.subject


def teste_assinatura_valida_mas_autoassinada():
    _, pdf = _preparar()
    rel = validar_pdf_assinado(pdf)
    assert rel.possui_assinaturas and rel.quantidade == 1
    a = rel.assinaturas[0]
    assert a.integro and a.criptograficamente_valida
    assert a.confianca == "AUTOASSINADO"
    assert not a.alterado_apos_assinatura
    assert a.hash_calculado == a.hash_assinado


def teste_certificado_marcado_como_confiavel():
    gerado, pdf = _preparar()
    a = validar_pdf_assinado(pdf, [gerado.certificado_pem]).assinaturas[0]
    assert a.confiavel and a.nivel == "ok"


def teste_adulteracao_de_bytes_invalida_assinatura():
    _, pdf = _preparar()
    alterado = adulterar_bytes(pdf, "R$ 1.000,00", "R$ 9.000,00")
    a = validar_pdf_assinado(alterado).assinaturas[0]
    assert not a.integro and not a.assinatura_valida
    assert a.hash_calculado != a.hash_assinado


def teste_alteracao_incremental_detectada():
    _, pdf = _preparar()
    alterado = alterar_incrementalmente(pdf)
    a = validar_pdf_assinado(alterado).assinaturas[0]
    assert a.alterado_apos_assinatura
    assert a.nivel == "erro"


def teste_pdf_preserva_conteudo_original():
    _, pdf = _preparar()
    original = PDF_EXEMPLO.read_bytes()
    assert pdf.startswith(original)  # atualização incremental: bytes originais intactos


if __name__ == "__main__":
    for nome, func in list(globals().items()):
        if nome.startswith("teste_"):
            func()
            print(f"[OK] {nome}")
