"""
Funcionalidade 3 — Validação de assinaturas digitais
=====================================================

Para cada assinatura encontrada no PDF, o módulo responde a TRÊS perguntas
diferentes (e as apresenta SEPARADAMENTE, como exige o trabalho):

  A) INTEGRIDADE  — O conteúdo assinado foi alterado?
       Recalcula-se o hash SHA-256 dos bytes cobertos pelo /ByteRange e
       compara-se com o hash (messageDigest) que está DENTRO da assinatura.

  B) VALIDADE CRIPTOGRÁFICA — A assinatura confere com a chave pública?
       Usa-se a CHAVE PÚBLICA do certificado para verificar a assinatura
       RSA sobre os atributos assinados. Só quem possui a chave privada
       correspondente conseguiria produzi-la.

  C) CONFIANÇA NO CERTIFICADO — Quem garante que a chave pública pertence
       ao titular? Tenta-se montar uma cadeia até uma raiz confiável
       (lista do sistema + certificados que o usuário marcar como confiáveis).
       Resultados possíveis: CONFIÁVEL, AUTOASSINADO (sem cadeia) ou
       SEM CADEIA DE CONFIANÇA RECONHECIDA.

Além disso, verifica ALTERAÇÕES FEITAS APÓS A ASSINATURA (atualizações
incrementais acrescentadas depois que o documento foi assinado).

Assim a aplicação distingue "assinatura inválida" (A ou B falharam)
de "certificado não confiável" (C falhou, mas A e B estão corretos).
"""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import SignatureCoverageLevel
from pyhanko_certvalidator import ValidationContext
from asn1crypto import x509 as asn1_x509

from .certificados import carregar_certificado, descrever_certificado, eh_autoassinado

# O pyHanko emite avisos de log detalhados; aqui deixamos só os erros.
logging.getLogger("pyhanko").setLevel(logging.ERROR)
logging.getLogger("pyhanko_certvalidator").setLevel(logging.ERROR)


@dataclass
class ResultadoAssinaturaPdf:
    """Relatório de UMA assinatura encontrada no documento."""

    campo: str
    certificado: dict | None = None
    data_assinatura: str | None = None
    motivo: str | None = None
    local: str | None = None
    algoritmo_hash: str | None = None
    hash_calculado: str | None = None     # SHA-256 recalculado agora
    hash_assinado: str | None = None      # SHA-256 gravado dentro da assinatura
    integro: bool = False                 # (A) hashes iguais
    criptograficamente_valida: bool = False  # (B) assinatura RSA confere
    assinatura_valida: bool = False       # (A) e (B)
    confianca: str = ""                   # (C) CONFIÁVEL / AUTOASSINADO / SEM CADEIA
    confianca_detalhe: str = ""
    confiavel: bool = False
    cobertura: str = ""
    alterado_apos_assinatura: bool = False
    alteracoes_detalhe: str = ""
    revisao_assinada: int | None = None
    total_revisoes: int | None = None
    erros: list[str] = field(default_factory=list)
    veredito: str = ""
    nivel: str = "erro"                   # usado para colorir a interface: ok / alerta / erro


@dataclass
class RelatorioValidacao:
    possui_assinaturas: bool
    quantidade: int
    total_revisoes: int
    assinaturas: list[ResultadoAssinaturaPdf]


def montar_contexto_validacao(certificados_confiaveis: list[bytes] | None) -> ValidationContext:
    """
    Cria o contexto de validação da cadeia de certificados.

    - `extra_trust_roots`: certificados que o USUÁRIO declarou confiáveis
      (ex.: o .crt público do colega). São somados às raízes do sistema.
    - `allow_fetching=False`: não acessa a internet (CRL/OCSP); a aplicação
      funciona offline.
    """
    raizes = []
    for dados in certificados_confiaveis or []:
        cert = carregar_certificado(dados)
        raizes.append(asn1_x509.Certificate.load(cert.public_bytes(Encoding.DER)))
    return ValidationContext(
        extra_trust_roots=raizes,
        allow_fetching=False,
        revocation_mode="soft-fail",
    )


def _hash_dentro_da_assinatura(assinatura) -> bytes | None:
    """
    Lê o atributo assinado `messageDigest` da estrutura CMS: é o hash do
    documento calculado NO MOMENTO da assinatura.
    """
    atributos = assinatura.signer_info["signed_attrs"]
    for attr in atributos:
        if attr["type"].native == "message_digest":
            return attr["values"][0].native
    return None


def _texto_cobertura(cobertura) -> str:
    return {
        SignatureCoverageLevel.ENTIRE_FILE: "A assinatura cobre o arquivo inteiro.",
        SignatureCoverageLevel.ENTIRE_REVISION: (
            "A assinatura cobre a revisão assinada; existem dados acrescentados depois."
        ),
        SignatureCoverageLevel.CONTIGUOUS_BLOCK_FROM_START: (
            "A assinatura cobre apenas um bloco inicial do arquivo."
        ),
        SignatureCoverageLevel.UNCLEAR: "Não foi possível determinar a cobertura.",
    }.get(cobertura, str(cobertura))


def _analisar_alteracoes(status, assinatura, total_revisoes) -> tuple[bool, str]:
    """
    Requisito 16 — Identifica alterações realizadas APÓS a assinatura.

    Cada vez que um PDF é salvo de forma incremental, uma nova "revisão" é
    acrescentada ao final do arquivo. Se existem revisões posteriores à
    revisão assinada, o pyHanko compara as duas versões (diff) e classifica:
      NONE / LTA_UPDATES -> nada relevante mudou
      FORM_FILLING       -> preenchimento de formulário / novas assinaturas
      ANNOTATIONS        -> comentários/anotações
      OTHER              -> alteração de conteúdo NÃO permitida
    """
    if status.coverage == SignatureCoverageLevel.ENTIRE_FILE:
        return False, "Nenhuma alteração após a assinatura (a assinatura cobre o arquivo inteiro)."

    revisoes_depois = None
    if total_revisoes is not None and assinatura.signed_revision is not None:
        revisoes_depois = total_revisoes - 1 - assinatura.signed_revision
    prefixo = (
        f"Foram encontradas {revisoes_depois} revisão(ões) acrescentada(s) após a assinatura. "
        if revisoes_depois
        else "Foram acrescentados dados após a assinatura. "
    )

    nivel = status.modification_level
    if nivel in (ModificationLevel.NONE, ModificationLevel.LTA_UPDATES):
        return True, prefixo + "As mudanças não afetam o conteúdo assinado (ex.: dados de validação)."
    if nivel == ModificationLevel.FORM_FILLING:
        return True, prefixo + "Mudanças permitidas: preenchimento de formulário ou nova assinatura."
    if nivel == ModificationLevel.ANNOTATIONS:
        return True, prefixo + "Foram adicionadas anotações/comentários ao documento."
    return True, prefixo + (
        "ALTERAÇÃO NÃO PERMITIDA: o conteúdo do documento foi modificado depois "
        "da assinatura (ex.: texto, páginas ou objetos alterados)."
    )


def _classificar_confianca(status, cert_crypto) -> tuple[bool, str, str]:
    """
    Requisito 18 — Informa SEPARADAMENTE a situação do certificado.
    """
    if status.trusted:
        return True, "CONFIÁVEL", (
            "Foi possível montar uma cadeia de certificação até uma raiz confiável."
        )
    if cert_crypto is not None and eh_autoassinado(cert_crypto):
        return False, "AUTOASSINADO", (
            "O certificado foi emitido por ele mesmo e NÃO possui uma cadeia de "
            "confiança reconhecida. A assinatura pode ser matematicamente válida, "
            "mas a identidade do titular não é garantida por uma Autoridade "
            "Certificadora. Para confiar nele, informe o .crt como confiável."
        )
    return False, "SEM CADEIA DE CONFIANÇA RECONHECIDA", (
        "O emissor do certificado não é reconhecido por nenhuma raiz confiável."
    )


def validar_assinatura(assinatura, contexto: ValidationContext, total_revisoes: int) -> ResultadoAssinaturaPdf:
    """Valida UMA assinatura embutida e monta o relatório correspondente."""
    r = ResultadoAssinaturaPdf(campo=assinatura.field_name)
    r.total_revisoes = total_revisoes
    r.revisao_assinada = assinatura.signed_revision

    # Requisito 14 — informações do certificado utilizado.
    cert_crypto = None
    try:
        cert_crypto = x509.load_der_x509_certificate(assinatura.signer_cert.dump())
        r.certificado = descrever_certificado(cert_crypto)
    except Exception as erro:  # pragma: no cover
        r.erros.append(f"Não foi possível ler o certificado: {erro}")

    dicionario = assinatura.sig_object
    r.motivo = dicionario.get("/Reason")
    r.local = dicionario.get("/Location")
    if assinatura.self_reported_timestamp:
        r.data_assinatura = assinatura.self_reported_timestamp.strftime("%d/%m/%Y %H:%M:%S %Z")

    # Requisito 15 — recalcula o hash e compara com o hash assinado.
    r.algoritmo_hash = assinatura.md_algorithm.upper()
    try:
        r.hash_calculado = assinatura.compute_digest().hex().upper()
        hash_assinado = _hash_dentro_da_assinatura(assinatura)
        r.hash_assinado = hash_assinado.hex().upper() if hash_assinado else None
    except Exception as erro:
        r.erros.append(f"Falha ao calcular o hash: {erro}")

    try:
        status = validate_pdf_signature(assinatura, signer_validation_context=contexto)
    except Exception as erro:  # estrutura CMS corrompida, certificado ilegível etc.
        r.erros.append(f"Erro na validação: {erro}")
        r.veredito = "ASSINATURA INVÁLIDA — a estrutura da assinatura não pôde ser verificada."
        return r

    r.integro = bool(status.intact)
    r.criptograficamente_valida = bool(status.valid)
    r.assinatura_valida = r.integro and r.criptograficamente_valida
    r.cobertura = _texto_cobertura(status.coverage)
    r.confiavel, r.confianca, r.confianca_detalhe = _classificar_confianca(status, cert_crypto)
    r.alterado_apos_assinatura, r.alteracoes_detalhe = _analisar_alteracoes(
        status, assinatura, total_revisoes
    )
    alteracao_proibida = (
        status.coverage != SignatureCoverageLevel.ENTIRE_FILE
        and status.modification_level == ModificationLevel.OTHER
    ) or status.docmdp_ok is False

    # Requisito 17 + regra "distinguir assinatura inválida de certificado não confiável".
    if not r.assinatura_valida:
        r.nivel = "erro"
        motivo = (
            "o hash do documento não confere com o hash assinado (conteúdo adulterado)"
            if not r.integro
            else "a assinatura não confere com a chave pública do certificado"
        )
        r.veredito = f"ASSINATURA INVÁLIDA — {motivo}."
    elif alteracao_proibida:
        r.nivel = "erro"
        r.veredito = (
            "ASSINATURA VÁLIDA para a versão assinada, porém o DOCUMENTO FOI ALTERADO "
            "após a assinatura — o conteúdo atual não é o que foi assinado."
        )
    elif not r.confiavel:
        r.nivel = "alerta"
        r.veredito = (
            "ASSINATURA CRIPTOGRAFICAMENTE VÁLIDA e documento íntegro, porém o "
            f"certificado é: {r.confianca}."
        )
    else:
        r.nivel = "ok"
        r.veredito = "ASSINATURA VÁLIDA, documento íntegro e certificado confiável."
    return r


def validar_pdf_assinado(
    pdf: bytes, certificados_confiaveis: list[bytes] | None = None
) -> RelatorioValidacao:
    """
    Requisitos 12 e 13 — Recebe o PDF, localiza TODAS as assinaturas e
    valida cada uma delas.
    """
    if not pdf or pdf.lstrip()[:5] != b"%PDF-":
        raise ValueError("O arquivo enviado não é um PDF válido.")

    leitor = PdfFileReader(io.BytesIO(pdf), strict=False)
    assinaturas = leitor.embedded_signatures
    total_revisoes = leitor.xrefs.total_revisions
    contexto = montar_contexto_validacao(certificados_confiaveis)

    resultados = [validar_assinatura(a, contexto, total_revisoes) for a in assinaturas]
    return RelatorioValidacao(
        possui_assinaturas=bool(assinaturas),
        quantidade=len(assinaturas),
        total_revisoes=total_revisoes,
        assinaturas=resultados,
    )
