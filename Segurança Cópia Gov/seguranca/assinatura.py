"""
Funcionalidade 2 — Assinatura digital de documentos PDF
========================================================

Fluxo implementado:

  7.  O usuário seleciona um documento PDF.
  8.  O usuário seleciona o certificado (.pfx) e informa a senha, o que dá
      acesso à CHAVE PRIVADA correspondente.
  9.  O documento é assinado com criptografia assimétrica (RSA + SHA-256):
        a) calcula-se o HASH SHA-256 dos bytes do PDF (exceto o espaço
           reservado para a própria assinatura -> /ByteRange);
        b) o hash é cifrado com a CHAVE PRIVADA (RSA) -> assinatura;
        c) assinatura + certificado são empacotados em uma estrutura
           CMS/PKCS#7 (padrão PAdES, SubFilter /ETSI.CAdES.detached).
  10. Um novo PDF é gerado com a assinatura INCORPORADA em um campo de
      assinatura (/Sig) — reconhecido pelo Adobe Acrobat Reader.
  11. O conteúdo original é preservado: a assinatura é gravada como uma
      "atualização incremental", ou seja, os bytes originais do arquivo
      não são alterados; apenas novos objetos são acrescentados ao final.

Biblioteca utilizada: `pyHanko` (https://github.com/MatthiasValvekens/pyHanko).
"""

from __future__ import annotations

import io
from dataclasses import dataclass

from pyhanko import stamp
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers

from .certificados import descrever_certificado


@dataclass
class ResultadoAssinatura:
    pdf_assinado: bytes
    nome_campo: str
    titular: dict


def validar_pdf(dados: bytes) -> None:
    """Verificação básica: o arquivo precisa começar com o cabeçalho '%PDF-'."""
    if not dados or not dados.lstrip()[:5] == b"%PDF-":
        raise ValueError("O arquivo enviado não é um PDF válido.")


def carregar_assinante(pfx: bytes, senha: str) -> signers.SimpleSigner:
    """
    Requisito 8 — Abre o arquivo PKCS#12 (.pfx) com a senha e obtém:
      - a CHAVE PRIVADA (usada para assinar);
      - o CERTIFICADO (que contém a chave pública e será embutido no PDF).
    Se a senha estiver errada, o arquivo não pode ser decifrado.
    """
    try:
        assinante = signers.SimpleSigner.load_pkcs12_data(
            pkcs12_bytes=pfx, other_certs=[], passphrase=senha.encode("utf-8")
        )
    except Exception as erro:  # senha incorreta ou arquivo corrompido
        raise ValueError(
            "Não foi possível abrir o certificado .pfx. Verifique a senha."
        ) from erro
    if assinante is None:
        raise ValueError("Não foi possível abrir o certificado .pfx. Verifique a senha.")
    return assinante


def proximo_nome_de_campo(leitor: PdfFileReader) -> str:
    """Gera um nome único para o campo de assinatura (Assinatura1, Assinatura2...)."""
    existentes = {s.field_name for s in leitor.embedded_signatures}
    n = 1
    while f"Assinatura{n}" in existentes:
        n += 1
    return f"Assinatura{n}"


def assinar_pdf(
    pdf: bytes,
    pfx: bytes,
    senha: str,
    motivo: str = "",
    local: str = "",
    visivel: bool = True,
) -> ResultadoAssinatura:
    """
    Requisitos 7 a 11 — Assina digitalmente o PDF e devolve o novo arquivo.

    Parâmetros:
      pdf     -> bytes do documento original
      pfx     -> bytes do certificado PKCS#12 (certificado + chave privada)
      senha   -> senha que protege a chave privada
      motivo  -> motivo da assinatura (aparece no Adobe Reader)
      local   -> local da assinatura
      visivel -> se True, desenha um carimbo na 1ª página. O carimbo é apenas
                 a APARÊNCIA; a assinatura real é a estrutura criptográfica
                 CMS gravada no dicionário /Sig.
    """
    validar_pdf(pdf)
    assinante = carregar_assinante(pfx, senha)

    # IncrementalPdfFileWriter = atualização incremental (preserva o original).
    escritor = IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)
    nome_campo = proximo_nome_de_campo(escritor.prev)

    metadados = signers.PdfSignatureMetadata(
        field_name=nome_campo,
        md_algorithm="sha256",                          # função hash usada
        subfilter=fields.SigSeedSubFilter.PADES,        # padrão PAdES (ETSI.CAdES.detached)
        reason=motivo or None,
        location=local or None,
    )

    especificacao_campo = None
    estilo = None
    if visivel:
        # Retângulo (x1, y1, x2, y2) em pontos, no canto inferior esquerdo da página 1.
        caixa = (40, 40, 300, 110)
        especificacao_campo = fields.SigFieldSpec(
            sig_field_name=nome_campo, on_page=0, box=caixa
        )
        estilo = stamp.TextStampStyle(
            stamp_text=(
                "Assinado digitalmente por:\n%(signer)s\n"
                "Data: %(ts)s"
            ),
            border_width=1,
        )
    else:
        especificacao_campo = fields.SigFieldSpec(sig_field_name=nome_campo)

    assinador_pdf = signers.PdfSigner(
        metadados,
        signer=assinante,
        stamp_style=estilo,
        new_field_spec=especificacao_campo,
    )

    saida = io.BytesIO()
    # Aqui acontece a assinatura: cálculo do hash do /ByteRange + RSA com a chave privada.
    assinador_pdf.sign_pdf(escritor, output=saida)

    certificado = assinante.signing_cert.dump()
    from cryptography import x509  # import local para não poluir o módulo

    return ResultadoAssinatura(
        pdf_assinado=saida.getvalue(),
        nome_campo=nome_campo,
        titular=descrever_certificado(x509.load_der_x509_certificate(certificado)),
    )
