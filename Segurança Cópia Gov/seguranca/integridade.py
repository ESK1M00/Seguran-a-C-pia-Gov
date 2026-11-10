"""
Funcionalidade 4 — Verificação de integridade
==============================================

Este módulo MODIFICA de propósito um PDF já assinado, para demonstrar que
a validação detecta a alteração (requisitos 19 a 22). Há dois tipos de
ataque simulados:

  1) ADULTERAÇÃO DIRETA DOS BYTES ("substituir texto")
     Troca um trecho de texto DENTRO da área coberta pela assinatura
     (ex.: "R$ 1.000,00" -> "R$ 9.000,00"). Como os bytes assinados mudam,
     o hash SHA-256 recalculado deixa de bater com o hash gravado na
     assinatura -> ASSINATURA INVÁLIDA (falha de integridade).

  2) ALTERAÇÃO INCREMENTAL ("acrescentar conteúdo")
     Acrescenta uma nova revisão ao final do arquivo que escreve um texto
     por cima da página 1 (do jeito que um editor de PDF faria). Os bytes
     assinados continuam intactos, mas a aplicação percebe que existe uma
     revisão posterior que alterou o conteúdo -> DOCUMENTO ALTERADO APÓS
     A ASSINATURA.
"""

from __future__ import annotations

import io

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader


def _intervalos_assinados(pdf: bytes) -> list[tuple[int, int]]:
    """Lê o /ByteRange da primeira assinatura: [(início, fim), (início, fim)]."""
    leitor = PdfFileReader(io.BytesIO(pdf), strict=False)
    assinaturas = leitor.embedded_signatures
    if not assinaturas:
        raise ValueError("O PDF enviado não possui assinatura digital.")
    a, b, c, d = [int(x) for x in assinaturas[0].byte_range]
    return [(a, a + b), (c, c + d)]


def adulterar_bytes(pdf: bytes, texto_original: str, texto_novo: str) -> bytes:
    """
    Ataque 1 — substitui `texto_original` por `texto_novo` diretamente nos
    bytes do arquivo, sem recalcular a assinatura.

    Os textos precisam ter o MESMO tamanho, para não deslocar as posições
    (offsets) dos objetos do PDF. Se o texto não for encontrado de forma
    legível (PDFs com conteúdo comprimido), alteramos 1 único byte dentro
    da área assinada — o efeito no hash é o mesmo ("efeito avalanche").
    """
    intervalos = _intervalos_assinados(pdf)
    dados = bytearray(pdf)

    if texto_original:
        if len(texto_original) != len(texto_novo):
            raise ValueError("O texto novo deve ter o mesmo número de caracteres do original.")
        alvo = texto_original.encode("latin-1", errors="strict")
        novo = texto_novo.encode("latin-1", errors="strict")
        pos = dados.find(alvo)
        if pos != -1 and any(i <= pos < f for i, f in intervalos):
            dados[pos : pos + len(alvo)] = novo
            return bytes(dados)

    # Alternativa: altera 1 byte dentro do primeiro "stream" da área assinada.
    inicio, fim = intervalos[0]
    pos = dados.find(b"stream", inicio, fim)
    pos = (pos + 20) if pos != -1 else (inicio + fim) // 2
    pos = min(pos, fim - 1)
    dados[pos] ^= 0x01
    return bytes(dados)


def _escapar_texto_pdf(texto: str) -> bytes:
    """Escapa caracteres especiais de strings literais do PDF: \\ ( )."""
    bruto = texto.encode("latin-1", errors="replace")
    return bruto.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def alterar_incrementalmente(pdf: bytes, texto: str = "DOCUMENTO ALTERADO APOS A ASSINATURA") -> bytes:
    """
    Ataque 2 — acrescenta uma atualização incremental que desenha uma faixa
    vermelha com `texto` no topo da página 1.
    """
    _intervalos_assinados(pdf)  # garante que o PDF está assinado
    escritor = IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)

    fonte = generic.DictionaryObject(
        {
            generic.NameObject("/Type"): generic.NameObject("/Font"),
            generic.NameObject("/Subtype"): generic.NameObject("/Type1"),
            generic.NameObject("/BaseFont"): generic.NameObject("/Helvetica-Bold"),
            generic.NameObject("/Encoding"): generic.NameObject("/WinAnsiEncoding"),
        }
    )
    recursos = generic.DictionaryObject(
        {
            generic.NameObject("/Font"): generic.DictionaryObject(
                {generic.NameObject("/FAlt"): escritor.add_object(fonte)}
            )
        }
    )
    # Operadores de desenho do PDF: retângulo vermelho (re f) + texto branco (BT ... Tj ET).
    conteudo = (
        b"q 0.85 0.1 0.1 rg 30 760 540 40 re f "
        b"BT 1 1 1 rg /FAlt 16 Tf 45 775 Td (" + _escapar_texto_pdf(texto) + b") Tj ET Q"
    )
    fluxo = generic.StreamObject(stream_data=conteudo)
    escritor.add_stream_to_page(0, escritor.add_object(fluxo), resources=recursos)

    saida = io.BytesIO()
    escritor.write(saida)
    return saida.getvalue()
