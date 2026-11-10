"""
Gera o PDF de exemplo `contrato_exemplo.pdf` usado nos testes.

O conteúdo é gravado SEM compressão para que o texto "R$ 1.000,00" fique
legível nos bytes do arquivo — isso permite demonstrar a adulteração
direta (Funcionalidade 4).

Uso:  python exemplos/gerar_pdf_exemplo.py
"""
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

DESTINO = Path(__file__).with_name("contrato_exemplo.pdf")


def gerar(destino: Path = DESTINO) -> Path:
    c = canvas.Canvas(str(destino), pagesize=A4, pageCompression=0, invariant=1)
    c.setTitle("Contrato de Prestação de Serviços - Exemplo")
    largura, altura = A4
    c.setFont("Helvetica-Bold", 18)
    c.drawString(60, altura - 90, "CONTRATO DE PRESTACAO DE SERVICOS")
    c.setFont("Helvetica", 12)
    linhas = [
        "Documento de exemplo para o trabalho de Seguranca de Software.",
        "",
        "CONTRATANTE: Prefeitura Municipal de Exemplo",
        "CONTRATADA: Empresa Ficticia de Tecnologia LTDA",
        "",
        "Clausula 1 - Objeto: desenvolvimento de sistema de assinatura digital.",
        "Clausula 2 - Valor total do contrato: R$ 1.000,00",
        "Clausula 3 - Prazo de execucao: 30 dias.",
        "",
        "Este documento sera assinado digitalmente (PAdES / RSA / SHA-256).",
        "Qualquer alteracao apos a assinatura deve ser detectada pela aplicacao.",
    ]
    y = altura - 140
    for linha in linhas:
        c.drawString(60, y, linha)
        y -= 20
    c.showPage()
    c.save()
    return destino


if __name__ == "__main__":
    print(f"PDF gerado em: {gerar()}")
