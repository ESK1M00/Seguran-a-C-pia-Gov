"""
Segurança Assinatura Digital — aplicação web (Flask)
============================================

Este arquivo contém apenas a CAMADA WEB: recebe os formulários, chama as
funções do pacote `seguranca/` e devolve as páginas HTML.

Rotas:
  GET  /                    -> página inicial com o fluxo completo
  GET/POST /certificado     -> Funcionalidade 1 (gerar certificado)
  GET/POST /assinar         -> Funcionalidade 2 (assinar PDF)
  GET/POST /validar         -> Funcionalidade 3 (validar assinaturas)
  GET/POST /integridade     -> Funcionalidade 4 (teste de integridade)
  GET  /baixar/<token>/<id> -> download dos arquivos gerados

Boas práticas de segurança aplicadas:
  - Nenhum arquivo enviado é gravado em disco: tudo é processado em memória.
  - Arquivos gerados ficam em um cache temporário (15 min) e são acessados
    por um token aleatório; o .pfx só pode ser baixado UMA vez.
  - Proteção CSRF simples (token na sessão + campo oculto nos formulários).
  - Limite de tamanho de upload (20 MB) e verificação do cabeçalho %PDF-.
  - Cabeçalhos HTTP de segurança (CSP, X-Frame-Options, nosniff...).
  - Por padrão o servidor escuta apenas em 127.0.0.1 (máquina local).
"""

from __future__ import annotations

import hmac
import os
import re
import secrets
import threading
import time
from io import BytesIO

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from seguranca.assinatura import assinar_pdf
from seguranca.certificados import (
    TAMANHOS_PERMITIDOS,
    DadosTitular,
    descrever_certificado,
    gerar_certificado_completo,
)
from seguranca.integridade import adulterar_bytes, alterar_incrementalmente
from seguranca.validacao import validar_pdf_assinado

app = Flask(__name__)
# Chave usada para assinar o cookie de sessão. Gerada a cada execução se não for informada.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"


# --------------------------------------------------------------------------
# Cache temporário em memória para os arquivos gerados
# --------------------------------------------------------------------------
TEMPO_EXPIRACAO = 15 * 60  # segundos
_cache: dict[str, dict] = {}
_trava = threading.Lock()


def guardar_arquivos(arquivos: dict[str, tuple[str, bytes, str]], uso_unico: set[str] | None = None) -> str:
    """
    Guarda arquivos gerados em memória e devolve um token aleatório.
    `arquivos` = {id: (nome_do_arquivo, conteúdo, mimetype)}.
    Ids em `uso_unico` são apagados após o primeiro download (ex.: o .pfx).
    """
    token = secrets.token_urlsafe(24)
    with _trava:
        _limpar_expirados()
        _cache[token] = {
            "criado": time.time(),
            "arquivos": arquivos,
            "uso_unico": uso_unico or set(),
        }
    return token


def _limpar_expirados() -> None:
    agora = time.time()
    for token in [t for t, v in _cache.items() if agora - v["criado"] > TEMPO_EXPIRACAO]:
        del _cache[token]


@app.get("/baixar/<token>/<ident>")
def baixar(token: str, ident: str):
    """Entrega um arquivo do cache. Retorna 404 se expirou ou já foi baixado."""
    with _trava:
        _limpar_expirados()
        item = _cache.get(token)
        if not item or ident not in item["arquivos"]:
            abort(404)
        nome, conteudo, tipo = item["arquivos"][ident]
        if ident in item["uso_unico"]:
            del item["arquivos"][ident]
    return send_file(BytesIO(conteudo), mimetype=tipo, as_attachment=True, download_name=nome)


# --------------------------------------------------------------------------
# Proteção CSRF e cabeçalhos de segurança
# --------------------------------------------------------------------------
def token_csrf() -> str:
    """Cria (uma vez por sessão) o token CSRF incluído em todos os formulários."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = token_csrf


@app.before_request
def verificar_csrf():
    """Rejeita POSTs cujo token não confere com o da sessão (ataque CSRF)."""
    if request.method == "POST":
        enviado = request.form.get("csrf", "")
        esperado = session.get("csrf", "")
        if not esperado or not hmac.compare_digest(enviado, esperado):
            abort(400, "Token CSRF inválido. Recarregue a página e tente novamente.")


@app.after_request
def cabecalhos_seguranca(resposta):
    resposta.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:"
    )
    resposta.headers["X-Frame-Options"] = "DENY"
    resposta.headers["X-Content-Type-Options"] = "nosniff"
    resposta.headers["Referrer-Policy"] = "no-referrer"
    resposta.headers["Cache-Control"] = "no-store"
    return resposta


@app.errorhandler(413)
def arquivo_grande(_):
    flash("Arquivo muito grande (limite de 20 MB).", "erro")
    return redirect(request.path)


# --------------------------------------------------------------------------
# Funções auxiliares
# --------------------------------------------------------------------------
def ler_arquivo(campo: str, obrigatorio: bool = True) -> bytes | None:
    """Lê um arquivo enviado pelo formulário (em memória)."""
    arquivo = request.files.get(campo)
    if not arquivo or not arquivo.filename:
        if obrigatorio:
            raise ValueError("Selecione o arquivo solicitado.")
        return None
    return arquivo.read()


def nome_seguro(texto: str, padrao: str = "documento") -> str:
    """Remove caracteres perigosos de nomes de arquivos."""
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", texto or "").strip("._")
    return base[:60] or padrao


# --------------------------------------------------------------------------
# Páginas
# --------------------------------------------------------------------------
@app.get("/")
def inicio():
    return render_template("index.html")


@app.route("/certificado", methods=["GET", "POST"])
def certificado():
    """Funcionalidade 1 — formulário e geração do certificado X.509."""
    if request.method == "GET":
        return render_template("certificado.html", tamanhos=TAMANHOS_PERMITIDOS)

    f = request.form
    try:
        senha, confirmacao = f.get("senha", ""), f.get("senha2", "")
        if senha != confirmacao:
            raise ValueError("As senhas não conferem.")
        dados = DadosTitular(
            nome_comum=f.get("cn", ""),
            organizacao=f.get("o", ""),
            unidade=f.get("ou", ""),
            cidade=f.get("l", ""),
            estado=f.get("st", ""),
            pais=f.get("c", "BR"),
            email=f.get("email", ""),
        )
        gerado = gerar_certificado_completo(
            dados,
            senha_pfx=senha,
            dias_validade=int(f.get("dias", "365")),
            tamanho_bits=int(f.get("bits", "2048")),
        )
    except ValueError as erro:
        flash(str(erro), "erro")
        return render_template("certificado.html", tamanhos=TAMANHOS_PERMITIDOS, form=f), 400

    base = nome_seguro(dados.nome_comum, "certificado")
    token = guardar_arquivos(
        {
            "crt": (f"{base}.crt", gerado.certificado_pem, "application/x-x509-ca-cert"),
            "pfx": (f"{base}.pfx", gerado.pacote_pfx, "application/x-pkcs12"),
        },
        uso_unico={"pfx"},
    )
    return render_template(
        "certificado_gerado.html",
        info=descrever_certificado(gerado.certificado),
        pem=gerado.certificado_pem.decode(),
        token=token,
    )


@app.route("/assinar", methods=["GET", "POST"])
def assinar():
    """Funcionalidade 2 — assina o PDF com o certificado .pfx."""
    if request.method == "GET":
        return render_template("assinar.html")
    try:
        pdf = ler_arquivo("pdf")
        pfx = ler_arquivo("pfx")
        arquivo_pdf = request.files["pdf"].filename
        resultado = assinar_pdf(
            pdf,
            pfx,
            request.form.get("senha", ""),
            motivo=request.form.get("motivo", ""),
            local=request.form.get("local", ""),
            visivel=request.form.get("visivel") == "on",
        )
    except ValueError as erro:
        flash(str(erro), "erro")
        return render_template("assinar.html"), 400

    nome = nome_seguro(arquivo_pdf.rsplit(".", 1)[0]) + "_assinado.pdf"
    token = guardar_arquivos({"pdf": (nome, resultado.pdf_assinado, "application/pdf")})
    relatorio = validar_pdf_assinado(resultado.pdf_assinado)
    return render_template(
        "assinado.html", resultado=resultado, token=token, nome=nome, relatorio=relatorio
    )


@app.route("/validar", methods=["GET", "POST"])
def validar():
    """Funcionalidade 3 — valida as assinaturas de um PDF."""
    if request.method == "GET":
        return render_template("validar.html")
    try:
        pdf = ler_arquivo("pdf")
        confiaveis = [a.read() for a in request.files.getlist("confiaveis") if a and a.filename]
        relatorio = validar_pdf_assinado(pdf, confiaveis)
    except ValueError as erro:
        flash(str(erro), "erro")
        return render_template("validar.html"), 400
    except Exception:
        flash("Não foi possível ler o arquivo. Verifique se é um PDF e se os certificados são .crt/.pem válidos.", "erro")
        return render_template("validar.html"), 400
    return render_template("relatorio.html", relatorio=relatorio, arquivo=request.files["pdf"].filename)


@app.route("/integridade", methods=["GET", "POST"])
def integridade():
    """Funcionalidade 4 — altera um PDF assinado e compara a validação antes/depois."""
    if request.method == "GET":
        return render_template("integridade.html")
    try:
        pdf = ler_arquivo("pdf")
        modo = request.form.get("modo", "bytes")
        if modo == "bytes":
            alterado = adulterar_bytes(
                pdf, request.form.get("original", ""), request.form.get("novo", "")
            )
        else:
            alterado = alterar_incrementalmente(
                pdf, request.form.get("texto", "") or "DOCUMENTO ALTERADO APOS A ASSINATURA"
            )
        antes = validar_pdf_assinado(pdf)
        depois = validar_pdf_assinado(alterado)
    except ValueError as erro:
        flash(str(erro), "erro")
        return render_template("integridade.html"), 400
    except Exception:
        flash("Não foi possível processar o PDF. Envie um PDF assinado digitalmente.", "erro")
        return render_template("integridade.html"), 400

    token = guardar_arquivos({"pdf": ("documento_modificado.pdf", alterado, "application/pdf")})
    return render_template(
        "integridade_resultado.html", antes=antes, depois=depois, token=token, modo=modo
    )


if __name__ == "__main__":
    # debug=False: o modo debug do Flask permite execução de código remoto se exposto.
    host = os.environ.get("HOST", "127.0.0.1")
    porta = int(os.environ.get("PORT", "5000"))
    print(f"Acesse: http://{host}:{porta}")
    app.run(host=host, port=porta, debug=False)
