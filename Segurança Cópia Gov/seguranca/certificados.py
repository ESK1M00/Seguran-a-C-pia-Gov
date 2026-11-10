"""
Funcionalidade 1 — Geração de certificados digitais
====================================================

Este módulo é responsável por:

  1. Gerar um par de chaves RSA (pública + privada) de no mínimo 2048 bits.
  2. Criar um certificado X.509 AUTOASSINADO (o emissor é o próprio titular).
  3. Receber os dados de identificação do titular (Nome, Organização, etc.).
  4. Definir o período de validade (data de início e de fim).
  5. Exportar o certificado:
       - .crt / .pem  -> SOMENTE o certificado público (pode ser publicado);
       - .pfx / .p12  -> certificado + chave privada, protegido por senha
                         (NUNCA deve ser publicado no repositório).

Biblioteca utilizada: `cryptography` (https://cryptography.io).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Requisito 6: RSA com chaves de, no mínimo, 2048 bits.
TAMANHO_MINIMO_CHAVE = 2048
TAMANHOS_PERMITIDOS = (2048, 3072, 4096)


@dataclass
class DadosTitular:
    """Dados de identificação do titular do certificado (requisito 3)."""

    nome_comum: str              # CN  - Common Name (ex.: "Maria da Silva")
    organizacao: str = ""        # O   - Organization
    unidade: str = ""            # OU  - Organizational Unit
    cidade: str = ""             # L   - Locality
    estado: str = ""             # ST  - State or Province
    pais: str = "BR"             # C   - Country (2 letras)
    email: str = ""              # E   - e-mail do titular


@dataclass
class CertificadoGerado:
    """Resultado da geração: objetos criptográficos e arquivos exportados."""

    certificado: x509.Certificate
    chave_privada: rsa.RSAPrivateKey
    certificado_pem: bytes       # certificado público em formato PEM (.crt)
    pacote_pfx: bytes            # PKCS#12 (.pfx) = certificado + chave privada cifrada


def gerar_par_de_chaves(tamanho_bits: int = 2048) -> rsa.RSAPrivateKey:
    """
    Requisitos 1 e 6 — Gera um par de chaves RSA.

    - `public_exponent=65537` é o expoente público padrão (seguro e eficiente).
    - A chave pública é derivada da privada: `chave_privada.public_key()`.
    - Lança ValueError se o tamanho for menor que 2048 bits.
    """
    if tamanho_bits < TAMANHO_MINIMO_CHAVE:
        raise ValueError(
            f"O tamanho mínimo da chave RSA é {TAMANHO_MINIMO_CHAVE} bits."
        )
    if tamanho_bits not in TAMANHOS_PERMITIDOS:
        raise ValueError(f"Tamanho de chave inválido. Use {TAMANHOS_PERMITIDOS}.")
    return rsa.generate_private_key(public_exponent=65537, key_size=tamanho_bits)


def montar_nome_distinto(dados: DadosTitular) -> x509.Name:
    """
    Requisito 3 — Converte os dados do titular em um "Distinguished Name" (DN)
    do padrão X.509, por exemplo: CN=Maria, O=UniRV, C=BR.
    Campos vazios são ignorados.
    """
    if not dados.nome_comum.strip():
        raise ValueError("O nome do titular (CN) é obrigatório.")

    atributos = [x509.NameAttribute(NameOID.COMMON_NAME, dados.nome_comum.strip())]
    opcionais = [
        (NameOID.ORGANIZATION_NAME, dados.organizacao),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, dados.unidade),
        (NameOID.LOCALITY_NAME, dados.cidade),
        (NameOID.STATE_OR_PROVINCE_NAME, dados.estado),
        (NameOID.EMAIL_ADDRESS, dados.email),
    ]
    for oid, valor in opcionais:
        if valor and valor.strip():
            atributos.append(x509.NameAttribute(oid, valor.strip()))

    pais = (dados.pais or "").strip().upper()
    if pais:
        if len(pais) != 2:
            raise ValueError("O país deve ter 2 letras (ex.: BR).")
        atributos.append(x509.NameAttribute(NameOID.COUNTRY_NAME, pais))
    return x509.Name(atributos)


def criar_certificado_autoassinado(
    chave_privada: rsa.RSAPrivateKey,
    dados: DadosTitular,
    dias_validade: int = 365,
    inicio: dt.datetime | None = None,
) -> x509.Certificate:
    """
    Requisitos 2, 3 e 4 — Cria um certificado X.509 v3 autoassinado.

    "Autoassinado" significa que o EMISSOR (issuer) é igual ao TITULAR
    (subject) e que o certificado é assinado com a PRÓPRIA chave privada
    do titular. Por isso não existe uma Autoridade Certificadora (AC)
    reconhecida que garanta a identidade -> o validador mostrará
    "certificado autoassinado / sem cadeia de confiança".

    Extensões incluídas:
      - BasicConstraints: indica que é um certificado final (não é AC);
      - KeyUsage: digitalSignature + nonRepudiation (uso para assinatura);
      - ExtendedKeyUsage: proteção de e-mail / assinatura de documentos;
      - SubjectKeyIdentifier / AuthorityKeyIdentifier: identificam a chave.
    """
    if dias_validade < 1 or dias_validade > 3650:
        raise ValueError("A validade deve estar entre 1 e 3650 dias.")

    nome = montar_nome_distinto(dados)
    inicio = inicio or dt.datetime.now(dt.timezone.utc)
    fim = inicio + dt.timedelta(days=dias_validade)
    chave_publica = chave_privada.public_key()

    construtor = (
        x509.CertificateBuilder()
        .subject_name(nome)                       # TITULAR
        .issuer_name(nome)                        # EMISSOR = titular (autoassinado)
        .public_key(chave_publica)                # chave pública embutida no certificado
        .serial_number(x509.random_serial_number())
        .not_valid_before(inicio)                 # início da validade (requisito 4)
        .not_valid_after(fim)                     # fim da validade    (requisito 4)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,          # = nonRepudiation
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    # OID 1.3.6.1.4.1.311.10.3.12 = "Document Signing" (Microsoft/Adobe)
                    x509.ObjectIdentifier("1.3.6.1.4.1.311.10.3.12"),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(chave_publica), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(chave_publica),
            critical=False,
        )
    )
    if dados.email and dados.email.strip():
        construtor = construtor.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(dados.email.strip())]),
            critical=False,
        )

    # A assinatura do certificado: hash SHA-256 do conteúdo + cifragem RSA com a chave privada.
    return construtor.sign(private_key=chave_privada, algorithm=hashes.SHA256())


def exportar_certificado_pem(certificado: x509.Certificate) -> bytes:
    """Requisito 5 — Exporta SOMENTE o certificado público (formato PEM / .crt)."""
    return certificado.public_bytes(serialization.Encoding.PEM)


def exportar_pfx(
    certificado: x509.Certificate,
    chave_privada: rsa.RSAPrivateKey,
    senha: str,
    nome_amigavel: str = "certificado",
) -> bytes:
    """
    Requisito 5 — Exporta o pacote PKCS#12 (.pfx) contendo certificado e
    chave privada. A chave privada é CIFRADA com a senha informada
    (AES-256-CBC + PBKDF2-SHA256), portanto é necessário conhecê-la para
    usar o arquivo na assinatura.
    """
    if len(senha) < 6:
        raise ValueError("A senha do arquivo .pfx deve ter pelo menos 6 caracteres.")

    cifragem = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50_000)
        .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
        .hmac_hash(hashes.SHA256())
        .build(senha.encode("utf-8"))
    )
    return pkcs12.serialize_key_and_certificates(
        name=nome_amigavel.encode("utf-8"),
        key=chave_privada,
        cert=certificado,
        cas=None,
        encryption_algorithm=cifragem,
    )


def gerar_certificado_completo(
    dados: DadosTitular,
    senha_pfx: str,
    dias_validade: int = 365,
    tamanho_bits: int = 2048,
) -> CertificadoGerado:
    """
    Função "orquestradora" da Funcionalidade 1: executa todos os passos
    (gera chaves -> cria certificado -> exporta .crt e .pfx).
    """
    chave = gerar_par_de_chaves(tamanho_bits)
    cert = criar_certificado_autoassinado(chave, dados, dias_validade)
    return CertificadoGerado(
        certificado=cert,
        chave_privada=chave,
        certificado_pem=exportar_certificado_pem(cert),
        pacote_pfx=exportar_pfx(cert, chave, senha_pfx, dados.nome_comum),
    )


def descrever_certificado(certificado: x509.Certificate) -> dict:
    """
    Extrai as informações principais de um certificado X.509 em um
    dicionário (usado para exibir os dados na interface — requisito 14).
    """
    chave_publica = certificado.public_key()
    tamanho = getattr(chave_publica, "key_size", None)
    sha256 = certificado.fingerprint(hashes.SHA256()).hex(":").upper()
    sha1 = certificado.fingerprint(hashes.SHA1()).hex(":").upper()
    return {
        "titular": certificado.subject.rfc4514_string(),
        "emissor": certificado.issuer.rfc4514_string(),
        "numero_serie": format(certificado.serial_number, "X"),
        "valido_de": certificado.not_valid_before_utc.strftime("%d/%m/%Y %H:%M:%S UTC"),
        "valido_ate": certificado.not_valid_after_utc.strftime("%d/%m/%Y %H:%M:%S UTC"),
        "algoritmo_chave": f"RSA {tamanho} bits" if tamanho else type(chave_publica).__name__,
        "algoritmo_assinatura": certificado.signature_algorithm_oid._name,
        "impressao_sha256": sha256,
        "impressao_sha1": sha1,
        "versao": certificado.version.name,
        "autoassinado": eh_autoassinado(certificado),
    }


def eh_autoassinado(certificado: x509.Certificate) -> bool:
    """
    Verifica se o certificado é autoassinado:
      1. emissor == titular; e
      2. a assinatura do certificado é válida usando a PRÓPRIA chave pública.
    """
    if certificado.issuer != certificado.subject:
        return False
    try:
        certificado.verify_directly_issued_by(certificado)
        return True
    except Exception:  # assinatura não confere / extensões incompatíveis
        return False


def carregar_certificado(dados: bytes) -> x509.Certificate:
    """Carrega um certificado nos formatos PEM ou DER (.crt, .cer, .pem)."""
    try:
        return x509.load_pem_x509_certificate(dados)
    except ValueError:
        return x509.load_der_x509_certificate(dados)
