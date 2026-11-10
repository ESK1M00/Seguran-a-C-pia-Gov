# Segurança Cópia Gov — Assinatura e Validação Digital de PDF

Trabalho Prático de **Segurança de Software**: uma aplicação web que **gera certificados digitais X.509**, **assina documentos PDF** (padrão PAdES, verificável no Adobe Acrobat Reader) e **valida assinaturas**, detectando qualquer alteração feita depois da assinatura.

```
Gerar certificado → Selecionar PDF → Assinar digitalmente → Validar assinatura → Detectar alterações
```

## Integrantes do grupo

- Ezequiel Pereira
- Paulo Vitor Martins
- Matheus Lucas Paes

## Tecnologias

| Item | Escolha |
|------|---------|
| Linguagem | Python 3.10+ |
| Interface | Web (Flask) |
| Criptografia | `cryptography`: RSA, SHA-256, X.509, PKCS#12 |
| PDF | `pyHanko`: assinatura PAdES / CMS e validação |
| Testes | `pytest` |

## Instalação e execução

```bash
# 1. Entre na pasta do projeto
cd "Segurança Cópia Gov"

# 2. Crie e ative um ambiente virtual
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Rode a aplicação
python app.py
```

Abra **http://127.0.0.1:5000** no navegador.

Para rodar os testes automatizados do fluxo completo:

```bash
python -m pytest -v
```

## Estrutura do projeto

```
Segurança Cópia Gov/
├── app.py                      # Camada web (rotas Flask, CSRF, downloads)
├── seguranca/                  # Lógica de segurança (independente da web)
│   ├── certificados.py         # Funcionalidade 1: chaves RSA + certificado X.509
│   ├── assinatura.py           # Funcionalidade 2: assinatura PAdES do PDF
│   ├── validacao.py            # Funcionalidade 3: validação das assinaturas
│   └── integridade.py          # Funcionalidade 4: alteração proposital do PDF
├── templates/                  # Páginas HTML (Jinja2)
├── static/estilo.css           # Estilo visual
├── exemplos/                   # PDFs de teste e certificado público de exemplo
├── testes/                     # Testes automatizados (pytest)
├── EXPLICACAO.md               # Explicação detalhada de cada função
├── requirements.txt            # Dependências
└── .gitignore                  # Impede publicar .pfx/.key (dados sensíveis)
```

## Como usar (roteiro da apresentação)

1. **Gerar certificado** (menu *1. Certificado*): preencha os dados do titular, escolha o tamanho da chave (≥ 2048 bits), a validade e uma senha. Baixe o `.crt` (público) e o `.pfx` (chave privada protegida por senha).
2. **Assinar** (menu *2. Assinar*): selecione um PDF (ex.: `exemplos/contrato_exemplo.pdf`), o `.pfx` e a senha. Baixe o PDF assinado.
3. **Abrir no Adobe Reader**: o painel *Assinaturas* mostra a assinatura. Ele avisa que a identidade é desconhecida porque o certificado é autoassinado. Isso é esperado.
4. **Validar** (menu *3. Validar*): envie o PDF assinado. A aplicação mostra os dados do certificado e o resultado de três verificações separadas:
   - **A) Integridade**: o hash SHA-256 recalculado é igual ao hash assinado?
   - **B) Assinatura criptográfica**: a assinatura RSA confere com a chave pública?
   - **C) Confiança**: o certificado é *confiável*, *autoassinado* ou *sem cadeia de confiança reconhecida*? Envie o `.crt` no campo “certificados confiáveis” para vê-lo como **CONFIÁVEL**.
5. **Modificar o PDF e detectar** (menu *4. Integridade*): envie o PDF assinado e escolha:
   - *Adulterar bytes*: troca “R$ 1.000,00” por “R$ 9.000,00”. O hash muda e o resultado é **ASSINATURA INVÁLIDA**.
   - *Alteração incremental*: acrescenta uma revisão que escreve sobre a página. A assinatura antiga continua válida para a versão assinada, mas a aplicação aponta **DOCUMENTO ALTERADO APÓS A ASSINATURA**.

## Arquivos de exemplo (`exemplos/`)

| Arquivo | Descrição |
|---------|-----------|
| `contrato_exemplo.pdf` | PDF original, sem assinatura |
| `contrato_exemplo_assinado.pdf` | Assinado pela aplicação (válido, autoassinado) |
| `contrato_exemplo_adulterado_bytes.pdf` | Valor alterado nos bytes: assinatura inválida |
| `contrato_exemplo_adulterado_incremental.pdf` | Conteúdo acrescentado após a assinatura |
| `certificado_exemplo_publico.crt` | Certificado **público** gerado pela aplicação |
| `gerar_pdf_exemplo.py` | Script que gera o `contrato_exemplo.pdf` |

> 🔒 **Chaves privadas (`.pfx`, `.p12`, `.key`) e senhas não são publicadas.** O `.gitignore` bloqueia esses arquivos.

## Como as chaves, o hash e o certificado participam do processo

| Elemento | Papel |
|----------|-------|
| **Chave privada** (RSA, dentro do `.pfx`) | Fica só com o titular. Assina o hash do documento. Só ela consegue produzir uma assinatura que a chave pública aceita. |
| **Chave pública** (dentro do certificado) | Vai junto no PDF. Qualquer pessoa usa essa chave para **verificar** a assinatura, mas ela não serve para assinar. |
| **Função hash** (SHA-256) | Gera um “resumo” de 256 bits do documento. Se um único byte mudar, o resumo muda completamente. Assina-se o hash, não o arquivo inteiro. |
| **Certificado X.509** | Liga a chave pública à identidade do titular (nome, organização, validade). Se for emitido por uma AC confiável, essa identidade é garantida. Se for autoassinado, ninguém além do próprio titular garante. |

Mais detalhes em [`EXPLICACAO.md`](EXPLICACAO.md).

## Medidas de segurança da própria aplicação

- Uploads processados **só em memória** (nada é gravado em disco).
- `.pfx` cifrado com **AES-256 + PBKDF2-SHA256**; download disponível **uma única vez**, com expiração de 15 minutos.
- Proteção **CSRF** em todos os formulários.
- Cabeçalhos HTTP de segurança: `Content-Security-Policy`, `X-Frame-Options`, `nosniff`, `no-store`.
- Limite de upload de 20 MB, validação do cabeçalho `%PDF-` e sanitização de nomes de arquivos.
- Servidor escuta só em `127.0.0.1` e roda com `debug=False`.
