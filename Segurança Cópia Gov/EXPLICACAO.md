# Explicação do código: o que cada função faz

Este documento descreve cada arquivo e cada função do projeto, na ordem do fluxo do trabalho.

---

## 1. `seguranca/certificados.py`: Funcionalidade 1 (geração de certificados)

| Função / classe | O que faz | Requisito |
|---|---|---|
| `DadosTitular` | Estrutura com os dados do titular: nome (CN), organização (O), unidade (OU), cidade (L), estado (ST), país (C) e e-mail. | 3 |
| `gerar_par_de_chaves(tamanho_bits)` | Gera o par de chaves **RSA** com expoente público 65537. Recusa tamanhos menores que **2048 bits**. A chave pública é derivada da privada. | 1, 6 |
| `montar_nome_distinto(dados)` | Converte os dados do titular em um *Distinguished Name* X.509 (ex.: `CN=Maria,O=UniRV,C=BR`). Valida o CN obrigatório e o país com 2 letras. | 3 |
| `criar_certificado_autoassinado(chave, dados, dias)` | Monta o certificado **X.509 v3**: titular = emissor (por isso é autoassinado), número de série aleatório, datas de início e fim, extensões (`KeyUsage` para assinatura digital e não repúdio, `ExtendedKeyUsage` para *Document Signing*, identificadores de chave). Depois assina o certificado com SHA-256 + RSA usando a **própria chave privada**. | 2, 4 |
| `exportar_certificado_pem(cert)` | Exporta **só o certificado público** em PEM (`.crt`). Pode ser compartilhado. | 5 |
| `exportar_pfx(cert, chave, senha)` | Exporta certificado e chave privada em **PKCS#12** (`.pfx`). A chave é cifrada com AES-256-CBC e a senha passa por PBKDF2-SHA256 (50.000 iterações). | 5 |
| `gerar_certificado_completo(...)` | Função “orquestradora”: chama as anteriores na ordem e devolve tudo pronto. | 1 a 6 |
| `descrever_certificado(cert)` | Extrai titular, emissor, série, validade, tamanho da chave, algoritmo e impressão digital SHA-256 para exibir na tela. | 14 |
| `eh_autoassinado(cert)` | Retorna `True` se emissor == titular **e** a assinatura do certificado confere com a sua própria chave pública. | 18 |
| `carregar_certificado(bytes)` | Lê um certificado em PEM ou DER. | — |

---

## 2. `seguranca/assinatura.py`: Funcionalidade 2 (assinatura do PDF)

| Função | O que faz | Requisito |
|---|---|---|
| `validar_pdf(bytes)` | Confere se o arquivo começa com `%PDF-`. | 7 |
| `carregar_assinante(pfx, senha)` | Abre o `.pfx` com a senha e obtém a **chave privada** e o **certificado**. Com a senha errada, a chave não é decifrada e é exibido um erro. | 8 |
| `proximo_nome_de_campo(leitor)` | Escolhe um nome livre para o campo de assinatura (`Assinatura1`, `Assinatura2`...), o que permite várias assinaturas no mesmo PDF. | — |
| `assinar_pdf(pdf, pfx, senha, motivo, local, visivel)` | Faz a assinatura de fato (detalhes abaixo). | 9, 10, 11 |

**Passo a passo do `assinar_pdf`:**

1. `IncrementalPdfFileWriter` abre o PDF em modo de **atualização incremental**: os bytes originais não são mexidos e tudo o que é novo vai para o **final** do arquivo (requisito 11, preservar o conteúdo original).
2. É criado um campo de assinatura `/Sig`, com um espaço reservado `/Contents` e um `/ByteRange` que indica quais bytes serão protegidos (o arquivo inteiro, menos o espaço da própria assinatura).
3. Calcula-se o **hash SHA-256** dos bytes do `/ByteRange`.
4. O hash vai para uma estrutura **CMS/PKCS#7** (atributo `messageDigest`). Os atributos são assinados com **RSA usando a chave privada**.
5. O CMS, que contém a assinatura e o certificado, é gravado em `/Contents`. O `SubFilter` é `/ETSI.CAdES.detached` (**PAdES**), o formato que o Adobe Reader reconhece (requisito 10).
6. O carimbo visível opcional é só a aparência; a assinatura real é o passo 4.

---

## 3. `seguranca/validacao.py`: Funcionalidade 3 (validação)

| Função | O que faz | Requisito |
|---|---|---|
| `validar_pdf_assinado(pdf, confiaveis)` | Função principal: lê o PDF, encontra **todas** as assinaturas (`embedded_signatures`) e valida cada uma. | 12, 13 |
| `montar_contexto_validacao(confiaveis)` | Prepara a validação da cadeia de certificados: usa as raízes do sistema e os `.crt` que o usuário marcar como confiáveis. Funciona offline (`allow_fetching=False`). | 18 |
| `validar_assinatura(assinatura, contexto, revisoes)` | Gera o relatório de uma assinatura: dados do certificado, hashes, integridade, validade, confiança, alterações e veredito final. | 14 a 18 |
| `_hash_dentro_da_assinatura(assinatura)` | Lê o `messageDigest` de dentro do CMS, ou seja, o hash calculado **no momento da assinatura**. | 15 |
| `_analisar_alteracoes(status, ...)` | Verifica se existem revisões **posteriores** à assinatura e classifica a mudança: nenhuma, formulário/nova assinatura, anotações ou **alteração não permitida**. | 16 |
| `_classificar_confianca(status, cert)` | Classifica o certificado como **CONFIÁVEL**, **AUTOASSINADO** ou **SEM CADEIA DE CONFIANÇA RECONHECIDA**. | 18 |
| `_texto_cobertura(cobertura)` | Explica, em português, quanto do arquivo a assinatura cobre. | 16 |

### Como a aplicação distingue “assinatura inválida” de “certificado não confiável”

| Situação | Integridade (A) | Assinatura RSA (B) | Confiança (C) | Veredito |
|---|---|---|---|---|
| Tudo certo + certificado confiável | ✅ | ✅ | ✅ | **VÁLIDA, confiável** (verde) |
| Tudo certo + certificado autoassinado | ✅ | ✅ | ⚠️ | **VÁLIDA, mas AUTOASSINADO** (amarelo) |
| Bytes alterados | ❌ | ❌ | qualquer | **ASSINATURA INVÁLIDA** (vermelho) |
| Conteúdo acrescentado depois | ✅ (versão assinada) | ✅ | qualquer | **DOCUMENTO ALTERADO APÓS A ASSINATURA** (vermelho) |

Um certificado não confiável **não** torna a assinatura inválida: a matemática confere, só a identidade do titular é que não está garantida. Já uma assinatura inválida mostra que o documento foi adulterado ou que a assinatura não pertence a ele.

---

## 4. `seguranca/integridade.py`: Funcionalidade 4 (teste de integridade)

| Função | O que faz | Requisito |
|---|---|---|
| `_intervalos_assinados(pdf)` | Lê o `/ByteRange` para saber quais bytes estão protegidos pela assinatura. | — |
| `adulterar_bytes(pdf, original, novo)` | **Ataque 1**: troca um texto (ex.: `R$ 1.000,00` → `R$ 9.000,00`) direto nos bytes assinados. Se o texto não aparecer (PDF comprimido), inverte 1 bit dentro da área assinada. O hash muda e a assinatura fica inválida. | 20, 22 |
| `alterar_incrementalmente(pdf, texto)` | **Ataque 2**: acrescenta uma nova revisão ao PDF que desenha uma faixa vermelha com um texto na página 1, como um editor de PDF faria. A assinatura antiga continua válida para a versão antiga, mas a aplicação detecta a alteração posterior. | 20, 22 |
| `_escapar_texto_pdf(texto)` | Escapa `\`, `(` e `)` para gerar uma string válida no PDF. | — |

---

## 5. `app.py`: camada web (Flask)

| Função | O que faz |
|---|---|
| `inicio()` | Página inicial com o fluxo e a explicação do processo. |
| `certificado()` | GET mostra o formulário; POST chama `gerar_certificado_completo` e mostra os dados e os links de download. |
| `assinar()` | Recebe o PDF, o `.pfx` e a senha, chama `assinar_pdf`, já valida o resultado e disponibiliza o download. |
| `validar()` | Recebe o PDF assinado (e, se houver, `.crt` confiáveis) e mostra o relatório. |
| `integridade()` | Aplica o ataque escolhido, valida o original e o modificado e mostra os dois lado a lado. |
| `guardar_arquivos()` / `baixar()` | Cache temporário em memória com token aleatório. Os arquivos expiram em 15 min e o `.pfx` só pode ser baixado uma vez. |
| `token_csrf()` / `verificar_csrf()` | Proteção contra CSRF: um token por sessão é comparado em todo POST, com `hmac.compare_digest`. |
| `cabecalhos_seguranca()` | Adiciona CSP, X-Frame-Options, nosniff, Referrer-Policy e Cache-Control. |
| `ler_arquivo()` / `nome_seguro()` | Leem uploads em memória e sanitizam nomes de arquivos. |

---

## 6. Outros arquivos

- `templates/_macros.html`: blocos reutilizados que desenham a tabela do certificado e o relatório de cada assinatura, com as três verificações separadas.
- `exemplos/gerar_pdf_exemplo.py`: cria o contrato de exemplo **sem compressão**, para que o valor “R$ 1.000,00” fique visível nos bytes e possa ser adulterado na demonstração.
- `testes/teste_fluxo_completo.py`: testa automaticamente todo o fluxo (certificado 2048 bits autoassinado, assinatura válida, certificado confiável, adulteração de bytes, alteração incremental e preservação do conteúdo original).
