# Security Sentinels — URL & File Checker

Ferramenta em Python que verifica URLs e arquivos contra a base de detecção do
[VirusTotal](https://www.virustotal.com), via API v3. Exibe um alerta gráfico
(Tkinter) quando há ambiente gráfico disponível e, caso contrário, imprime o
resultado no terminal — funcionando tanto em Windows quanto em Linux.

> Implementação em Python desenvolvida no âmbito do projeto acadêmico
> **"Security Sentinels — Conscientização de Engenharia Social / Phishing"**
> (Faculdade Impacta de Tecnologia, 2025). Este repositório contém a minha
> implementação da ferramenta de verificação; o artigo completo é de autoria
> coletiva (ver *Créditos*).

## Funcionalidades

- Verifica **URLs**: codifica em base64 url-safe e consulta o endpoint `/urls`.
- Verifica **arquivos**: faz upload para `/files` e busca o resultado em `/analyses`.
- Extrai os **engines que classificaram o alvo como malicioso**.
- **Alerta visual** (verde = seguro, vermelho = malicioso) via Tkinter.
- **Fallback para terminal** quando não há display (ex.: VM Linux headless).
- **API key fora do código**, lida de variável de ambiente.

## Requisitos

- Python 3.8+
- Conta no VirusTotal (a [API key gratuita](https://www.virustotal.com) basta)
- Dependência: `requests` (`pip install -r requirements.txt`)
- *Opcional (alerta gráfico):* Tkinter — no Linux, `sudo apt install python3-tk`

## Configuração da API key

A chave **não** fica no código. Defina a variável de ambiente `VIRUSTOTAL_API_KEY`:

**Linux / macOS**
```bash
export VIRUSTOTAL_API_KEY="sua_chave_aqui"
```

**Windows (PowerShell)**
```powershell
$env:VIRUSTOTAL_API_KEY="sua_chave_aqui"
```

Há um arquivo [`.env.example`](.env.example) indicando a variável esperada.

## Uso

```bash
pip install -r requirements.txt
python phishing_checker.py
```

A ferramenta pede a URL ou o caminho do arquivo a analisar e retorna o status.

## Como funciona (fluxo)

1. Lê a entrada (URL ou caminho de arquivo).
2. Consulta a API do VirusTotal (upload do arquivo **ou** lookup da URL).
3. Lê `last_analysis_stats` para contar detecções maliciosas.
4. Apresenta **SEGURO** ou **MALICIOSO**, com os engines que detectaram.

## Limitações conhecidas

- **Dependência da API**: sujeita a rate limit e disponibilidade do VirusTotal.
- **Zero-day**: ameaças ainda não catalogadas podem não ser detectadas.
- **Arquivos protegidos/ofuscados**: podem impedir a análise.
- **Foco em URLs/arquivos**: não analisa macros ou conteúdo embutido sem link.

## Trabalhos futuros

- Integração com múltiplas APIs (Google Safe Browsing, AlienVault OTX).
- Geração de relatório (`.txt`/HTML) com histórico das análises.
- Suporte a `.eml`/`.zip` e extração de links de documentos.
- Heurísticas de similaridade de domínio e análise de caminho de URL.

## Segurança

- A API key é lida de variável de ambiente e **nunca** é commitada.
- `.env` está no `.gitignore`; o repositório traz apenas `.env.example`.

## Créditos

Projeto acadêmico **Security Sentinels** (Faculdade Impacta de Tecnologia, 2025),
de autoria coletiva. Implementação Python deste repositório por
**Davi de Oliveira Carlos Gil**.

## Licença

MIT (ver `LICENSE`).
