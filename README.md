# DomainFinder - Verificador de Disponibilidade de Domínios WHOIS (Rust Edition 🦀)

Um sistema web de altíssima performance para consulta em massa de disponibilidade de domínios via protocolo **WHOIS** e **RDAP**, desenvolvido com **Rust (Axum + Tokio)** no backend e **HTML5 + Bootstrap 5** no frontend.

---

## ⚡ Por que em Rust?

- **Concorrência Assíncrona com Tokio**: Conexões de socket TCP diretas na porta 43 sem bloqueio de threads do sistema operacional e sem gargalo de GIL.
- **Consultas em Milissegundos**: Capaz de processar dezenas ou centenas de domínios simultaneamente com consumo mínimo de memória RAM (< 20MB) e latência de rede otimizada.
- **Binário Único e Auto-Contido**: A aplicação pode rodar como um executável nativo compilado (`domainfinder.exe`), sem necessidade de interpretadores pesados.

---

## 🚀 Funcionalidades

- **Busca Única Multi-Extensões (NOVO! `/busca-unica`)**:
  - Digite apenas o nome da marca ou ideia (ex: `exemplo`) e o sistema gera e verifica automaticamente todas as extensões possíveis: `.com`, `.com.br`, `.ai`, `.io`, `.uk`, `.net`, `.org`, `.app`, `.dev`, `.co`, `.pt`, `.tech`, `.store` (+ de 50 extensões oficiais).
  - Filtros por categoria: *Mais Populares*, *Brasil (.br)*, *Tecnologia & IA*, *Internacionais/Países* e *Negócios & Vendas*.
  - Possibilidade de adicionar extensões personalizadas dinamicamente.
  - **Redirecionamento Direto para Compra**:
    - Botão "Comprar" em 1 clique que redireciona diretamente com o domínio pré-preenchido para o registrador oficial (Registro.br para extensões `.br` e Namecheap/Hostinger/GoDaddy/Porkbun para internacionais).
    - Menu seletor com todos os registradores para máxima flexibilidade.
  - Filtro instantâneo por disponíveis e exportação em CSV / Cópia para Área de Transferência.

- **Verificador em Lote (/ - Upload de Lista .TXT e .CSV)**:
  - Arquivos `.txt`: um domínio por linha.
  - Arquivos `.csv`: detecção automática de delimitadores (`,`, `;`, `\t`, `|`) e localização inteligente da coluna de domínios ou cabeçalho (`dominio`, `domain`, `url`, etc.).
- **Digitação / Colagem Direta**: Aba dedicada para colar domínios manualmente e botão para preencher dados de demonstração com 1 clique.
- **Higienização Automática de URLs**: Remove automaticamente `https://`, `http://`, `www.`, portas e caminhos (`/caminho`).
- **Informações Ricas do WHOIS**:
  - **Titular / Proprietário**: Razão Social, Organização ou Nome do proprietário.
  - **Documento Oficial**: CNPJ ou CPF (comum em domínios `.com.br` e registros públicos).
  - **Contato & Localização**: E-mails de contato/abuse, País, Estado e Cidade.
  - **Registrador Oficial**: Registrar responsável (Registro.br, MarkMonitor, GoDaddy, 1API, etc.).
  - **Servidores DNS (Nameservers)**: Lista limpa dos servidores DNS autoritativos.
  - **Ciclo de Vida (Datas)**: Data de Criação, Última Atualização e Data de Expiração.
  - **Segurança**: Status EPP e DNSSEC.
  - **Modal de Detalhes Completos**: Ficha completa e resposta bruta original do WHOIS.
- **Interface e Paginação**:
  - Paginação fluida: **10, 25, 50, 100 ou Todos**.
  - Atualização cirúrgica *in-place* que **não pisca a tela** conforme os domínios são encontrados.
  - Ordenação por cabeçalho de coluna e filtro de busca instantânea.
- **Exportação Completa**:
  - Download de CSV estruturado com UTF-8 BOM (compatível com Microsoft Excel).
  - Download apenas de disponíveis ou cópia direta para a Área de Transferência.

---

## 🛠️ Tecnologias Utilizadas

- **Backend (Rust)**:
  - [Axum](https://github.com/tokio-rs/axum) (framework web moderno e ergonômico)
  - [Tokio](https://tokio.rs/) (runtime assíncrono para I/O não-bloqueante)
  - [Tower-HTTP](https://github.com/tower-rs/tower-http) (serviço de arquivos estáticos e CORS)
  - [Reqwest](https://github.com/seanmonstar/reqwest) (cliente HTTP assíncrono para fallback RDAP)
  - [Regex](https://github.com/rust-lang/regex) e [CSV](https://github.com/BurntSushi/rust-csv)
- **Frontend**:
  - HTML5 semântico
  - Bootstrap 5.3 + Bootstrap Icons
  - JavaScript moderno com Fetch assíncrono

---

## ▶️ Como Executar

### Opção 1: Executando o binário Release otimizado (Mais rápido)

No PowerShell:
```powershell
.\target\release\domainfinder.exe
```

### Opção 2: Compilando e executando com Cargo

```powershell
cargo run --release
```

Em seguida, abra o navegador em:
```
http://localhost:5000
```

---

## 📁 Estrutura do Projeto

```
domainfinder/
├── Cargo.toml                  # Manifesto de dependências do Rust
├── src/
│   ├── main.rs                 # Servidor web Axum, rotas REST e API de TLDs
│   ├── whois.rs                # Engine assíncrona TCP socket porta 43 e RDAP
│   └── parser.rs               # Parser inteligente de listas .txt e .csv
├── templates/
│   ├── index.html              # Interface do Verificador em Lote
│   └── busca_unica.html        # Interface da Busca Única Multi-Extensões
├── static/
│   ├── css/style.css           # Estilos personalizados (Cards, Badges, Botões)
│   └── js/
│       ├── app.js              # Lógica do Verificador em Lote
│       └── busca_unica.js      # Engine da Busca Única e Redirecionamento
├── sample_domains.txt          # Arquivo de exemplo .txt
├── sample_domains.csv          # Arquivo de exemplo .csv
└── README.md                   # Documentação
```
