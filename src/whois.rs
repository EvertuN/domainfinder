use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

static DOMAIN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap()
});

static AVAILABLE_PATTERNS: &[&str] = &[
    "no match",
    "not found",
    "is available",
    "status: available",
    "status: free",
    "no entries found",
    "no data found",
    "domain not found",
    "object does not exist",
    "nothing found",
    "no object found",
    "dominio nao encontrado",
    "domínio não encontrado",
    "% no match for",
];

static REDACTED_PATTERNS: &[&str] = &[
    "redacted",
    "privacy",
    "privada",
    "whoisguard",
    "proxy",
    "withheld",
    "contact privacy",
    "protected",
    "domains by proxy",
    "gdpr masked",
    "data protected",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResult {
    pub domain: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub status_label: String,
    #[serde(default)]
    pub status_class: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub owner_id: String,
    #[serde(default)]
    pub is_redacted: bool,
    #[serde(default)]
    pub registrar: String,
    #[serde(default)]
    pub registrar_url: String,
    #[serde(default)]
    pub creation_date: String,
    #[serde(default)]
    pub expiration_date: String,
    #[serde(default)]
    pub updated_date: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub name_servers: Vec<String>,
    #[serde(default)]
    pub status_epp: Vec<String>,
    #[serde(default)]
    pub dnssec: String,
    #[serde(default)]
    pub whois_server: String,
    #[serde(default)]
    pub responsible_person: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub raw_text: String,
}

pub fn sanitize_domain(raw: &str) -> String {
    let mut d = raw.trim().to_lowercase();
    if let Some(pos) = d.find("://") {
        d = d[pos + 3..].to_string();
    }
    if d.starts_with("www.") {
        d = d[4..].to_string();
    }
    if let Some(pos) = d.find('/') {
        d = d[..pos].to_string();
    }
    if let Some(pos) = d.find('?') {
        d = d[..pos].to_string();
    }
    if let Some(pos) = d.find('#') {
        d = d[..pos].to_string();
    }
    if let Some(pos) = d.find(':') {
        d = d[..pos].to_string();
    }
    d.trim_end_matches('.').to_string()
}

pub fn is_valid_domain(d: &str) -> bool {
    if d.is_empty() || d.len() > 253 {
        return false;
    }
    DOMAIN_REGEX.is_match(d)
}

fn get_whois_server(domain: &str) -> (&'static str, &'static str) {
    if domain.ends_with(".br") {
        ("whois.registro.br", "whois.registro.br:43")
    } else if domain.ends_with(".com") || domain.ends_with(".net") {
        ("whois.verisign-grs.com", "whois.verisign-grs.com:43")
    } else if domain.ends_with(".org") {
        ("whois.pir.org", "whois.pir.org:43")
    } else if domain.ends_with(".io") {
        ("whois.nic.io", "whois.nic.io:43")
    } else if domain.ends_with(".me") {
        ("whois.nic.me", "whois.nic.me:43")
    } else if domain.ends_with(".co") {
        ("whois.nic.co", "whois.nic.co:43")
    } else if domain.ends_with(".app") || domain.ends_with(".dev") || domain.ends_with(".page") {
        ("whois.nic.google", "whois.nic.google:43")
    } else {
        ("whois.iana.org", "whois.iana.org:43")
    }
}

pub async fn query_tcp_whois(domain: &str, server_addr: &str) -> Result<String, String> {
    let connect_future = TcpStream::connect(server_addr);
    let mut stream = match timeout(Duration::from_secs(3), connect_future).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("Falha na conexão TCP com {server_addr}: {e}")),
        Err(_) => return Err(format!("Timeout de conexão com {server_addr}")),
    };

    let query = format!("{domain}\r\n");
    if let Err(e) = stream.write_all(query.as_bytes()).await {
        return Err(format!("Erro ao enviar query: {e}"));
    }

    let mut buffer = Vec::with_capacity(8192);
    let read_future = stream.read_to_end(&mut buffer);
    match timeout(Duration::from_secs(4), read_future).await {
        Ok(Ok(_)) => {
            match String::from_utf8(buffer) {
                Ok(s) => Ok(s),
                Err(e) => {
                    let (cow, _, _) = encoding_rs::WINDOWS_1252.decode(e.as_bytes());
                    Ok(cow.into_owned())
                }
            }
        }
        Ok(Err(e)) => Err(format!("Erro na leitura: {e}")),
        Err(_) => Err("Timeout ao ler resposta WHOIS".to_string()),
    }
}

pub async fn query_rdap(domain: &str) -> Option<(bool, String)> {
    let url = if domain.ends_with(".br") {
        format!("https://rdap.registro.br/domain/{domain}")
    } else {
        format!("https://rdap.org/domain/{domain}")
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
        .ok()?;

    if let Ok(res) = client.get(&url).send().await {
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Some((true, "Domínio disponível (confirmado via RDAP).".to_string()));
        } else if res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            return Some((false, text));
        }
    }
    None
}

fn format_date(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() || s == "-" {
        return "-".to_string();
    }
    let first_token = s.split_whitespace().next().unwrap_or(s);
    if first_token.len() == 8 && first_token.chars().all(|c| c.is_ascii_digit()) {
        let year = &first_token[0..4];
        let month = &first_token[4..6];
        let day = &first_token[6..8];
        return format!("{day}/{month}/{year}");
    }
    if s.len() >= 10 && s.chars().nth(4) == Some('-') && s.chars().nth(7) == Some('-') {
        let year = &s[0..4];
        let month = &s[5..7];
        let day = &s[8..10];
        return format!("{day}/{month}/{year}");
    }
    s.to_string()
}

pub async fn check_domain(raw_domain: &str) -> WhoisResult {
    let domain = sanitize_domain(raw_domain);

    let empty = WhoisResult {
        domain: raw_domain.to_string(),
        status: "invalid".to_string(),
        status_label: "Formato Inválido".to_string(),
        status_class: "warning".to_string(),
        owner: "-".to_string(),
        owner_id: "".to_string(),
        is_redacted: false,
        registrar: "-".to_string(),
        registrar_url: "".to_string(),
        creation_date: "-".to_string(),
        expiration_date: "-".to_string(),
        updated_date: "-".to_string(),
        country: "-".to_string(),
        state: "-".to_string(),
        city: "-".to_string(),
        emails: vec![],
        name_servers: vec![],
        status_epp: vec![],
        dnssec: "-".to_string(),
        whois_server: "-".to_string(),
        responsible_person: "-".to_string(),
        details: "O formato informado não é um nome de domínio válido.".to_string(),
        raw_text: "".to_string(),
    };

    if !is_valid_domain(&domain) {
        return empty;
    }

    let (server_name, server_addr) = get_whois_server(&domain);

    // 1. Tenta consulta TCP WHOIS direto
    let mut whois_text = match query_tcp_whois(&domain, server_addr).await {
        Ok(txt) => txt,
        Err(_) => "".to_string(),
    };

    // Se o registrar informar um segundo servidor WHOIS, tenta consultá-lo
    if whois_text.contains("WHOIS Server:") {
        for line in whois_text.lines() {
            let lower = line.to_lowercase();
            if lower.contains("whois server:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let second_server = parts[1].trim();
                    if !second_server.is_empty() && second_server != server_name {
                        let second_addr = format!("{second_server}:43");
                        if let Ok(second_txt) = query_tcp_whois(&domain, &second_addr).await {
                            if !second_txt.is_empty() && second_txt.len() > 100 {
                                whois_text = second_txt;
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    // Se o WHOIS vier vazio ou falhar, tenta RDAP
    if whois_text.trim().is_empty() {
        if let Some((is_available, _rdap_info)) = query_rdap(&domain).await {
            if is_available {
                return WhoisResult {
                    domain: domain.clone(),
                    status: "available".to_string(),
                    status_label: "Disponível".to_string(),
                    status_class: "success".to_string(),
                    details: "Domínio disponível (confirmado via RDAP).".to_string(),
                    ..empty
                };
            } else {
                return WhoisResult {
                    domain: domain.clone(),
                    status: "registered".to_string(),
                    status_label: "Registrado".to_string(),
                    status_class: "danger".to_string(),
                    registrar: "Registro Oficial".to_string(),
                    details: "Domínio registrado (confirmado via RDAP).".to_string(),
                    ..empty
                };
            }
        }
    }

    let lower_text = whois_text.to_lowercase();

    // 2. Checa se o texto indica disponibilidade
    for kw in AVAILABLE_PATTERNS {
        if lower_text.contains(kw) {
            return WhoisResult {
                domain: domain.clone(),
                status: "available".to_string(),
                status_label: "Disponível".to_string(),
                status_class: "success".to_string(),
                details: "Domínio livre para registro imediato no registro oficial.".to_string(),
                raw_text: whois_text.chars().take(2500).collect(),
                ..empty
            };
        }
    }

    // 3. Extrai campos do WHOIS
    let mut owner = "-".to_string();
    let mut owner_id = "".to_string();
    let mut registrar = if domain.ends_with(".br") {
        "Registro.br".to_string()
    } else {
        "Registrador Oficial".to_string()
    };
    let mut registrar_url = "".to_string();
    let mut creation_date = "-".to_string();
    let mut expiration_date = "-".to_string();
    let mut updated_date = "-".to_string();
    let mut country = if domain.ends_with(".br") { "BR".to_string() } else { "-".to_string() };
    let mut state = "-".to_string();
    let mut city = "-".to_string();
    let mut emails = Vec::new();
    let mut name_servers = Vec::new();
    let mut status_epp = Vec::new();
    let mut dnssec = "-".to_string();
    let mut person = "-".to_string();

    let email_regex = Regex::new(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+").unwrap();

    for line in whois_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('%') || trimmed.starts_with('#') {
            continue;
        }

        let lower_line = trimmed.to_lowercase();

        // Titular (.br e internacional)
        if (lower_line.starts_with("owner:")
            || lower_line.starts_with("registrant name:")
            || lower_line.starts_with("registrant organization:")
            || lower_line.starts_with("registrant:")
            || lower_line.starts_with("organization:")
            || lower_line.starts_with("org:")
            || lower_line.starts_with("org-name:"))
            && owner == "-"
        {
            if let Some(pos) = trimmed.find(':') {
                let val = trimmed[pos + 1..].trim();
                if !val.is_empty() {
                    owner = val.to_string();
                }
            }
        }

        // Documento CNPJ / CPF / ID
        if (lower_line.starts_with("ownerid:") || lower_line.starts_with("registrant id:") || lower_line.starts_with("documento:"))
            && owner_id.is_empty()
        {
            if let Some(pos) = trimmed.find(':') {
                owner_id = trimmed[pos + 1..].trim().to_string();
            }
        }

        // Registrador
        if (lower_line.starts_with("registrar:") || lower_line.starts_with("registrar name:"))
            && (registrar == "Registrador Oficial" || registrar == "-")
        {
            if let Some(pos) = trimmed.find(':') {
                let val = trimmed[pos + 1..].trim();
                if !val.is_empty() {
                    registrar = val.to_string();
                }
            }
        }

        if lower_line.starts_with("registrar url:") && registrar_url.is_empty() {
            if let Some(pos) = trimmed.find(':') {
                registrar_url = trimmed[pos + 1..].trim().to_string();
            }
        }

        // Datas
        if (lower_line.starts_with("created:") || lower_line.starts_with("creation date:")) && creation_date == "-" {
            if let Some(pos) = trimmed.find(':') {
                creation_date = format_date(trimmed[pos + 1..].trim());
            }
        }
        if (lower_line.starts_with("expires:") || lower_line.starts_with("registry expiry date:") || lower_line.starts_with("expiration date:")) && expiration_date == "-" {
            if let Some(pos) = trimmed.find(':') {
                expiration_date = format_date(trimmed[pos + 1..].trim());
            }
        }
        if (lower_line.starts_with("changed:") || lower_line.starts_with("updated date:")) && updated_date == "-" {
            if let Some(pos) = trimmed.find(':') {
                updated_date = format_date(trimmed[pos + 1..].trim());
            }
        }

        // Localização
        if lower_line.starts_with("registrant country:") || (lower_line.starts_with("country:") && country == "-") {
            if let Some(pos) = trimmed.find(':') {
                country = trimmed[pos + 1..].trim().to_string();
            }
        }
        if lower_line.starts_with("registrant state/province:") && state == "-" {
            if let Some(pos) = trimmed.find(':') {
                state = trimmed[pos + 1..].trim().to_string();
            }
        }
        if lower_line.starts_with("registrant city:") && city == "-" {
            if let Some(pos) = trimmed.find(':') {
                city = trimmed[pos + 1..].trim().to_string();
            }
        }

        // Servidores DNS
        if lower_line.starts_with("nserver:") || lower_line.starts_with("name server:") {
            if let Some(pos) = trimmed.find(':') {
                let ns = trimmed[pos + 1..].trim();
                let clean_ns = ns.split_whitespace().next().unwrap_or("").trim_end_matches('.').to_lowercase();
                if !clean_ns.is_empty() && !name_servers.contains(&clean_ns) && name_servers.len() < 6 {
                    name_servers.push(clean_ns);
                }
            }
        }

        // Status EPP
        if lower_line.starts_with("status:") || lower_line.starts_with("domain status:") {
            if let Some(pos) = trimmed.find(':') {
                let st = trimmed[pos + 1..].trim();
                let clean_st = st.split_whitespace().next().unwrap_or("").to_string();
                if !clean_st.is_empty() && !status_epp.contains(&clean_st) && status_epp.len() < 5 {
                    status_epp.push(clean_st);
                }
            }
        }

        // DNSSEC
        if lower_line.starts_with("dnssec:") && dnssec == "-" {
            if let Some(pos) = trimmed.find(':') {
                dnssec = trimmed[pos + 1..].trim().to_string();
            }
        }

        // Responsável / Person
        if (lower_line.starts_with("person:") || lower_line.starts_with("tech-c:") || lower_line.starts_with("admin name:")) && person == "-" {
            if let Some(pos) = trimmed.find(':') {
                person = trimmed[pos + 1..].trim().to_string();
            }
        }

        // Emails
        for mat in email_regex.find_iter(trimmed) {
            let em = mat.as_str().to_lowercase();
            if !emails.contains(&em) && emails.len() < 4 {
                emails.push(em);
            }
        }
    }

    // Se owner ainda for "-" em domínio registrado internacional, busca no RDAP
    if owner == "-" && !domain.ends_with(".br") {
        if let Some((false, rdap_body)) = query_rdap(&domain).await {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&rdap_body) {
                if let Some(entities) = val.get("entities").and_then(|e| e.as_array()) {
                    for ent in entities {
                        let roles = ent.get("roles").and_then(|r| r.as_array());
                        let is_reg = roles.map(|arr| arr.iter().any(|role| role.as_str() == Some("registrant"))).unwrap_or(false);
                        if is_reg {
                            if let Some(vcard) = ent.get("vcardArray").and_then(|v| v.as_array()) {
                                if vcard.len() > 1 {
                                    if let Some(props) = vcard[1].as_array() {
                                        for prop in props {
                                            if let Some(arr) = prop.as_array() {
                                                if arr.len() >= 4 {
                                                    let prop_name = arr[0].as_str().unwrap_or("");
                                                    if prop_name == "fn" || prop_name == "org" {
                                                        if let Some(s) = arr[3].as_str() {
                                                            let s_trimmed = s.trim();
                                                            if !s_trimmed.is_empty() && s_trimmed != "-" {
                                                                owner = s_trimmed.to_string();
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Verifica se o titular está oculto por privacidade
    let mut is_redacted = false;
    let lower_owner = owner.to_lowercase();
    for kw in REDACTED_PATTERNS {
        if lower_owner.contains(kw) {
            is_redacted = true;
            owner = "Oculto por Privacidade (GDPR / WhoisPrivacy)".to_string();
            break;
        }
    }

    WhoisResult {
        domain: domain.clone(),
        status: "registered".to_string(),
        status_label: "Registrado".to_string(),
        status_class: "danger".to_string(),
        owner,
        owner_id,
        is_redacted,
        registrar,
        registrar_url,
        creation_date,
        expiration_date,
        updated_date,
        country,
        state,
        city,
        emails,
        name_servers,
        status_epp,
        dnssec,
        whois_server: server_name.to_string(),
        responsible_person: person,
        details: "Domínio atualmente ativo e registrado.".to_string(),
        raw_text: whois_text.chars().take(2500).collect(),
    }
}
