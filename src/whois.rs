use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{timeout, Instant};

static DOMAIN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap()
});

static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(5))
        .pool_max_idle_per_host(10)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
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

static RATE_LIMIT_PATTERNS: &[&str] = &[
    "permissão negada",
    "permissao negada",
    "abuse@registro.br",
    "query rate limit exceeded",
    "quota exceeded",
    "too many requests",
    "access denied",
];

// Rate Limiter para chamadas TCP ao Registro.br (porta 43)
static BR_RATE_LIMITER: LazyLock<Mutex<Instant>> = LazyLock::new(|| {
    Mutex::new(Instant::now().checked_sub(Duration::from_secs(5)).unwrap_or_else(Instant::now))
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResult {
    pub domain: String,
    #[serde(default)]
    pub status: String,            // "available", "registered", "rate_limited", "error", "invalid"
    #[serde(default)]
    pub status_label: String,      // "Disponível", "Registrado", "Limite Atingido", etc.
    #[serde(default)]
    pub status_class: String,      // "success", "danger", "warning", "secondary"
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

pub async fn enforce_br_rate_limit() {
    let mut last_query = BR_RATE_LIMITER.lock().await;
    let min_interval = Duration::from_millis(800);
    let elapsed = last_query.elapsed();
    if elapsed < min_interval {
        tokio::time::sleep(min_interval - elapsed).await;
    }
    *last_query = Instant::now();
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

pub fn format_date(raw: &str) -> String {
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

/// Consulta oficial de disponibilidade do Registro.br (motor oficial de consulta de domínios)
/// Retorna informações exatas de disponibilidade, expiração, servidores DNS e regras de sintaxe similar (IDN)
pub async fn check_registro_br_avail(domain: &str) -> Option<WhoisResult> {
    let url = format!("https://registro.br/v2/ajax/avail/raw/{domain}");
    let res = HTTP_CLIENT.get(&url).send().await.ok()?;
    if res.status() != reqwest::StatusCode::OK {
        return None;
    }
    let json: serde_json::Value = res.json().await.ok()?;
    let status_code = json.get("status").and_then(|s| s.as_i64())?;

    let mut result = WhoisResult {
        domain: domain.to_string(),
        status: "registered".to_string(),
        status_label: "Registrado".to_string(),
        status_class: "danger".to_string(),
        owner: "-".to_string(),
        owner_id: "".to_string(),
        is_redacted: false,
        registrar: "Registro.br".to_string(),
        registrar_url: "https://registro.br".to_string(),
        creation_date: "-".to_string(),
        expiration_date: "-".to_string(),
        updated_date: "-".to_string(),
        country: "BR".to_string(),
        state: "-".to_string(),
        city: "-".to_string(),
        emails: vec![],
        name_servers: vec![],
        status_epp: vec![],
        dnssec: "-".to_string(),
        whois_server: "Registro.br Engine".to_string(),
        responsible_person: "-".to_string(),
        details: "".to_string(),
        raw_text: serde_json::to_string_pretty(&json).unwrap_or_default(),
    };

    if status_code == 0 {
        // Status 0: Domínio Disponível para Registro Imediato
        result.status = "available".to_string();
        result.status_label = "Disponível".to_string();
        result.status_class = "success".to_string();
        result.details = "Domínio livre para registro imediato no Registro.br.".to_string();
        return Some(result);
    } else if status_code == 2 {
        // Status 2: Domínio Registrado e Publicado
        result.status = "registered".to_string();
        result.status_label = "Registrado".to_string();
        result.status_class = "danger".to_string();
        result.details = "Domínio ativo e publicado no Registro.br.".to_string();

        if let Some(exp) = json.get("expires-at").and_then(|e| e.as_str()) {
            result.expiration_date = format_date(exp);
        }
        if let Some(hosts) = json.get("hosts").and_then(|h| h.as_array()) {
            for h in hosts {
                if let Some(ns) = h.as_str() {
                    result.name_servers.push(ns.trim_end_matches('.').to_lowercase());
                }
            }
        }
        if let Some(pub_status) = json.get("publication-status").and_then(|s| s.as_str()) {
            result.status_epp.push(pub_status.to_string());
        }

        // Tenta enriquecer com dados de titular via RDAP oficial caso não esteja com rate limit
        let rdap_url = format!("https://rdap.registro.br/domain/{domain}");
        if let Ok(rdap_res) = HTTP_CLIENT.get(&rdap_url).send().await {
            if rdap_res.status() == reqwest::StatusCode::OK {
                if let Ok(rdap_json) = rdap_res.json::<serde_json::Value>().await {
                    let mut rdap_result = parse_rdap_json(domain, &rdap_json);
                    if rdap_result.expiration_date == "-" && result.expiration_date != "-" {
                        rdap_result.expiration_date = result.expiration_date;
                    }
                    if rdap_result.name_servers.is_empty() && !result.name_servers.is_empty() {
                        rdap_result.name_servers = result.name_servers;
                    }
                    return Some(rdap_result);
                }
            }
        }

        return Some(result);
    } else if status_code == 3 {
        // Status 3: Não disponível por regras de sintaxe similar (IDN) ou formato
        let reasons_str = json.get("reasons")
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" "))
            .unwrap_or_default();

        let lower_reasons = reasons_str.to_lowercase();
        if lower_reasons.contains("similar") || lower_reasons.contains("registrado") {
            result.status = "registered".to_string();
            result.status_label = "Registrado (IDN)".to_string();
            result.status_class = "danger".to_string();
            result.owner = "Vinculado a Domínio Acentuado (IDN)".to_string();
            result.details = format!("Domínio indisponível: {reasons_str}");
            return Some(result);
        } else {
            result.status = "invalid".to_string();
            result.status_label = "Inválido".to_string();
            result.status_class = "warning".to_string();
            result.details = if reasons_str.is_empty() { "Formato inválido para Registro.br".to_string() } else { reasons_str };
            return Some(result);
        }
    } else if status_code == 1 {
        // Status 1: Processo de Liberação
        result.status = "registered".to_string();
        result.status_label = "Em Liberação".to_string();
        result.status_class = "warning".to_string();
        result.details = "Domínio em processo de liberação no Registro.br.".to_string();
        return Some(result);
    } else if status_code == 4 {
        // Status 4: Reservado
        result.status = "registered".to_string();
        result.status_label = "Reservado".to_string();
        result.status_class = "warning".to_string();
        result.details = "Domínio reservado pelo Registro.br.".to_string();
        return Some(result);
    }

    None
}

/// Parser de resposta JSON do protocolo oficial RDAP (RFC 7480/7482)
pub fn parse_rdap_json(domain: &str, val: &serde_json::Value) -> WhoisResult {
    let mut owner = "-".to_string();
    let mut owner_id = "".to_string();
    let mut person = "-".to_string();
    let mut creation_date = "-".to_string();
    let mut expiration_date = "-".to_string();
    let mut updated_date = "-".to_string();
    let mut country = if domain.ends_with(".br") { "BR".to_string() } else { "-".to_string() };
    let mut emails = Vec::new();
    let mut name_servers = Vec::new();
    let mut status_epp = Vec::new();
    let registrar = if domain.ends_with(".br") { "Registro.br".to_string() } else { "Registro Oficial".to_string() };

    if let Some(entities) = val.get("entities").and_then(|e| e.as_array()) {
        for ent in entities {
            let roles = ent.get("roles").and_then(|r| r.as_array());
            let is_registrant = roles.map(|arr| arr.iter().any(|role| role.as_str() == Some("registrant"))).unwrap_or(false);
            let is_admin_or_tech = roles.map(|arr| arr.iter().any(|role| role.as_str() == Some("administrative") || role.as_str() == Some("technical"))).unwrap_or(false);

            if is_registrant {
                if let Some(rep) = ent.get("legalRepresentative").and_then(|s| s.as_str()) {
                    let trimmed = rep.trim();
                    if !trimmed.is_empty() {
                        person = trimmed.to_string();
                    }
                }

                if let Some(public_ids) = ent.get("publicIds").and_then(|p| p.as_array()) {
                    for pid in public_ids {
                        if let Some(id) = pid.get("identifier").and_then(|s| s.as_str()) {
                            owner_id = id.trim().to_string();
                            break;
                        }
                    }
                }

                if let Some(vcard) = ent.get("vcardArray").and_then(|v| v.as_array()) {
                    if vcard.len() > 1 {
                        if let Some(props) = vcard[1].as_array() {
                            for prop in props {
                                if let Some(arr) = prop.as_array() {
                                    if arr.len() >= 4 {
                                        let prop_name = arr[0].as_str().unwrap_or("");
                                        if (prop_name == "fn" || prop_name == "org") && owner == "-" {
                                            if let Some(s) = arr[3].as_str() {
                                                let trimmed = s.trim();
                                                if !trimmed.is_empty() && trimmed != "-" {
                                                    owner = trimmed.to_string();
                                                }
                                            }
                                        }
                                        if prop_name == "adr" && country == "-" {
                                            if let Some(adr_arr) = arr[3].as_array() {
                                                if let Some(c) = adr_arr.last().and_then(|v| v.as_str()) {
                                                    if !c.trim().is_empty() {
                                                        country = c.trim().to_string();
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

            if is_admin_or_tech {
                if let Some(vcard) = ent.get("vcardArray").and_then(|v| v.as_array()) {
                    if vcard.len() > 1 {
                        if let Some(props) = vcard[1].as_array() {
                            for prop in props {
                                if let Some(arr) = prop.as_array() {
                                    if arr.len() >= 4 {
                                        let prop_name = arr[0].as_str().unwrap_or("");
                                        if prop_name == "email" {
                                            if let Some(em) = arr[3].as_str() {
                                                let em_clean = em.trim().to_lowercase();
                                                if !em_clean.is_empty() && !emails.contains(&em_clean) && emails.len() < 3 {
                                                    emails.push(em_clean);
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

    if let Some(events) = val.get("events").and_then(|e| e.as_array()) {
        for ev in events {
            let action = ev.get("eventAction").and_then(|a| a.as_str()).unwrap_or("");
            let date = ev.get("eventDate").and_then(|d| d.as_str()).unwrap_or("");
            if action == "registration" && creation_date == "-" && !date.is_empty() {
                creation_date = format_date(date);
            } else if action == "expiration" && expiration_date == "-" && !date.is_empty() {
                expiration_date = format_date(date);
            } else if (action == "last changed" || action == "last update") && updated_date == "-" && !date.is_empty() {
                updated_date = format_date(date);
            }
        }
    }

    if let Some(ns_list) = val.get("nameservers").and_then(|n| n.as_array()) {
        for ns in ns_list {
            if let Some(ldh) = ns.get("ldhName").and_then(|s| s.as_str()) {
                let clean = ldh.trim_end_matches('.').to_lowercase();
                if !clean.is_empty() && !name_servers.contains(&clean) && name_servers.len() < 6 {
                    name_servers.push(clean);
                }
            }
        }
    }

    if let Some(st_list) = val.get("status").and_then(|s| s.as_array()) {
        for st in st_list {
            if let Some(s) = st.as_str() {
                status_epp.push(s.to_string());
            }
        }
    }

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
        domain: domain.to_string(),
        status: "registered".to_string(),
        status_label: "Registrado".to_string(),
        status_class: "danger".to_string(),
        owner,
        owner_id,
        is_redacted,
        registrar,
        registrar_url: "".to_string(),
        creation_date,
        expiration_date,
        updated_date,
        country,
        state: "-".to_string(),
        city: "-".to_string(),
        emails,
        name_servers,
        status_epp,
        dnssec: "-".to_string(),
        whois_server: "RDAP Oficial Registro.br".to_string(),
        responsible_person: person,
        details: "Domínio ativo confirmado via consulta oficial RDAP.".to_string(),
        raw_text: serde_json::to_string_pretty(val).unwrap_or_default(),
    }
}

pub fn parse_whois_text(domain: &str, whois_text: &str, mut base: WhoisResult) -> WhoisResult {
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

        if (lower_line.starts_with("ownerid:") || lower_line.starts_with("registrant id:") || lower_line.starts_with("documento:"))
            && owner_id.is_empty()
        {
            if let Some(pos) = trimmed.find(':') {
                owner_id = trimmed[pos + 1..].trim().to_string();
            }
        }

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

        if lower_line.starts_with("nserver:") || lower_line.starts_with("name server:") {
            if let Some(pos) = trimmed.find(':') {
                let ns = trimmed[pos + 1..].trim();
                let clean_ns = ns.split_whitespace().next().unwrap_or("").trim_end_matches('.').to_lowercase();
                if !clean_ns.is_empty() && !name_servers.contains(&clean_ns) && name_servers.len() < 6 {
                    name_servers.push(clean_ns);
                }
            }
        }

        if lower_line.starts_with("status:") || lower_line.starts_with("domain status:") {
            if let Some(pos) = trimmed.find(':') {
                let st = trimmed[pos + 1..].trim();
                let clean_st = st.split_whitespace().next().unwrap_or("").to_string();
                if !clean_st.is_empty() && !status_epp.contains(&clean_st) && status_epp.len() < 5 {
                    status_epp.push(clean_st);
                }
            }
        }

        if lower_line.starts_with("dnssec:") && dnssec == "-" {
            if let Some(pos) = trimmed.find(':') {
                dnssec = trimmed[pos + 1..].trim().to_string();
            }
        }

        if (lower_line.starts_with("person:") || lower_line.starts_with("tech-c:") || lower_line.starts_with("admin name:")) && person == "-" {
            if let Some(pos) = trimmed.find(':') {
                person = trimmed[pos + 1..].trim().to_string();
            }
        }

        for mat in email_regex.find_iter(trimmed) {
            let em = mat.as_str().to_lowercase();
            if !emails.contains(&em) && emails.len() < 4 {
                emails.push(em);
            }
        }
    }

    let mut is_redacted = false;
    let lower_owner = owner.to_lowercase();
    for kw in REDACTED_PATTERNS {
        if lower_owner.contains(kw) {
            is_redacted = true;
            owner = "Oculto por Privacidade (GDPR / WhoisPrivacy)".to_string();
            break;
        }
    }

    base.status = "registered".to_string();
    base.status_label = "Registrado".to_string();
    base.status_class = "danger".to_string();
    base.owner = owner;
    base.owner_id = owner_id;
    base.is_redacted = is_redacted;
    base.registrar = registrar;
    base.registrar_url = registrar_url;
    base.creation_date = creation_date;
    base.expiration_date = expiration_date;
    base.updated_date = updated_date;
    base.country = country;
    base.state = state;
    base.city = city;
    base.emails = emails;
    base.name_servers = name_servers;
    base.status_epp = status_epp;
    base.dnssec = dnssec;
    base.responsible_person = person;
    base.details = "Domínio atualmente ativo e registrado.".to_string();
    base.raw_text = whois_text.chars().take(2500).collect();
    base
}

/// Função principal que verifica a disponibilidade e detalhes do domínio
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

    // =========================================================================
    // ESTRATÉGIA PARA DOMÍNIOS BRASILEIROS (.BR)
    // 1. Motor oficial de disponibilidade do Registro.br (ajax avail engine)
    //    Nunca bloqueia com 403, detecta 100% de disponibilidade, expiração,
    //    servidores DNS e regras IDN (acentuação similar).
    // 2. Se registrado, enriquece com dados completos de titular via RDAP oficial.
    // =========================================================================
    if domain.ends_with(".br") {
        if let Some(res) = check_registro_br_avail(&domain).await {
            return res;
        }

        // Fallback: RDAP direto caso o endpoint ajax falhe
        let rdap_url = format!("https://rdap.registro.br/domain/{domain}");
        if let Ok(res) = HTTP_CLIENT.get(&rdap_url).send().await {
            let status = res.status();
            if status == reqwest::StatusCode::OK {
                if let Ok(json_val) = res.json::<serde_json::Value>().await {
                    return parse_rdap_json(&domain, &json_val);
                }
            } else if status == reqwest::StatusCode::NOT_FOUND {
                return WhoisResult {
                    domain: domain.clone(),
                    status: "available".to_string(),
                    status_label: "Disponível".to_string(),
                    status_class: "success".to_string(),
                    registrar: "Registro.br".to_string(),
                    country: "BR".to_string(),
                    details: "Domínio livre para registro imediato no Registro.br.".to_string(),
                    ..empty
                };
            }
        }

        // Fallback 2: WHOIS TCP porta 43
        enforce_br_rate_limit().await;
        let (_, server_addr) = get_whois_server(&domain);
        if let Ok(txt) = query_tcp_whois(&domain, server_addr).await {
            let lower = txt.to_lowercase();
            let is_rate_limited = RATE_LIMIT_PATTERNS.iter().any(|kw| lower.contains(kw));
            if !is_rate_limited && !txt.trim().is_empty() {
                let is_avail = AVAILABLE_PATTERNS.iter().any(|kw| lower.contains(kw));
                if is_avail {
                    return WhoisResult {
                        domain: domain.clone(),
                        status: "available".to_string(),
                        status_label: "Disponível".to_string(),
                        status_class: "success".to_string(),
                        registrar: "Registro.br".to_string(),
                        country: "BR".to_string(),
                        details: "Domínio livre para registro imediato no Registro.br.".to_string(),
                        raw_text: txt.chars().take(2500).collect(),
                        ..empty
                    };
                } else if lower.contains("domain:") || lower.contains("owner:") {
                    return parse_whois_text(&domain, &txt, empty);
                }
            }
        }

        // Se todos falharem:
        return WhoisResult {
            domain: domain.clone(),
            status: "rate_limited".to_string(),
            status_label: "Limite Atingido".to_string(),
            status_class: "warning".to_string(),
            details: "Servidor ocupado ou conexão temporariamente instável. Tente novamente em instantes.".to_string(),
            ..empty
        };
    }

    // =========================================================================
    // ESTRATÉGIA PARA DOMÍNIOS INTERNACIONAIS (.COM, .NET, .ORG, etc.)
    // =========================================================================
    let (server_name, server_addr) = get_whois_server(&domain);
    let mut whois_text = match query_tcp_whois(&domain, server_addr).await {
        Ok(txt) => txt,
        Err(_) => "".to_string(),
    };

    let lower_text = whois_text.to_lowercase();
    let is_rate_limited = RATE_LIMIT_PATTERNS.iter().any(|kw| lower_text.contains(kw));

    if !is_rate_limited && !whois_text.trim().is_empty() {
        for kw in AVAILABLE_PATTERNS {
            if lower_text.contains(kw) {
                return WhoisResult {
                    domain: domain.clone(),
                    status: "available".to_string(),
                    status_label: "Disponível".to_string(),
                    status_class: "success".to_string(),
                    details: "Domínio livre para registro imediato.".to_string(),
                    raw_text: whois_text.chars().take(2500).collect(),
                    ..empty
                };
            }
        }

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

        return parse_whois_text(&domain, &whois_text, empty);
    }

    // Fallback Internacional: RDAP via rdap.org
    let rdap_url = format!("https://rdap.org/domain/{domain}");
    if let Ok(res) = HTTP_CLIENT.get(&rdap_url).send().await {
        let status = res.status();
        if status == reqwest::StatusCode::OK {
            if let Ok(json_val) = res.json::<serde_json::Value>().await {
                return parse_rdap_json(&domain, &json_val);
            }
        } else if status == reqwest::StatusCode::NOT_FOUND {
            return WhoisResult {
                domain: domain.clone(),
                status: "available".to_string(),
                status_label: "Disponível".to_string(),
                status_class: "success".to_string(),
                details: "Domínio livre (confirmado via RDAP).".to_string(),
                ..empty
            };
        }
    }

    WhoisResult {
        domain: domain.clone(),
        status: "rate_limited".to_string(),
        status_label: "Limite Atingido".to_string(),
        status_class: "warning".to_string(),
        details: "Servidor ocupado. Tente novamente em alguns instantes.".to_string(),
        ..empty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bow_registration() {
        let res = check_domain("bow.com.br").await;
        assert_eq!(res.status, "registered");
        assert_eq!(res.expiration_date, "27/04/2027");
        assert!(!res.name_servers.is_empty());
    }

    #[tokio::test]
    async fn test_abg_registration_idn() {
        let res = check_domain("abg.com.br").await;
        assert_eq!(res.status, "registered");
        assert_eq!(res.status_label, "Registrado (IDN)");
    }

    #[tokio::test]
    async fn test_available_domain() {
        let res = check_domain("teste-livre-1293819.com.br").await;
        assert_eq!(res.status, "available");
        assert_eq!(res.status_label, "Disponível");
    }
}
