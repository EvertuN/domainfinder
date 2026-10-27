use crate::whois::{is_valid_domain, sanitize_domain};
use std::collections::HashSet;

pub fn decode_bytes(bytes: &[u8]) -> String {
    // Tenta UTF-8 primeiro
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.trim_start_matches('\u{feff}').to_string();
    }
    // Fallback para Windows-1252 / Latin-1
    let (cow, _, _) = encoding_rs::WINDOWS_1252.decode(bytes);
    cow.trim_start_matches('\u{feff}').to_string()
}

pub fn parse_domains_from_text(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for line in text.lines() {
        let cleaned = sanitize_domain(line);
        if !cleaned.is_empty() && is_valid_domain(&cleaned) && seen.insert(cleaned.clone()) {
            result.push(cleaned);
        }
    }

    result
}

pub fn parse_domains_from_file(bytes: &[u8], filename: &str) -> Vec<String> {
    let content = decode_bytes(bytes);
    let is_csv = filename.to_lowercase().ends_with(".csv")
        || content.contains(',')
        || content.contains(';')
        || content.contains('\t');

    if !is_csv {
        return parse_domains_from_text(&content);
    }

    // Detecta delimitador
    let sample = if content.len() > 2048 {
        &content[..2048]
    } else {
        &content
    };

    let mut delimiter = b',';
    for d in [b';', b'\t', b',', b'|'] {
        if sample.contains(d as char) {
            delimiter = d;
            break;
        }
    }

    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(false)
        .flexible(true)
        .from_reader(content.as_bytes());

    let mut seen = HashSet::new();
    let mut result = Vec::new();
    let mut target_col: Option<usize> = None;
    let mut is_first_row = true;

    let header_keywords = [
        "dominio", "domínio", "domain", "url", "site", "website", "link", "nome", "name",
    ];

    for record_res in reader.records() {
        let record = match record_res {
            Ok(r) => r,
            Err(_) => continue,
        };

        if is_first_row {
            is_first_row = false;
            // Verifica se a primeira linha é cabeçalho
            for (idx, field) in record.iter().enumerate() {
                let lower = field.trim().to_lowercase();
                if header_keywords.iter().any(|&k| lower == k) {
                    target_col = Some(idx);
                    break;
                }
            }
            if target_col.is_some() {
                continue; // Pula linha de cabeçalho
            }
        }

        if let Some(col_idx) = target_col {
            if let Some(field) = record.get(col_idx) {
                let cleaned = sanitize_domain(field);
                if !cleaned.is_empty() && is_valid_domain(&cleaned) && seen.insert(cleaned.clone()) {
                    result.push(cleaned);
                }
            }
        } else {
            // Procura a primeira coluna que contenha domínio válido
            let mut found = false;
            for field in record.iter() {
                let cleaned = sanitize_domain(field);
                if !cleaned.is_empty() && is_valid_domain(&cleaned) {
                    if seen.insert(cleaned.clone()) {
                        result.push(cleaned);
                    }
                    found = true;
                    break;
                }
            }
            if !found {
                if let Some(first) = record.get(0) {
                    let cleaned = sanitize_domain(first);
                    if !cleaned.is_empty() && is_valid_domain(&cleaned) && seen.insert(cleaned.clone()) {
                        result.push(cleaned);
                    }
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_normalized_csv() {
        let content = b"google.com\nuol.com.br\ndefinitivamente-livre.com\n";
        let domains = parse_domains_from_file(content, "dominios.csv");
        assert_eq!(domains, vec!["google.com", "uol.com.br", "definitivamente-livre.com"]);
    }
}
