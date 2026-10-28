mod parser;
mod whois;

use axum::{
    extract::{Multipart, Path},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tower_http::services::ServeDir;

#[derive(Debug, Serialize)]
struct ParseResponse {
    success: bool,
    count: usize,
    total_found: usize,
    is_truncated: bool,
    domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CheckSinglePayload {
    domain: String,
}

#[derive(Debug, Deserialize)]
struct CheckBatchPayload {
    domains: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CheckBatchResponse {
    success: bool,
    count: usize,
    results: Vec<whois::WhoisResult>,
}

#[derive(Debug, Deserialize)]
struct ExportCsvPayload {
    results: Vec<whois::WhoisResult>,
    filter: Option<String>,
}

async fn index_handler() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate".parse().unwrap());
    headers.insert(header::PRAGMA, "no-cache".parse().unwrap());
    headers.insert(header::EXPIRES, "0".parse().unwrap());
    (headers, Html(include_str!("../templates/index.html")))
}

async fn api_parse_handler(mut multipart: Multipart) -> impl IntoResponse {
    let mut domains = Vec::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        let file_name = field.file_name().unwrap_or("").to_string();

        if name == "file" || !file_name.is_empty() {
            if let Ok(bytes) = field.bytes().await {
                let parsed = parser::parse_domains_from_file(&bytes, &file_name);
                domains.extend(parsed);
            }
        } else if name == "text" {
            if let Ok(text) = field.text().await {
                let parsed = parser::parse_domains_from_text(&text);
                domains.extend(parsed);
            }
        }
    }

    // Deduplica mantendo a ordem
    let mut seen = std::collections::HashSet::new();
    let mut unique_domains: Vec<String> = domains
        .into_iter()
        .filter(|d| seen.insert(d.clone()))
        .collect();

    // Limite estrito de 500 domínios
    let max_limit = 500;
    let total_found = unique_domains.len();
    let is_truncated = total_found > max_limit;
    if is_truncated {
        unique_domains.truncate(max_limit);
    }

    Json(ParseResponse {
        success: true,
        count: unique_domains.len(),
        total_found,
        is_truncated,
        domains: unique_domains,
    })
}

async fn api_check_single_handler(Json(payload): Json<CheckSinglePayload>) -> impl IntoResponse {
    let result = whois::check_domain(&payload.domain).await;
    Json(result)
}

async fn api_check_batch_handler(Json(payload): Json<CheckBatchPayload>) -> impl IntoResponse {
    let domains = payload.domains;
    let max_domains = 500;
    let domains_slice = if domains.len() > max_domains {
        &domains[..max_domains]
    } else {
        &domains[..]
    };

    // Semaphore para controlar concorrência (até 25 conexões simultâneas)
    let sem = Arc::new(Semaphore::new(25));
    let mut handles = Vec::with_capacity(domains_slice.len());

    for domain in domains_slice {
        let domain = domain.clone();
        let permit = sem.clone();
        handles.push(tokio::spawn(async move {
            let _guard = permit.acquire().await.unwrap();
            whois::check_domain(&domain).await
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(res) = handle.await {
            results.push(res);
        }
    }

    Json(CheckBatchResponse {
        success: true,
        count: results.len(),
        results,
    })
}

async fn api_export_csv_handler(Json(payload): Json<ExportCsvPayload>) -> impl IntoResponse {
    let filter = payload.filter.unwrap_or_else(|| "all".to_string());
    let mut items = payload.results;

    if filter == "available" {
        items.retain(|r| r.status == "available");
    } else if filter == "registered" {
        items.retain(|r| r.status == "registered");
    }

    let filename = if filter == "available" {
        "dominios_disponiveis.csv"
    } else if filter == "registered" {
        "dominios_registrados.csv"
    } else {
        "dominios.csv"
    };

    // Gera CSV normalizado com somente a lista de domínios (um por linha)
    let mut output = String::new();
    for r in &items {
        if !r.domain.is_empty() {
            output.push_str(&r.domain);
            output.push('\n');
        }
    }

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "text/csv; charset=utf-8".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"").parse().unwrap(),
    );

    (headers, output)
}

async fn download_sample_handler(Path(file_type): Path<String>) -> Response {
    let (content, filename, content_type) = if file_type == "txt" {
        (
            include_str!("../sample_domains.txt"),
            "exemplo_dominios.txt",
            "text/plain; charset=utf-8",
        )
    } else if file_type == "csv" {
        (
            include_str!("../sample_domains.csv"),
            "exemplo_dominios.csv",
            "text/csv; charset=utf-8",
        )
    } else {
        return (StatusCode::NOT_FOUND, "Tipo não encontrado").into_response();
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"").parse().unwrap(),
    );

    (headers, content).into_response()
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/parse", post(api_parse_handler))
        .route("/api/check-single", post(api_check_single_handler))
        .route("/api/check-batch", post(api_check_batch_handler))
        .route("/api/export-csv", post(api_export_csv_handler))
        .route("/download-sample/:file_type", get(download_sample_handler))
        .nest_service("/static", ServeDir::new("static"));

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(5000);

    let addr = format!("0.0.0.0:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("============================================================");
            eprintln!("  ❌ ERRO AO INICIAR SERVIDOR:");
            eprintln!("  A porta {port} já está em uso por outro processo!");
            eprintln!("  Detalhes: {e}");
            eprintln!("  Dica: Você pode rodar em outra porta definindo $env:PORT=5001");
            eprintln!("============================================================");
            return;
        }
    };

    println!("============================================================");
    println!("  🦀 DomainFinder (Rust Engine) iniciado com sucesso!");
    println!("  🚀 Servidor rodando em: http://localhost:{port}");
    println!("  ⚡ Socket TCP não-bloqueante na porta 43 + Tokio Async");
    println!("============================================================");

    axum::serve(listener, app).await.unwrap();
}
