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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TldInfo {
    pub tld: String,
    pub name: String,
    pub category: String,
    pub category_name: String,
    pub default_checked: bool,
    pub price_estimate: String,
    pub buy_provider: String,
    pub description: String,
}

pub fn get_all_tlds() -> Vec<TldInfo> {
    vec![
        // Mais Populares
        TldInfo {
            tld: ".com".to_string(),
            name: "Comercial Global".to_string(),
            category: "populares".to_string(),
            category_name: "Mais Populares".to_string(),
            default_checked: true,
            price_estimate: "$10 - $14/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "O domínio mais popular, valioso e reconhecido do mundo.".to_string(),
        },
        TldInfo {
            tld: ".com.br".to_string(),
            name: "Brasil Oficial".to_string(),
            category: "populares".to_string(),
            category_name: "Mais Populares".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "O padrão absoluto de maior confiança e relevância no Brasil.".to_string(),
        },
        TldInfo {
            tld: ".net".to_string(),
            name: "Redes & Infra".to_string(),
            category: "populares".to_string(),
            category_name: "Mais Populares".to_string(),
            default_checked: true,
            price_estimate: "$12 - $15/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Tradicional e perfeito para tecnologia, redes e conectividade.".to_string(),
        },
        TldInfo {
            tld: ".org".to_string(),
            name: "Organizações".to_string(),
            category: "populares".to_string(),
            category_name: "Mais Populares".to_string(),
            default_checked: true,
            price_estimate: "$10 - $14/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Credibilidade mundial para comunidades, fundações e iniciativas.".to_string(),
        },
        TldInfo {
            tld: ".io".to_string(),
            name: "Tech & Startups".to_string(),
            category: "populares".to_string(),
            category_name: "Mais Populares".to_string(),
            default_checked: true,
            price_estimate: "$35 - $45/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "O favorito do Vale do Silício, desenvolvedores e plataformas SaaS.".to_string(),
        },
        TldInfo {
            tld: ".ai".to_string(),
            name: "Inteligência Artificial (IA)".to_string(),
            category: "populares".to_string(),
            category_name: "Mais Populares".to_string(),
            default_checked: true,
            price_estimate: "$70 - $90/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "O domínio definitivo e mais valioso para IA, Machine Learning e Inovação.".to_string(),
        },
        TldInfo {
            tld: ".co".to_string(),
            name: "Companhias Globais".to_string(),
            category: "populares".to_string(),
            category_name: "Mais Populares".to_string(),
            default_checked: true,
            price_estimate: "$10 - $25/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Curto, moderno e excelente alternativa quando o .com está ocupado.".to_string(),
        },
        TldInfo {
            tld: ".dev".to_string(),
            name: "Desenvolvedores & Código".to_string(),
            category: "populares".to_string(),
            category_name: "Mais Populares".to_string(),
            default_checked: true,
            price_estimate: "$12 - $16/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Extensão segura do Google para engenheiros de software e devs.".to_string(),
        },
        TldInfo {
            tld: ".app".to_string(),
            name: "Aplicativos & SaaS".to_string(),
            category: "populares".to_string(),
            category_name: "Mais Populares".to_string(),
            default_checked: true,
            price_estimate: "$12 - $16/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Feito sob medida pelo Google para aplicativos web, mobile e APIs.".to_string(),
        },
        TldInfo {
            tld: ".me".to_string(),
            name: "Marca Pessoal".to_string(),
            category: "populares".to_string(),
            category_name: "Mais Populares".to_string(),
            default_checked: true,
            price_estimate: "$8 - $18/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Ideal para portfólios pessoais, criadores de conteúdo e profissionais.".to_string(),
        },

        // Brasil (.br)
        TldInfo {
            tld: ".net.br".to_string(),
            name: "Redes & Conectividade BR".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Para empresas de infraestrutura, telecomunicações e redes no Brasil.".to_string(),
        },
        TldInfo {
            tld: ".org.br".to_string(),
            name: "Organizações BR".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Entidades sem fins lucrativos, ONGs e fundações brasileiras.".to_string(),
        },
        TldInfo {
            tld: ".dev.br".to_string(),
            name: "Desenvolvedores Brasil".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "A extensão oficial do Registro.br para programadores e tech leads.".to_string(),
        },
        TldInfo {
            tld: ".app.br".to_string(),
            name: "Aplicativos Brasil".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Para aplicativos móveis e soluções web nacionais.".to_string(),
        },
        TldInfo {
            tld: ".tech.br".to_string(),
            name: "Tecnologia Brasil".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Empresas e iniciativas brasileiras do ecossistema de inovação.".to_string(),
        },
        TldInfo {
            tld: ".io.br".to_string(),
            name: "Tech & Inovação BR".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Alternativa nacional e econômica para projetos de tecnologia.".to_string(),
        },
        TldInfo {
            tld: ".eco.br".to_string(),
            name: "Sustentabilidade & ESG".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Iniciativas ecológicas, créditos de carbono e sustentabilidade.".to_string(),
        },
        TldInfo {
            tld: ".art.br".to_string(),
            name: "Artes & Cultura BR".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Música, galerias, design e artes visuais no Brasil.".to_string(),
        },
        TldInfo {
            tld: ".store.br".to_string(),
            name: "Lojas Virtuais BR".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Extensão comercial direta para lojas virtuais e varejo online.".to_string(),
        },
        TldInfo {
            tld: ".site.br".to_string(),
            name: "Websites Brasil".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Websites institucionais, páginas de captura e portais gerais.".to_string(),
        },
        TldInfo {
            tld: ".blog.br".to_string(),
            name: "Blogs Brasileiros".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Criadores de conteúdo, publicações e portais informativos.".to_string(),
        },
        TldInfo {
            tld: ".eti.br".to_string(),
            name: "Especialistas de TI".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: true,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Profissionais liberais, consultores e especialistas em TI.".to_string(),
        },
        TldInfo {
            tld: ".adv.br".to_string(),
            name: "Advogados & Jurídico".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: false,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Advogados com registro regular na OAB e sociedades de advogados.".to_string(),
        },
        TldInfo {
            tld: ".med.br".to_string(),
            name: "Medicina & Saúde".to_string(),
            category: "brasil".to_string(),
            category_name: "Brasil (.br)".to_string(),
            default_checked: false,
            price_estimate: "R$ 40/ano".to_string(),
            buy_provider: "registro.br".to_string(),
            description: "Médicos com registro regular no CRM e clínicas médicas.".to_string(),
        },

        // Tecnologia & IA
        TldInfo {
            tld: ".tech".to_string(),
            name: "Tecnologia & Inovação".to_string(),
            category: "tech".to_string(),
            category_name: "Tecnologia & IA".to_string(),
            default_checked: true,
            price_estimate: "$5 - $20/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Perfeito para negócios tech, produtos de hardware e software.".to_string(),
        },
        TldInfo {
            tld: ".cloud".to_string(),
            name: "Computação em Nuvem".to_string(),
            category: "tech".to_string(),
            category_name: "Tecnologia & IA".to_string(),
            default_checked: true,
            price_estimate: "$8 - $15/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Soluções SaaS, hospedagem, cloud computing e infraestrutura moderna.".to_string(),
        },
        TldInfo {
            tld: ".software".to_string(),
            name: "Empresas de Software".to_string(),
            category: "tech".to_string(),
            category_name: "Tecnologia & IA".to_string(),
            default_checked: true,
            price_estimate: "$25 - $35/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Transmite autoridade máxima para software houses e produtos digitais.".to_string(),
        },
        TldInfo {
            tld: ".digital".to_string(),
            name: "Negócios Digitais".to_string(),
            category: "tech".to_string(),
            category_name: "Tecnologia & IA".to_string(),
            default_checked: true,
            price_estimate: "$6 - $20/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Agências digitais, transformação digital e produtos online.".to_string(),
        },
        TldInfo {
            tld: ".space".to_string(),
            name: "Comunidade Tech".to_string(),
            category: "tech".to_string(),
            category_name: "Tecnologia & IA".to_string(),
            default_checked: true,
            price_estimate: "$4 - $12/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Espaço para inovadores, hackerspaces e projetos experimentais.".to_string(),
        },
        TldInfo {
            tld: ".global".to_string(),
            name: "Presença Global".to_string(),
            category: "tech".to_string(),
            category_name: "Tecnologia & IA".to_string(),
            default_checked: true,
            price_estimate: "$15 - $25/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Alcance mundial e presença corporativa sem restrição geográfica.".to_string(),
        },
        TldInfo {
            tld: ".ia".to_string(),
            name: "Inteligência Artificial (Dica: .ai)".to_string(),
            category: "tech".to_string(),
            category_name: "Tecnologia & IA".to_string(),
            default_checked: true,
            price_estimate: "Inativo na ICANN".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Nota: .ia não existe na ICANN. O domínio oficial mundialmente adotado é .ai.".to_string(),
        },

        // Países & Internacionais
        TldInfo {
            tld: ".uk".to_string(),
            name: "Reino Unido (.uk)".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "$7 - $12/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "A extensão oficial de primeiro nível do Reino Unido.".to_string(),
        },
        TldInfo {
            tld: ".co.uk".to_string(),
            name: "Empresas Reino Unido".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "$7 - $12/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "A mais tradicional e utilizada extensão de negócios no Reino Unido.".to_string(),
        },
        TldInfo {
            tld: ".pt".to_string(),
            name: "Portugal".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "€10 - €15/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Domínio de topo oficial de Portugal e da lusofonia europeia.".to_string(),
        },
        TldInfo {
            tld: ".es".to_string(),
            name: "Espanha".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "€8 - €14/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Para empresas que atuam no mercado espanhol e hispânico.".to_string(),
        },
        TldInfo {
            tld: ".de".to_string(),
            name: "Alemanha".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "€6 - €12/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "O maior e mais forte ccTLD da Europa continental.".to_string(),
        },
        TldInfo {
            tld: ".fr".to_string(),
            name: "França".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "€7 - €15/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Presença no mercado francês e espaço francófono.".to_string(),
        },
        TldInfo {
            tld: ".it".to_string(),
            name: "Itália".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "€8 - €15/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Domínio oficial da Itália, polo europeu de design e inovação.".to_string(),
        },
        TldInfo {
            tld: ".nl".to_string(),
            name: "Holanda / Países Baixos".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "€7 - €14/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Um dos países com maior penetração digital da Europa.".to_string(),
        },
        TldInfo {
            tld: ".eu".to_string(),
            name: "União Europeia".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "€5 - €10/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Identidade única e unificada para negócios em toda a Europa.".to_string(),
        },
        TldInfo {
            tld: ".us".to_string(),
            name: "Estados Unidos".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "$8 - $15/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Domínio nacional dos EUA para marcas e cidadãos americanos.".to_string(),
        },
        TldInfo {
            tld: ".ca".to_string(),
            name: "Canadá".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "$12 - $18/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Presença no crescente mercado canadense de tecnologia.".to_string(),
        },
        TldInfo {
            tld: ".ch".to_string(),
            name: "Suíça".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "$15 - $22/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Prestígio, estabilidade financeira e segurança com o TLD da Suíça.".to_string(),
        },
        TldInfo {
            tld: ".lat".to_string(),
            name: "América Latina".to_string(),
            category: "internacional".to_string(),
            category_name: "Internacionais & Países".to_string(),
            default_checked: true,
            price_estimate: "$10 - $20/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Comunidade e ecossistema integrado de toda a América Latina.".to_string(),
        },

        // Negócios & Vendas
        TldInfo {
            tld: ".store".to_string(),
            name: "Lojas Virtuais".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$5 - $15/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Direto ao ponto para vendas online, lojas e marcas de produtos.".to_string(),
        },
        TldInfo {
            tld: ".shop".to_string(),
            name: "Shopping & E-commerce".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$4 - $12/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Reconhecimento global instantâneo como destino de compras.".to_string(),
        },
        TldInfo {
            tld: ".online".to_string(),
            name: "Presença Online".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$3 - $10/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Versátil para marcas, consultorias e novos lançamentos na web.".to_string(),
        },
        TldInfo {
            tld: ".site".to_string(),
            name: "Websites Gerais".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$3 - $10/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Nome limpo e memorável para websites corporativos e pessoais.".to_string(),
        },
        TldInfo {
            tld: ".club".to_string(),
            name: "Clubes & Comunidades".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$10 - $18/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Programas de assinatura, membresias e clubes de vantagens.".to_string(),
        },
        TldInfo {
            tld: ".top".to_string(),
            name: "Marcas Top".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$3 - $8/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Extensão curta, altamente acessível e com forte apelo comercial.".to_string(),
        },
        TldInfo {
            tld: ".pro".to_string(),
            name: "Profissionais Certificados".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$5 - $15/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Destaque seu profissionalismo e autoridade técnica no seu nicho.".to_string(),
        },
        TldInfo {
            tld: ".biz".to_string(),
            name: "Negócios & B2B".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$12 - $18/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Uma das extensões comerciais mais tradicionais do mercado corporativo.".to_string(),
        },
        TldInfo {
            tld: ".agency".to_string(),
            name: "Agências & Criação".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$15 - $25/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Específico para agências de publicidade, design e marketing.".to_string(),
        },
        TldInfo {
            tld: ".solutions".to_string(),
            name: "Soluções Corporativas".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$15 - $25/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Empresas prestadoras de serviços, integradoras e consultorias B2B.".to_string(),
        },
        TldInfo {
            tld: ".link".to_string(),
            name: "Links & Bio".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$6 - $14/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Excelente para páginas link-in-bio, encurtadores e campanhas de anúncios.".to_string(),
        },
        TldInfo {
            tld: ".live".to_string(),
            name: "Streaming & Ao Vivo".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$12 - $20/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "Para canais de transmissão ao vivo, podcasts e eventos em tempo real.".to_string(),
        },
        TldInfo {
            tld: ".xyz".to_string(),
            name: "Criativos & Web3".to_string(),
            category: "negocios".to_string(),
            category_name: "Negócios & Vendas".to_string(),
            default_checked: true,
            price_estimate: "$2 - $12/ano".to_string(),
            buy_provider: "namecheap".to_string(),
            description: "A extensão mais popular entre a nova geração de startups e criadores.".to_string(),
        },
    ]
}

async fn index_handler() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate".parse().unwrap());
    headers.insert(header::PRAGMA, "no-cache".parse().unwrap());
    headers.insert(header::EXPIRES, "0".parse().unwrap());
    (headers, Html(include_str!("../templates/index.html")))
}

async fn busca_unica_handler() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate".parse().unwrap());
    headers.insert(header::PRAGMA, "no-cache".parse().unwrap());
    headers.insert(header::EXPIRES, "0".parse().unwrap());
    (headers, Html(include_str!("../templates/busca_unica.html")))
}

async fn api_tlds_handler() -> impl IntoResponse {
    Json(get_all_tlds())
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
        .route("/busca-unica", get(busca_unica_handler))
        .route("/busca", get(busca_unica_handler))
        .route("/api/tlds", get(api_tlds_handler))
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
