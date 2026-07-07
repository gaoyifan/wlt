//! Web portal: static SPA page plus the JSON API consumed by it.

use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use askama::Template;
use axum::Router;
use axum::extract::{ConnectInfo, Form, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum_server::tls_rustls::RustlsConfig;
use serde::Serialize;
use tokio::task::JoinSet;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::app::{AppState, ip_family, normalize_ip};
use crate::config::{PortalConfig, WebConfig, duration_label};

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    v4_host: String,
    v6_host: String,
    api_hosts_json: String,
}

#[derive(Serialize)]
struct TimeLimitPayload {
    label: String,
    value: u32,
}

#[derive(Serialize)]
struct GroupPayload {
    title: String,
    field: String,
    options: Vec<String>,
    selected: String,
}

#[derive(Serialize)]
struct StatusPayload {
    ip: String,
    hostname: Option<String>,
    family: u8,
    available: bool,
    groups: Vec<GroupPayload>,
    current_outlet: String,
    expires: Option<u32>,
    time_limits: Vec<TimeLimitPayload>,
}

#[derive(Serialize)]
struct ActionResponse {
    ok: bool,
    message: String,
    family: u8,
}

fn action(
    status: StatusCode,
    ok: bool,
    message: impl Into<String>,
    family: u8,
) -> impl IntoResponse {
    (
        status,
        axum::Json(ActionResponse {
            ok,
            message: message.into(),
            family,
        }),
    )
}

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let portal = &state.cfg.portal;
    let template = IndexTemplate {
        v4_host: portal.v4_host.clone().unwrap_or_default(),
        v6_host: portal.v6_host.clone().unwrap_or_default(),
        api_hosts_json: api_hosts_json(portal),
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("template render failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn api_hosts_json(portal: &PortalConfig) -> String {
    let mut hosts = serde_json::Map::new();
    for (page_host, api_hosts) in &portal.hosts {
        let v4_host = api_hosts
            .v4_host
            .as_deref()
            .or(portal.v4_host.as_deref())
            .unwrap_or("");
        let v6_host = api_hosts
            .v6_host
            .as_deref()
            .or(portal.v6_host.as_deref())
            .unwrap_or("");
        hosts.insert(
            page_host.clone(),
            serde_json::json!({
                "4": v4_host,
                "6": v6_host,
            }),
        );
    }
    serde_json::Value::Object(hosts).to_string()
}

fn time_limits(state: &AppState) -> Vec<TimeLimitPayload> {
    state
        .cfg
        .time_limits
        .iter()
        .map(|&hours| TimeLimitPayload {
            label: duration_label(hours),
            value: hours,
        })
        .collect()
}

async fn api_status(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ip = normalize_ip(addr.ip());
    let family = ip_family(ip);
    let mut payload = StatusPayload {
        ip: ip.to_string(),
        hostname: state.resolve_hostname(ip).await,
        family,
        available: false,
        groups: vec![],
        current_outlet: "默认".into(),
        expires: None,
        time_limits: time_limits(&state),
    };
    let Some(map_name) = state.cfg.map_for(family) else {
        return axum::Json(payload);
    };
    payload.available = true;

    let entry = state
        .nft
        .get_entry(&payload.ip, map_name)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("failed to fetch nftables entry for {ip}: {e:#}");
            None
        });
    let mark_value = entry.as_ref().map(|e| e.mark);
    payload.expires = entry.as_ref().and_then(|e| e.expires);

    let mut current_labels: Vec<&str> = Vec::new();
    for (idx, group) in state.cfg.outlet_groups.iter().enumerate() {
        if group.outlets_for(family).is_empty() {
            continue;
        }
        let selection = mark_value.and_then(|mark| group.selection_for(mark, family));
        if let Some(name) = selection {
            current_labels.push(name);
        }
        let display = group.display_outlets_for(family);
        payload.groups.push(GroupPayload {
            title: group.title.clone(),
            field: format!("group_{idx}"),
            options: display.iter().map(|&(name, _)| name.to_owned()).collect(),
            selected: selection.unwrap_or(display[0].0).to_owned(),
        });
    }
    payload.current_outlet = match mark_value {
        None => "默认".into(),
        Some(mark) if current_labels.is_empty() => format!("{mark:#x}"),
        Some(_) => current_labels.join(" + "),
    };
    axum::Json(payload)
}

async fn api_open(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let ip = normalize_ip(addr.ip());
    let family = ip_family(ip);
    let Some(map_name) = state.cfg.map_for(family) else {
        return action(
            StatusCode::BAD_REQUEST,
            false,
            "当前协议族暂不支持出口选择".into(),
            family,
        );
    };

    let mut mark_value: u32 = 0;
    let mut selected_labels: Vec<&str> = Vec::new();
    for (idx, group) in state.cfg.outlet_groups.iter().enumerate() {
        let outlets = group.outlets_for(family);
        if outlets.is_empty() {
            continue;
        }
        let selected = form
            .get(&format!("group_{idx}"))
            .and_then(|name| outlets.get_key_value(name));
        let Some((name, &value)) = selected else {
            return action(
                StatusCode::BAD_REQUEST,
                false,
                format!("无效的出口选择：{}", group.title),
                family,
            );
        };
        selected_labels.push(name);
        mark_value |= value & group.mask;
    }

    let hours = form.get("hours").and_then(|h| h.parse::<u32>().ok());
    let Some(hours) = hours.filter(|h| state.cfg.time_limits.contains(h)) else {
        return action(
            StatusCode::BAD_REQUEST,
            false,
            "无效的时限选择".into(),
            family,
        );
    };

    let ip_str = ip.to_string();
    if let Err(e) = state.nft.delete_element(&ip_str, map_name).await {
        tracing::error!("error deleting rule for {ip}: {e:#}");
    }
    match state
        .nft
        .add_element(&ip_str, mark_value, hours, map_name)
        .await
    {
        Ok(()) => {
            let message = format!(
                "IPv{family} 已开通：「{}」，{}",
                selected_labels.join(" + "),
                duration_label(hours)
            );
            action(StatusCode::OK, true, message, family)
        }
        Err(e) => {
            tracing::error!("error adding rule for {ip}: {e:#}");
            action(
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
                "设置网络出口失败".into(),
                family,
            )
        }
    }
}

async fn api_close(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ip = normalize_ip(addr.ip());
    let family = ip_family(ip);
    if let Some(map_name) = state.cfg.map_for(family) {
        match state.nft.delete_element(&ip.to_string(), map_name).await {
            Ok(()) => return action(StatusCode::OK, true, format!("IPv{family} 已重置"), family),
            Err(e) => tracing::error!("error deleting rule for {ip}: {e:#}"),
        }
    }
    action(
        StatusCode::INTERNAL_SERVER_ERROR,
        false,
        "重置网络失败".into(),
        family,
    )
}

/// Allow cross-origin requests from configured domains and their subdomains
/// (the SPA on one split-horizon host fetches the sibling family's API; no
/// credentials).
fn origin_host_allowed(host: &str, domains: &[String]) -> bool {
    domains
        .iter()
        .any(|domain| host == domain || host.ends_with(&format!(".{domain}")))
}

fn cors_layer(domains: Vec<String>) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin: &HeaderValue, _| {
            let Ok(origin) = origin.to_str() else {
                return false;
            };
            let host = origin
                .split_once("//")
                .map_or("", |(_, rest)| rest)
                .split(['/', ':'])
                .next()
                .unwrap_or("");
            origin_host_allowed(host, &domains)
        }))
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([header::CONTENT_TYPE])
}

fn router(state: AppState) -> Router {
    let cors_domains = state.cfg.portal.cors_domains();
    let mut router = Router::new()
        .route("/", get(index))
        .route("/api/status", get(api_status))
        .route("/api/open", post(api_open))
        .route("/api/close", post(api_close))
        .with_state(state);
    if !cors_domains.is_empty() {
        router = router.layer(cors_layer(cors_domains));
    }
    router
}

async fn serve_http(router: Router, listen: String) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("failed to bind {listen}"))?;
    tracing::info!("web listening on {listen}");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("web server failed")
}

async fn serve_https(router: Router, listen: String, tls: RustlsConfig) -> Result<()> {
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid https listen address {listen}"))?;
    tracing::info!("web (https) listening on {addr}");
    axum_server::bind_rustls(addr, tls)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("https server failed")
}

pub async fn serve(state: AppState, cfg: WebConfig) -> Result<()> {
    let router = router(state);
    let mut listeners: JoinSet<Result<()>> = JoinSet::new();
    for listen in cfg.listen {
        listeners.spawn(serve_http(router.clone(), listen));
    }
    if let Some(https) = cfg.https {
        let tls = RustlsConfig::from_pem_file(&https.cert, &https.key)
            .await
            .context("failed to load TLS certificate")?;
        for listen in https.listen {
            listeners.spawn(serve_https(router.clone(), listen, tls.clone()));
        }
    }
    // Listeners never exit on their own; treat the first return as fatal.
    match listeners.join_next().await {
        Some(result) => result.context("web listener panicked")?,
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PortalConfig, PortalHosts};
    use indexmap::IndexMap;

    #[test]
    fn renders_per_page_api_hosts_as_json() {
        let mut hosts = IndexMap::new();
        hosts.insert(
            "wlt.example.org".to_owned(),
            PortalHosts {
                v4_host: Some("wlt-ipv4.example.org".to_owned()),
                v6_host: Some("wlt-ipv6.example.org".to_owned()),
            },
        );
        hosts.insert(
            "wlt.example.net".to_owned(),
            PortalHosts {
                v4_host: None,
                v6_host: Some("wlt-ipv6.example.net".to_owned()),
            },
        );
        let portal = PortalConfig {
            v4_host: Some("wlt-ipv4.default.example".to_owned()),
            v6_host: Some("wlt-ipv6.default.example".to_owned()),
            hosts,
            cors_domain: None,
            cors_domains: vec![],
        };

        let data: serde_json::Value = serde_json::from_str(&api_hosts_json(&portal)).unwrap();

        assert_eq!(data["wlt.example.org"]["4"], "wlt-ipv4.example.org");
        assert_eq!(data["wlt.example.org"]["6"], "wlt-ipv6.example.org");
        assert_eq!(data["wlt.example.net"]["4"], "wlt-ipv4.default.example");
        assert_eq!(data["wlt.example.net"]["6"], "wlt-ipv6.example.net");
    }

    #[test]
    fn matches_exact_cors_domains_and_subdomains() {
        let domains = vec!["example.net".to_owned(), "example.org".to_owned()];

        assert!(origin_host_allowed("example.net", &domains));
        assert!(origin_host_allowed("wlt.example.net", &domains));
        assert!(origin_host_allowed("wlt.example.org", &domains));
        assert!(!origin_host_allowed("badexample.net", &domains));
        assert!(!origin_host_allowed("example.com", &domains));
    }
}
