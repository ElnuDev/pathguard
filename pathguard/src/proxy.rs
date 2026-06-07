use actix_web::{http::StatusCode, web, HttpRequest, HttpResponse, ResponseError};
use awc::{error::SendRequestError, Client};
use maud::{html, Render};
use thiserror::Error;

use crate::auth::{Authorized, Fancy, FancyError};

#[derive(Error, Debug)]
pub enum ProxyError {
	#[error("{0}")]
	SendRequest(#[from] SendRequestError),
}

impl Render for ProxyError {
	fn render(&self) -> maud::Markup {
		html! { (self.to_string()) }
	}
}

impl ResponseError for ProxyError {
	fn status_code(&self) -> StatusCode {
		StatusCode::BAD_GATEWAY
	}
}

/// RFC 7230 §6.1 hop-by-hop header names. A standards-compliant proxy
/// must not forward these from the client to the upstream, nor from
/// the upstream back to the client -- they describe the single hop
/// they were sent on. Forwarding them can break WebSocket upgrades,
/// confuse keep-alive accounting, and (with a misbehaving backend)
/// open request-smuggling attack surfaces.
const HOP_BY_HOP: &[&str] = &[
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
];

fn is_hop_by_hop(name: &str) -> bool {
	HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

pub async fn proxy(
	_auth: Fancy<Authorized>,
	req: HttpRequest,
	body: web::Bytes,
	port: u16,
) -> Result<HttpResponse, FancyError<ProxyError>> {
	// We want to pass redirect headers to the client, not follow them ourselves
	let client = Client::builder().disable_redirects().finish();
	let mut forwarded_req =
		client.request_from(format!("http://127.0.0.1:{port}{}", req.uri()), req.head());
	for name in HOP_BY_HOP {
		forwarded_req.headers_mut().remove(*name);
	}
	let res = forwarded_req
		.send_body(body)
		.await
		.map_err(ProxyError::SendRequest)?;
	let mut client_res = {
		let mut builder = HttpResponse::build(res.status());
		for (key, value) in res.headers() {
			if is_hop_by_hop(key.as_str()) {
				continue;
			}
			builder.insert_header((key, value));
		}
		builder
	};
	Ok(client_res.streaming(res))
}
