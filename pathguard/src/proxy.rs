use std::borrow::Cow;

use actix_web::{
	http::{
		header::{self, HeaderName, HeaderValue},
		StatusCode,
	},
	web, HttpRequest, HttpResponse, ResponseError,
};
use awc::{error::SendRequestError, Client};
use maud::{html, Render};
use thiserror::Error;

use crate::{
	auth::{Authorized, Fancy, FancyError},
	SESSION_COOKIE_NAME,
};

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

/// Header pathguard injects on every forwarded request so the backend
/// can identify the authenticated user.
///
/// Value contract: present iff the request came through pathguard. The
/// value is the pathguard username for authenticated callers and the
/// empty string for anonymous-but-allowed callers (which the default
/// group's rules permitted). A backend that wants "must be
/// authenticated" semantics checks for a non-empty value; a backend
/// that only wants "must come through pathguard" checks for the header's
/// presence.
const PATHGUARD_USER_HEADER: HeaderName = HeaderName::from_static("x-pathguard-user");

/// Removes pathguard's own session cookie from a serialized Cookie
/// header value.
///
/// Returns:
///  - `Some(Cow::Borrowed)` if the cookie was not present (caller can
///    leave the header alone)
///  - `Some(Cow::Owned)` with a rewritten value if the cookie was one
///    of several
///  - `None` if the session cookie was the only one (caller should
///    remove the Cookie header entirely)
fn strip_session_cookie<'a>(value: &'a str) -> Option<Cow<'a, str>> {
	let prefix = format!("{SESSION_COOKIE_NAME}=");
	let segments: Vec<&str> = value.split(';').map(str::trim).collect();
	if !segments.iter().any(|seg| seg.starts_with(&prefix)) {
		return Some(Cow::Borrowed(value));
	}
	let kept: Vec<&str> = segments
		.into_iter()
		.filter(|seg| !seg.is_empty() && !seg.starts_with(&prefix))
		.collect();
	if kept.is_empty() {
		None
	} else {
		Some(Cow::Owned(kept.join("; ")))
	}
}

pub async fn proxy(
	Fancy(Authorized(user)): Fancy<Authorized>,
	req: HttpRequest,
	body: web::Bytes,
	port: u16,
) -> Result<HttpResponse, FancyError<ProxyError>> {
	// We want to pass redirect headers to the client, not follow them ourselves
	let client = Client::builder().disable_redirects().finish();
	let mut forwarded_req =
		client.request_from(format!("http://127.0.0.1:{port}{}", req.uri()), req.head());
	{
		let headers = forwarded_req.headers_mut();

		for name in HOP_BY_HOP {
			headers.remove(*name);
		}

		// Strip the client's copy BEFORE injecting ours. A client that
		// sets X-Pathguard-User: admin in their own request must not
		// have that value reach the backend, or any authenticated user
		// (or any anonymous caller permitted by the default group)
		// becomes admin in the backend's view. The strip-then-insert
		// ordering is the entire reason this header is safe to ship.
		headers.remove(&PATHGUARD_USER_HEADER);
		let username = user.as_ref().map(|u| u.name.as_str()).unwrap_or("");
		// Usernames are not character-restricted at creation time, so
		// it is possible (though unusual) for a name to contain bytes
		// HTTP headers reject. Fall back to empty -- the backend then
		// sees the request as "came through pathguard, no usable user
		// identity", which fails closed rather than guessing.
		let value =
			HeaderValue::from_str(username).unwrap_or_else(|_| HeaderValue::from_static(""));
		headers.insert(PATHGUARD_USER_HEADER, value);

		// Strip pathguard's session cookie before it crosses the trust
		// boundary into the backend. The backend can't decrypt it (the
		// key lives in pathguard's process), but forwarding it leaks
		// the auth-system shape to the backend's request logs, can
		// collide with the backend's own cookie namespace, and is just
		// noise -- the user identity is now carried by the header
		// above, not by this cookie.
		if let Some(cookie) = headers.get(header::COOKIE).cloned() {
			if let Ok(s) = cookie.to_str() {
				match strip_session_cookie(s) {
					Some(Cow::Borrowed(_)) => { /* no pathguard cookie, leave header alone */ }
					Some(Cow::Owned(filtered)) => {
						if let Ok(new_value) = HeaderValue::from_str(&filtered) {
							headers.insert(header::COOKIE, new_value);
						}
					}
					None => {
						headers.remove(header::COOKIE);
					}
				}
			}
		}
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn strip_session_cookie_absent() {
		assert!(matches!(
			strip_session_cookie("foo=bar; baz=qux"),
			Some(Cow::Borrowed("foo=bar; baz=qux"))
		));
	}

	#[test]
	fn strip_session_cookie_only() {
		assert!(strip_session_cookie(&format!("{SESSION_COOKIE_NAME}=abc")).is_none());
	}

	#[test]
	fn strip_session_cookie_mixed() {
		let input = format!("foo=bar; {SESSION_COOKIE_NAME}=abc; baz=qux");
		assert_eq!(
			strip_session_cookie(&input).as_deref(),
			Some("foo=bar; baz=qux")
		);
	}

	#[test]
	fn strip_session_cookie_does_not_match_prefix() {
		// A cookie whose name happens to start with SESSION_COOKIE_NAME but
		// is not equal to it (e.g. "pathguard_id_other=...") must be kept.
		let input = format!("{SESSION_COOKIE_NAME}_other=keep");
		assert!(matches!(
			strip_session_cookie(&input),
			Some(Cow::Borrowed(_))
		));
	}
}
