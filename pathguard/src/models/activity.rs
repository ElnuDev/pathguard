use actix_web::HttpRequest;
use chrono::NaiveDateTime;
use diesel::prelude::*;

use crate::schema::activities;
use crate::ARGS;

#[derive(Queryable, Selectable, Insertable, Debug, Default)]
#[diesel(table_name = activities)]
pub struct Activity {
	pub timestamp: NaiveDateTime,
	pub user: Option<String>,
	pub ip: String,
	pub path: String,
	pub allowed: bool,
}

impl Activity {
	/// Activity with ip and path set from given request,
	/// with all other fields left as default
	pub fn from_request(req: &HttpRequest) -> Self {
		// `realip_remote_addr` consults Forwarded / X-Forwarded-For
		// headers, which are untrusted unless pathguard is behind a
		// proxy that strips client-supplied copies. When the operator
		// has not opted in via --trust-forwarded-for, fall back to the
		// real peer address so the audit log can't be spoofed by
		// anyone who can reach the listening socket.
		let ip = if ARGS.trust_forwarded_for {
			req.connection_info()
				.realip_remote_addr()
				.unwrap_or_default()
				.to_owned()
		} else {
			req.peer_addr()
				.map(|addr| addr.ip().to_string())
				.unwrap_or_default()
		};
		Activity {
			ip,
			path: req.path().to_string(),
			..Default::default()
		}
	}
}
