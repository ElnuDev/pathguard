use actix_web::HttpRequest;
use chrono::NaiveDateTime;
use diesel::prelude::*;

use crate::schema::activities;

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
		Activity {
			ip: req
				.connection_info()
				.realip_remote_addr()
				.unwrap_or_default()
				.to_owned(),
			path: req.path().to_string(),
			..Default::default()
		}
	}
}
