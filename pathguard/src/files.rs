use std::{
	borrow::Cow,
	fs::{self, DirEntry},
	io,
	path::{Path, PathBuf},
};

use actix_files::NamedFile;
use actix_htmx::Htmx;
use actix_web::{
	http::StatusCode, web::Redirect, HttpRequest, HttpResponse, Responder, ResponseError,
};
use chrono::{DateTime, Timelike, Utc};
use diesel::{dsl::insert_into, RunQueryDsl};
use maud::{html, PreEscaped, Render};
use thiserror::Error;

use crate::{
	auth::{user_rules, user_rules_allowed, Fancy, FancyError, Unauthorized, UnauthorizedError},
	database::DatabaseError,
	models::{group::Rule, Activity},
	templates::{const_icon, page},
	DATABASE,
};

#[derive(Error, Debug)]
pub enum FilesError {
	#[error("{0}")]
	Unauthorized(#[from] UnauthorizedError),
	#[error("Path out of scope of served directory")]
	OutOfScope,
	#[error("{0}")]
	Database(#[from] DatabaseError),
	#[error("{0}")]
	Io(#[from] io::Error),
}

impl From<UnauthorizedError> for FancyError<FilesError> {
	fn from(value: UnauthorizedError) -> Self {
		Self(value.into())
	}
}

impl From<DatabaseError> for FancyError<FilesError> {
	fn from(value: DatabaseError) -> Self {
		Self(value.into())
	}
}

impl From<io::Error> for FancyError<FilesError> {
	fn from(value: io::Error) -> Self {
		Self(value.into())
	}
}

impl ResponseError for FilesError {
	fn status_code(&self) -> StatusCode {
		match self {
			Self::Unauthorized(err) => err.status_code(),
			Self::OutOfScope => StatusCode::FORBIDDEN,
			Self::Database(err) => err.status_code(),
			Self::Io(err) => match err.kind() {
				io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
				io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
				io::ErrorKind::ConnectionRefused
				| io::ErrorKind::ConnectionReset
				| io::ErrorKind::HostUnreachable
				| io::ErrorKind::NetworkUnreachable
				| io::ErrorKind::ConnectionAborted
				| io::ErrorKind::NotConnected
				| io::ErrorKind::NetworkDown
				| io::ErrorKind::WouldBlock
				| io::ErrorKind::StaleNetworkFileHandle
				| io::ErrorKind::TimedOut => StatusCode::SERVICE_UNAVAILABLE,
				io::ErrorKind::ResourceBusy => StatusCode::LOCKED,
				_ => StatusCode::INTERNAL_SERVER_ERROR,
			},
		}
	}
}

impl Render for FilesError {
	fn render(&self) -> maud::Markup {
		match self {
			FilesError::Unauthorized(unauthorized) => unauthorized.render(),
			_ => html! { (self.to_string()) },
		}
	}
}

/// ### TODO: Recursive file search
///
/// For instance, suppose we have, where a is not allowed,
/// but a/b/c/file4 is allowed.
/// ```
/// a
/// ├── b
/// │   ├── c
/// │   │   └── file4
/// │   └── file3
/// ├── file1
/// └── file2
/// ```
/// Even though a/b/c is not explicitly permitted in our rules,
/// we should be able to see a/b/c pop up in the file browser in order to
/// make file4 accessible.
///
/// ### TODO: Rethink rule sorting
///
/// Currently, rules have a sort field -- is this really necessary?
///
/// Wouldn't simple alphabetic sorting be adequate?
///
/// ### TODO: Make it more clear who the current user is, BadLogin isn't handled
pub async fn files(
	Fancy(Unauthorized { user, fallback_err }): Fancy<Unauthorized>,
	req: HttpRequest,
	htmx: Htmx,
	root: &Path,
) -> Result<HttpResponse, FancyError<FilesError>> {
	// Get request timestamp before database ops
	let timestamp = Utc::now().naive_utc();
	let is_admin = user
		.as_ref()
		.map(|user| user.is_admin())
		.unwrap_or_default();
	let log_activity = |allowed| {
		if is_admin {
			return Ok(());
		}
		DATABASE.run(|conn| {
			use crate::schema::activities::dsl::activities;
			insert_into(activities)
				.values(Activity {
					user: user.as_ref().map(|user| user.name.clone()),
					timestamp,
					path: req.path().to_string(),
					allowed,
					..Activity::from_request(&req)
				})
				.execute(conn)?;
			Ok(())
		})
	};

	let path = req.path();
	let decoded_path = urlencoding::decode(path).unwrap_or(Cow::Borrowed(path));
	let path = root.join(decoded_path.trim_start_matches("/"));
	if !path.canonicalize()?.starts_with(root) {
		log_activity(false)?;
		return Err(FancyError(FilesError::OutOfScope));
	}
	Ok(match path.is_dir() {
		false => {
			if !is_admin
				&& !user_rules_allowed(
					&DATABASE.run(|conn| user_rules(conn, user.as_ref()))?,
					req.path(),
				) {
				log_activity(false)?;
				return Err(fallback_err.into());
			}
			log_activity(true)?;
			NamedFile::open(path)?.prefer_utf8(true).into_response(&req)
		}
		true => {
			let index = path.join("index.html");
			let index_exists = fs::exists(&index)?;
			if !index_exists && !req.path().ends_with("/") {
				let redirect = req.path().to_string() + "/";
				return Ok(if htmx.is_htmx {
					htmx.redirect(redirect);
					HttpResponse::Ok().finish()
				} else {
					Redirect::to(redirect)
						.respond_to(&req)
						.map_into_boxed_body()
				});
			}
			let rules: Option<Vec<Rule>> = if is_admin {
				None
			} else {
				Some(
					DATABASE
						.run(|conn| user_rules(conn, user.as_ref()))?
						.into_iter()
						.collect(),
				)
			};
			if index_exists
				&& rules
					.as_ref()
					.map(|rules| user_rules_allowed(rules, req.path()))
					.unwrap_or(true)
			{
				log_activity(true)?;
				match NamedFile::open(index) {
					Ok(file) => return Ok(file.prefer_utf8(true).into_response(&req)),
					// This is unreachable because we already checked
					//Err(err) if err.kind() == io::ErrorKind::NotFound => {},
					Err(err) => return Err(err.into()),
				}
			}

			const HOME_: &str = "home";
			const HOME: &str = HOME_;

			const DOCUMENT_: &str = "document";
			const DOCUMENT: &str = DOCUMENT_;

			const FOLDER_: &str = "folder";
			const FOLDER: &str = FOLDER_;

			let mut entries: Vec<(PathBuf, fs::Metadata, String)> = fs::read_dir(path)?
				.collect::<Result<Vec<DirEntry>, io::Error>>()?
				.into_iter()
				.filter_map(|entry| {
					let name = entry
						.file_name()
						.to_str()
						.filter(|name| {
							!name.starts_with(".")
								&& rules
									.as_ref()
									.map(|rules| {
										user_rules_allowed(rules, &(req.path().to_owned() + name))
									})
									.unwrap_or(true)
						})
						.map(|str| str.to_owned());
					name.map(|name| (entry, name))
				})
				.map(|(entry, name)| {
					let path = entry.path();
					fs::metadata(&path).map(|metadata| (path, metadata, name))
				})
				.collect::<io::Result<Vec<(PathBuf, fs::Metadata, String)>>>()?;
			entries.sort_by(
				|(_a_path, a_metadata, a_name), (_b_path, b_metadata, b_name)| {
					(!a_metadata.is_dir(), a_name).cmp(&(!b_metadata.is_dir(), b_name))
				},
			);
			if entries.is_empty()
				&& rules
					.as_ref()
					.map(|rules| !user_rules_allowed(rules, req.path()))
					.unwrap_or_default()
			{
				log_activity(false)?;
				return Err(FancyError(fallback_err.into()));
			}
			log_activity(true)?;

			fn boosted_dir(is_dir: bool, path: &Path) -> io::Result<Option<&str>> {
				Ok((!is_dir || fs::exists(path.join("index.html"))?).then_some("false"))
			}

			HttpResponse::Ok().body(page(html! {
				svg xmlns="http://www.w3.org/2000/svg" style="display: none" {
					symbol #(HOME_) fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" {
						(PreEscaped(r#"<path stroke-linecap="round" stroke-linejoin="round" d="m2.25 12 8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" />"#))
					}
					symbol #(DOCUMENT_) fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" {
						(PreEscaped(r#"<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z" />"#))
					}
					symbol #(FOLDER_) fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" {
						(PreEscaped(r#"<path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 0 1 4.5 9.75h15A2.25 2.25 0 0 1 21.75 12v.75m-8.69-6.44-2.12-2.12a1.5 1.5 0 0 0-1.061-.44H4.5A2.25 2.25 0 0 0 2.25 6v12a2.25 2.25 0 0 0 2.25 2.25h15A2.25 2.25 0 0 0 21.75 18V9a2.25 2.25 0 0 0-2.25-2.25h-5.379a1.5 1.5 0 0 1-1.06-.44Z" />"#))
					}

				}
				@if req.path() != "/" {
					nav.breadcrumbs aria-label="Breadcrumbs" {
						ol.margin-start:0 {
							@let mut path = root.to_owned();
							li {
								a.warn
									hx-boost=[boosted_dir(true, &path)?]
									href="/"
								{ (const_icon!(HOME)) " Home" }
							}
							@let mut link = String::new();
							@let comps: Vec<&str> = decoded_path.split("/").skip(1).collect();
							@for comp in comps.iter().rev().skip(2).rev() {
								li {
									@let _ = { path.push(comp); };
									a.warn
										hx-boost=[boosted_dir(true, &path)?]
										href={ ({ link.push('/'); link.push_str(comp); &link }) "/" }
									{
										(const_icon!(FOLDER)) " " (comp)
									}
								}
							}
							li {
								u { (const_icon!(FOLDER)) " " (comps[comps.len() - 2]) }
							}
						}
					}
				} @else { u { (const_icon!(HOME)) " Home" } }
				ul.list-of-links.mono-font style="list-style-type: none" {
					@if req.path() != "/" {
						li {
							a href=".." { ".." }
						}
					} @else { br; }
					@if entries.is_empty() {
						em { "Empty" }
					} @else {
						@for (path, metadata, name) in entries.iter() {
							li {
								@let is_dir = metadata.is_dir();
								a.warn[is_dir]
									hx-boost=[boosted_dir(is_dir, &path)?]
									href={ (name) @if is_dir { "/" } }
									target=[(!is_dir).then_some("_blank")]
								{
									(if is_dir {
										const_icon!(FOLDER)
									} else {
										const_icon!(DOCUMENT)
									})
									" "
									(name)
								}
								span.float:right { ({
									let modified: DateTime<Utc> = metadata.modified()?.into();
									modified.with_nanosecond(0).unwrap()
								}) }
							}
						}
					}
				}
			}))
		}
	})
}
