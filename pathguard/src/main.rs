#![feature(rwlock_downgrade)]

mod models;
mod proxy;
mod templates;
mod dashboard;
mod error;

use std::{env, fmt::format, path::PathBuf};

use actix_htmx::HtmxMiddleware;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{App, HttpResponse, HttpServer, cookie::Key, guard::Head, http::header::{CONTENT_TYPE, HeaderValue}, middleware::{self, ErrorHandlers}, mime::TEXT_HTML_UTF_8, web};
use awc::http::StatusCode;
use maud::html;
use models::*;

use clap::{Parser, Subcommand};

use crate::{dashboard::{dashboard, delete_group, logout, post_group, post_login}, templates::page};

#[derive(Subcommand, Debug, Clone)]
pub enum Mode {
    Proxy(ProxyMode),
    Files(FilesMode),
}

#[derive(Parser, Debug, Clone)]
pub struct ProxyMode {
    port: u16,
}

#[derive(Parser, Debug, Clone)]
pub struct FilesMode {
    root: PathBuf,
}

#[derive(Parser, Debug, Clone)]
#[command(author, version)]
pub struct Args {
    #[command(subcommand)]
    pub mode: Mode,
    #[arg(short, long = "users", default_value = "users.csv")]
    pub users_file: PathBuf,
    #[arg(short, long = "groups", default_value = "groups")]
    pub groups_dir: PathBuf,
    #[arg(short, long, default_value_t = 8000)]
    pub port: u16,
    #[arg(short, long, default_value = "/pathguard")]
    pub dashboard: Box<str>,
}

pub const LOGIN_ROUTE: &str = "/login";
pub const LOGOUT_ROUTE: &str = "/logout";
pub const GROUPS_ROUTE: &str = "/groups";

pub const HTMX: &str = "/pathguard_htmx.min.js";
pub const MISSING_CSS: &str = "/pathguard_missing.css";
pub const OVERRIDE_CSS: &str = "/pathguard_override.css";

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    unsafe { env::set_var("RUST_LOG", "actix_web=debug,pathguard") };
    env_logger::init();
    let args = Args::parse();
    let port = args.port;
    // If we construct this inside of HttpServer::new
    // then it will instantiate multiple times leading to state divergence
    let state = web::Data::new(State::load(&args).unwrap());
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .app_data(web::Data::new(args.clone()))
            .wrap(middleware::Logger::default())
            .wrap(middleware::NormalizePath::trim())
            .wrap(middleware::DefaultHeaders::new().add((CONTENT_TYPE, TEXT_HTML_UTF_8)))
            .wrap(SessionMiddleware::builder(
                CookieSessionStore::default(),
                Key::from(&[0; 64]),
            ).cookie_secure(false).build())
            .wrap(HtmxMiddleware)
            .service(web::resource(&*args.dashboard).get(dashboard))
            .service(web::resource(args.dashboard.to_string() + LOGIN_ROUTE).post(post_login))
            .service(web::resource(args.dashboard.to_string() + LOGOUT_ROUTE).get(logout))
            .service(web::resource(args.dashboard.to_string() + GROUPS_ROUTE)
                .post(post_group))
            .service(web::resource(args.dashboard.to_string() + GROUPS_ROUTE + "/{group}")
                .delete(delete_group))
            .service(web::resource(args.dashboard.to_string() + "/{tail:.*}").get(async |args: web::Data<Args>|
                HttpResponse::NotFound().body(page(html! {
                    h1 { "404 Not Found" }
                    p { "Couldn't find that page. Would you like to return to the " a href=(args.dashboard) { "dashboard" } "?" }
                }))
            ))
            .service(web::resource(HTMX).get(async || {
                let mut res = HttpResponse::Ok().body(include_str!("htmx.min.js"));
                res.headers_mut().append(CONTENT_TYPE, HeaderValue::from_str("application/javascript").unwrap());
                res
            }))
            .service(web::resource(MISSING_CSS).get(async || {
                let mut res = HttpResponse::Ok().body(include_str!("missing.css"));
                res.headers_mut().append(CONTENT_TYPE, HeaderValue::from_str("text/css").unwrap());
                res
            }))
            .service(web::resource(OVERRIDE_CSS).get(async || {
                let mut res = HttpResponse::Ok().body(include_str!("override.css"));
                res.headers_mut().append(CONTENT_TYPE, HeaderValue::from_str("text/css").unwrap());
                res
            }))
            .default_service(web::to(proxy::proxy))
    })
        .disable_signals()
        .bind(("127.0.0.1", port))?
        .run()
        .await?;
    Ok(())
}