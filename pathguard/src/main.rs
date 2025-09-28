#![feature(rwlock_downgrade)]
#![feature(impl_trait_in_assoc_type)]

mod auth;
mod dashboard;
mod files;
mod models;
mod proxy;
mod templates;

mod database;
mod schema;

use std::{env, fs, path::PathBuf};

use actix_htmx::{Htmx, HtmxMiddleware};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::Key,
    http::header::{HeaderValue, CONTENT_TYPE},
    middleware::{self},
    mime::TEXT_HTML_UTF_8,
    web, App, HttpRequest, HttpResponse, HttpServer,
};
use maud::html;

use clap::{Parser, Subcommand};
use passwords::PasswordGenerator;

use static_web_minify::minify_js_file;
use const_css_minify::minify as minify_css_file;

use crate::{
    auth::{Authorized, Fancy, Unauthorized},
    dashboard::*,
    database::Database,
    templates::page,
};

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
    #[arg(long = "db", default_value = "database.db")]
    pub database: Box<str>,
    #[arg(short, long, default_value = "session.key")]
    pub key: Box<str>,
    #[arg(short, long, default_value_t = 8000)]
    pub port: u16,
    #[arg(short, long, default_value = "/pathguard")]
    pub dashboard: Box<str>,
    #[arg(short, long, default_value_t = 60.0)]
    pub min_password_strength: f64,
    #[command(subcommand)]
    pub mode: Mode,
}

pub const PASSWORD_GENERATOR: PasswordGenerator = PasswordGenerator {
    length: 10,
    ..PasswordGenerator::new()
};

lazy_static::lazy_static! {
    static ref ARGS: Args = {
        let mut args = Args::parse();
        if let Mode::Files(FilesMode { root }) = &mut args.mode {
            // Ugly paths like . or .. can cause issues when checking for
            // FilesError::OutOfScope
            *root = root.canonicalize().unwrap();
        }
        args
    };
    pub static ref DATABASE: Database = Database::new(&ARGS.database).unwrap();
}

pub const LOGIN_ROUTE: &str = "/login";
pub const LOGOUT_ROUTE: &str = "/logout";
pub const GROUPS_ROUTE: &str = "/groups";
pub const USERS_ROUTE: &str = "/users";
pub const ACTIVITY_ROUTE: &str = "/activity";

pub const HTMX: &str = "/pathguard_htmx.min.js";
pub const SCRIPT: &str = "/pathguard_script.js";
pub const MISSING_CSS: &str = "/pathguard_missing.css";
pub const OVERRIDE_CSS: &str = "/pathguard_override.css";

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    unsafe { env::set_var("RUST_LOG", "actix_web=debug,pathguard") };
    env_logger::init();
    // If we construct this inside of HttpServer::new
    // then it will instantiate multiple times leading to state divergence
    let key = if fs::exists(&*ARGS.key)? {
        Key::from(&fs::read(&*ARGS.key)?)
    } else {
        let new = Key::generate();
        fs::write(&*ARGS.key, new.master())?;
        new
    };
    HttpServer::new(move || {
        let app = App::new()
            .wrap(middleware::Logger::default())
            .wrap(middleware::DefaultHeaders::new().add((CONTENT_TYPE, TEXT_HTML_UTF_8)))
            .wrap({
                let mut builder = SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
                    .cookie_name("pathguard_id".to_owned());
                #[cfg(debug_assertions)]
                {
                    builder = builder.cookie_secure(false);
                }
                builder.build()
            })
            .wrap(HtmxMiddleware)
            .service(web::resource(&*ARGS.dashboard).get(dashboard))
            .service(web::resource(ARGS.dashboard.to_string() + ACTIVITY_ROUTE)
                .get(dashboard_activity))
            .service(web::resource(ARGS.dashboard.to_string() + LOGIN_ROUTE)
                .post(post_login))
            .service(web::resource(ARGS.dashboard.to_string() + LOGOUT_ROUTE)
                .get(logout))
            .service(web::resource(ARGS.dashboard.to_string() + GROUPS_ROUTE)
                .get(get_groups)
                .post(post_group))
            .service(web::resource(ARGS.dashboard.to_string() + GROUPS_ROUTE + "/{group}")
                .post(post_rule)
                .delete(delete_group))
            .service(web::resource(ARGS.dashboard.to_string() + GROUPS_ROUTE + "/{group}/up")
                .post(post_group_up))
            .service(web::resource(ARGS.dashboard.to_string() + GROUPS_ROUTE + "/{group}/down")
                .post(post_group_down))
            .service(web::resource(ARGS.dashboard.to_string() + GROUPS_ROUTE + "/{group}/rules/{rule}")
                .patch(patch_rule)
                .delete(delete_rule))
            .service(web::resource(ARGS.dashboard.to_string() + GROUPS_ROUTE + "/{group}/rules/{rule}/up")
                .post(post_rule_up))
            .service(web::resource(ARGS.dashboard.to_string() + GROUPS_ROUTE + "/{group}/rules/{rule}/down")
                .post(post_rule_down))
            .service(web::resource(ARGS.dashboard.to_string() + USERS_ROUTE)
                .post(post_user))
            .service(web::resource(ARGS.dashboard.to_string() + USERS_ROUTE + "/{user}")
                .get(get_user)
                .patch(patch_user)
                .delete(delete_user))
            .service(web::resource(ARGS.dashboard.to_string() + USERS_ROUTE + "/{user}/edit")
                .get(get_user_edit))
            .service(web::resource(ARGS.dashboard.to_string() + USERS_ROUTE + "/{user}/groups")
                .get(get_user_groups))
            .service(web::resource(ARGS.dashboard.to_string() + "/{tail:.*}").get(async ||
                HttpResponse::NotFound().body(page(html! {
                    h1 { "404 Not Found" }
                    p { "Couldn't find that page. Would you like to return to the " a href=(ARGS.dashboard) { "dashboard" } "?" }
                }))
            ))
            .service(web::resource(HTMX).get(async || {
                let mut res = HttpResponse::Ok().body(include_str!("htmx.min.js"));
                res.headers_mut().append(CONTENT_TYPE, HeaderValue::from_str("application/javascript").unwrap());
                res
            }))
            .service(web::resource(SCRIPT).get(async || {
                let mut res = HttpResponse::Ok().body(minify_js_file!("pathguard/src/script.js"));
                res.headers_mut().append(CONTENT_TYPE, HeaderValue::from_str("application/javascript").unwrap());
                res
            }))
            .service(web::resource(MISSING_CSS).get(async || {
                let mut res = HttpResponse::Ok().body(include_str!("missing.css"));
                res.headers_mut().append(CONTENT_TYPE, HeaderValue::from_str("text/css").unwrap());
                res
            }))
            .service(web::resource(OVERRIDE_CSS).get(async || {
                let mut res = HttpResponse::Ok().body(minify_css_file!("pathguard/src/override.css"));
                res.headers_mut().append(CONTENT_TYPE, HeaderValue::from_str("text/css").unwrap());
                res
            }));
        match &ARGS.mode {
            Mode::Proxy(ProxyMode { port }) => app.default_service(
                web::to(async |auth: Fancy<Authorized>, req: HttpRequest, bytes: web::Bytes| proxy::proxy(auth, req, bytes, *port).await)
            ),
            Mode::Files(FilesMode { root }) => app.default_service(
                web::to(async |auth: Fancy<Unauthorized>, req: HttpRequest, htmx: Htmx| files::files(auth, req, htmx, root).await)
            ),
        }
    })
        .disable_signals()
        .bind(("127.0.0.1", ARGS.port))?
        .run()
        .await?;
    Ok(())
}
