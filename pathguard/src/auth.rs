use actix_web::{
    body::BoxBody,
    cookie::Cookie,
    http::{header::ContentType, StatusCode},
    FromRequest, HttpRequest, HttpResponse, ResponseError,
};
use awc::http::header::{TryIntoHeaderValue, CONTENT_TYPE};
use chrono::Utc;
use derive_more::{Display, From};
use diesel::{dsl::insert_into, prelude::*, r2d2::ConnectionManager};
use maud::{html, Markup, Render};
use r2d2::PooledConnection;
use std::{
    convert::Infallible,
    fmt::Debug,
    future::{self, ready, Ready},
    ops::{Deref, DerefMut},
};
use thiserror::Error;

use crate::{
    dashboard::login_form,
    database::{self, DatabaseError},
    models::{
        group::{Rule, DEFAULT_GROUP},
        user::{UserGroup, ADMIN_USERNAME},
        Activity, User,
    },
    templates::page,
    ARGS, DATABASE, LOGOUT_ROUTE,
};

pub struct MaybeSessionUserCookies(pub Option<SessionUserCookies>);

impl Deref for MaybeSessionUserCookies {
    type Target = Option<SessionUserCookies>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct SessionUserCookies {
    pub username: Box<str>,
    pub password: Box<str>,
}

#[derive(Error, Debug)]
pub enum UnauthorizedError {
    /// User is unauthorized and not logged in
    #[error("Unauthorized: not logged in")]
    NotLoggedIn { path: String },
    /// User is unauthorized and logged in
    #[error("Forbidden")]
    LoggedIn { username: String },
    /// User is unauthorized and bad credentials
    #[error("Unauthorized: invalid credentials")]
    BadLogin { path: String },
}

impl UnauthorizedError {
    fn not_logged_in(req: &HttpRequest) -> Self {
        Self::NotLoggedIn {
            path: req.path().to_string(),
        }
    }

    fn logged_in(user: User) -> Self {
        Self::LoggedIn {
            username: user.name,
        }
    }

    fn bad_login(req: &HttpRequest) -> Self {
        Self::BadLogin {
            path: req.path().to_string(),
        }
    }
}

impl ResponseError for UnauthorizedError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::NotLoggedIn { .. } | Self::BadLogin { .. } => StatusCode::UNAUTHORIZED,
            Self::LoggedIn { .. } => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        #[derive(Display, Debug)]
        #[display("{body}")]
        struct Error {
            status: StatusCode,
            body: String,
        }

        impl Error {
            fn new<T: ResponseError>(parent: &T) -> Self {
                Self {
                    status: parent.status_code(),
                    body: parent.to_string(),
                }
            }
        }

        impl ResponseError for Error {
            fn status_code(&self) -> StatusCode {
                self.status
            }
        }

        let mut res = Error::new(self).error_response();
        log_out(&mut res);
        res
    }
}

lazy_static::lazy_static! {
    pub static ref USERNAME_COOKIE: Cookie<'static> = {
        let mut c = Cookie::named("pathguard_username");
        c.set_path("/");
        c
    };
    pub static ref PASSWORD_COOKIE: Cookie<'static> = {
        let mut c = Cookie::named("pathguard_password");
        c.set_path("/");
        c
    };
}

pub fn log_out<T>(res: &mut HttpResponse<T>) {
    res.add_removal_cookie(&USERNAME_COOKIE).unwrap();
    res.add_removal_cookie(&PASSWORD_COOKIE).unwrap();
}

impl Render for UnauthorizedError {
    fn render(&self) -> Markup {
        match &self {
            UnauthorizedError::BadLogin { path, .. } => html! {
                h2 { "Log in" }
                p { "The username or password you last signed in with have been invalidated. Please sign in again." }
                (login_form(false, &path))
            },
            UnauthorizedError::NotLoggedIn { path, .. } => html! {
                h2 { "Log in" }
                (login_form(false, &path))
            },
            UnauthorizedError::LoggedIn { username, .. } => html! {
                p { "Hello, " strong { (username) } "!" }
                p {
                    "You're logged in correctly, but you don't have permission to access this page. "
                    "Try " a href={ (ARGS.dashboard) (LOGOUT_ROUTE) } { "logging out" } " and trying a different account, "
                    " or if you think this is a mistake, contact the administrator."
                }
            },
        }
    }
}

impl FromRequest for MaybeSessionUserCookies {
    type Error = Infallible;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        future::ready(Ok(Self((|| {
            let username_cookie = req.cookie(USERNAME_COOKIE.name())?;
            let password_cookie = req.cookie(PASSWORD_COOKIE.name())?;
            Some(SessionUserCookies {
                username: username_cookie.value().to_string().into_boxed_str(),
                password: password_cookie.value().to_string().into_boxed_str(),
            })
        })())))
    }
}

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("{0}")]
    Unauthorized(#[from] UnauthorizedError),
    #[error("{0}")]
    Database(#[from] DatabaseError),
}

impl Render for AuthorizationError {
    fn render(&self) -> Markup {
        html! {
            @match self {
                Self::Unauthorized(err) => (Render::render(&err)),
                _ => (self.to_string()),
            }
        }
    }
}

impl ResponseError for AuthorizationError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized(err) => err.status_code(),
            Self::Database(err) => err.status_code(),
        }
    }
}

pub fn user_rules(
    conn: &mut PooledConnection<ConnectionManager<SqliteConnection>>,
    user: Option<&User>,
) -> Result<Vec<Rule>, diesel::result::Error> {
    if let Some(user) = user {
        use crate::schema::{
            groups::dsl::{name as group_name, sort as group_sort, *},
            rules::dsl::{group as rule_group, sort as rule_sort, *},
            user_groups::dsl::group as user_group_group,
        };
        UserGroup::belonging_to(user)
            .inner_join(groups.on(group_name.eq(user_group_group)))
            .inner_join(rules.on(rule_group.eq(group_name)))
            .select(Rule::as_select())
            .order(group_sort)
            .then_order_by(rule_sort)
            .load(conn)
    } else {
        use crate::schema::rules::dsl;
        dsl::rules
            .filter(dsl::group.eq(DEFAULT_GROUP))
            .select(Rule::as_select())
            .load(conn)
    }
}

pub fn user_rules_allowed(rules: &[Rule], path: &str) -> bool {
    rules
        .iter()
        .filter_map(|rule| {
            rule.allowed
                .and_then(|allowed| path.starts_with(&rule.path).then_some(allowed))
        })
        .next_back()
        .unwrap_or_default()
}

fn allowed_and_log(req: &HttpRequest, user: Option<&User>) -> database::Result<bool> {
    if user.map(|user| user.is_admin()).unwrap_or_default() {
        return Ok(true);
    }
    let path = req.path();
    if path.starts_with(&*ARGS.dashboard) {
        return Ok(false);
    }
    // Get request timestamp before database ops
    let timestamp = Utc::now().naive_utc();
    DATABASE.run(|conn| {
        let allowed = user_rules_allowed(&user_rules(conn, user)?, path);
        {
            use crate::schema::activities::dsl::activities;
            insert_into(activities)
                .values(Activity {
                    user: user.map(|user| user.name.clone()),
                    timestamp,
                    path: req.path().to_string(),
                    allowed,
                    ..Activity::from_request(req)
                })
                .execute(conn)?;
        }
        Ok(allowed)
    })
}

/// Route requires users to be logged in, but protection rules are ignored and no activity is logged.
/// In almost all cases `Authorized` or `AuthorizedAdmin` should be used instead.
pub struct AuthorizedNoCheck(pub User);

impl FromRequest for AuthorizedNoCheck {
    type Error = AuthorizationError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        ready((|| {
            use AuthorizationError::*;
            let MaybeSessionUserCookies(Some(SessionUserCookies { username, password })) =
                MaybeSessionUserCookies::from_request(req, payload)
                    .into_inner()
                    .unwrap()
            else {
                return Err(Unauthorized(UnauthorizedError::not_logged_in(req)));
            };
            let user = match DATABASE.run(|conn| {
                use crate::schema::users::dsl::*;
                users
                    .select(User::as_select())
                    .filter(name.eq(&*username))
                    .get_result::<User>(conn)
                    .optional()
            })? {
                Some(user) => {
                    if *user.password == *password {
                        user
                    } else {
                        return Err(Unauthorized(UnauthorizedError::bad_login(req)));
                    }
                }
                None => return Err(Unauthorized(UnauthorizedError::not_logged_in(req))),
            };
            Ok(Self(user))
        })())
    }
}

/// Route requires valid user information but isn't protected and no activity is logged.
pub struct Unauthorized {
    pub user: Option<User>,
    pub fallback_err: UnauthorizedError,
}

impl FromRequest for Unauthorized {
    type Error = database::DatabaseError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        use AuthorizationError::*;
        ready((|| {
            Ok(
                match AuthorizedNoCheck::from_request(req, payload).into_inner() {
                    Ok(AuthorizedNoCheck(user)) => Self {
                        fallback_err: UnauthorizedError::LoggedIn {
                            username: user.name.clone(),
                        },
                        user: Some(user),
                    },
                    Err(Unauthorized(err)) => Self {
                        user: None,
                        fallback_err: err,
                    },
                    Err(Database(err)) => return Err(err),
                },
            )
        })())
    }
}

/// Route requires users to be logged in and protection rules are checked
pub struct Authorized(pub Option<User>);

impl FromRequest for Authorized {
    type Error = AuthorizationError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        ready((|| {
            use AuthorizationError::*;
            let (user, fallback_err) =
                match AuthorizedNoCheck::from_request(req, payload).into_inner() {
                    Ok(AuthorizedNoCheck(user)) => (Some(user), None),
                    Err(Unauthorized(err)) => (None, Some(err)),
                    Err(Database(err)) => return Err(Database(err)),
                };
            if allowed_and_log(req, user.as_ref())? {
                Ok(Self(user))
            } else {
                Err(Unauthorized(fallback_err.unwrap_or_else(|| {
                    UnauthorizedError::logged_in(user.unwrap())
                })))
            }
        })())
    }
}

/// Route requires user to be admin
pub struct AuthorizedAdmin;

impl FromRequest for AuthorizedAdmin {
    type Error = AuthorizationError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        ready((|| {
            use AuthorizationError::*;
            let user = Authorized::from_request(req, payload).into_inner()?.0;
            match user {
                Some(user) if user.name.as_str() == ADMIN_USERNAME => Ok(Self),
                Some(user) => Err(Unauthorized(UnauthorizedError::logged_in(user))),
                None => Err(Unauthorized(UnauthorizedError::not_logged_in(req))),
            }
        })())
    }
}

pub struct Fancy<T: FromRequest>(pub T);

#[derive(Display, Debug, From)]
pub struct FancyError<E: ResponseError + RenderError>(pub E);

impl<T, E> FromRequest for Fancy<T>
where
    T: FromRequest<Future = Ready<Result<T, E>>, Error = E>,
    E: ResponseError + RenderError + 'static,
{
    type Error = FancyError<T::Error>;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        ready(
            T::from_request(req, payload)
                .into_inner()
                .map(|ok| Self(ok))
                .map_err(|err| FancyError(err)),
        )
    }
}

impl<T: ResponseError + RenderError> Deref for FancyError<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: ResponseError + RenderError> DerefMut for FancyError<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub trait RenderError {
    fn render(&self) -> Markup;
}

impl<T> RenderError for T
where
    T: Render,
{
    fn render(&self) -> Markup {
        self.render()
    }
}

impl<T: ResponseError + RenderError> RenderError for FancyError<T> {
    fn render(&self) -> Markup {
        html! {
            h1 { (self.deref().status_code()) }
            p { (self.deref().render()) }
        }
    }
}

impl<T: ResponseError + RenderError> ResponseError for FancyError<T> {
    fn error_response(&self) -> HttpResponse {
        let mut res = self
            .deref()
            .error_response()
            .set_body(page(self.render()))
            .map_into_boxed_body();
        res.headers_mut()
            .insert(CONTENT_TYPE, ContentType::html().try_into_value().unwrap());
        res
    }
}
