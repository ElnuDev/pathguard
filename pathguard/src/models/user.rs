use std::{convert::Infallible, fmt::{Debug, Display}, fs, future::{self, Ready}, io, ops::Deref, path::PathBuf, sync::Mutex};
use actix_htmx::Htmx;
use actix_web::{FromRequest, HttpRequest, HttpResponse, HttpResponseBuilder, Responder, ResponseError, error::{ErrorUnauthorized, InternalError}, web};
use awc::{cookie::Cookie, http::StatusCode};
use clap::Arg;
use indexmap::IndexMap;
use maud::html;
use thiserror::Error;

use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};
use csv;

use crate::{ARGS, Args, LOGOUT_ROUTE, dashboard::login_form, error::Error, models::{State, group::{self, DEFAULT_GROUP}, user}, templates::page};

pub const ADMIN_USERNAME: &str = "admin";
pub const ADMIN_DEFAULT_PASSWORD: &str = "password";

#[derive(Debug, Deserialize)]
pub struct User {
    pub password: SecretString,
    #[serde(deserialize_with = "deserialize_groups")]
    pub groups: Vec<Box<str>>,
}

impl User {
    pub const GROUPS_SEPERATOR: &str = "|";

    pub fn default_admin() -> Self {
        Self::new(ADMIN_DEFAULT_PASSWORD)
    }

    pub fn new(password: &str) -> Self {
        Self {
            password: SecretString::new(password.to_string().into_boxed_str()),
            groups: Vec::new(),
        }
    }
}

impl AsRef<User> for User {
    fn as_ref(&self) -> &User {
        &self
    }
}

#[derive(Deserialize)]
pub struct UserData<N: AsRef<str>, U: AsRef<User>> {
    pub name: N,
    #[serde(flatten)]
    pub user: U,
}

pub type OwnedUserData = UserData<Box<str>, User>;

fn deserialize_groups<'de, D>(deserializer: D) -> Result<Vec<Box<str>>, D::Error>
where
    D: Deserializer<'de>
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Ok(s
        .split(User::GROUPS_SEPERATOR)
        .map(|str| str.to_owned().into_boxed_str())
        .collect())
}

impl<N, U> Serialize for UserData<N, U>
where N: AsRef<str>, U: AsRef<User>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer {
        let mut s = serializer.serialize_struct("user", 3)?;
        s.serialize_field("name", self.name.as_ref())?;
        s.serialize_field("password", self.user.as_ref().password.expose_secret())?;
        s.serialize_field("groups", &self.user.as_ref().groups.join(User::GROUPS_SEPERATOR))?;
        s.end()
    }
}

pub struct SessionUser(pub Option<SessionUserCookies>);

impl Deref for SessionUser {
    type Target = Option<SessionUserCookies>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct SessionUserCookies {
    pub username: Box<str>,
    pub password: Box<str>,
}

pub const USERNAME_COOKIE: &str = "pathguard_username";
pub const PASSWORD_COOKIE: &str = "pathguard_password";

pub type Authorization = std::result::Result<(), UnauthorizedError>;

#[derive(Debug)]
pub enum UnauthorizedError {
    /// User is unauthorized and not logged in
    NotLoggedIn,
    /// User is unauthorized and logged in
    LoggedIn,
    /// User is unauthorized and bad credentials
    BadLogin,
}

impl ResponseError for UnauthorizedError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::NotLoggedIn | Self::BadLogin => StatusCode::UNAUTHORIZED,
            Self::LoggedIn => StatusCode::FORBIDDEN,
        }
    }
}

impl UnauthorizedError {
    /// For pages
    pub fn fancy_response(&self, req: &HttpRequest, session_user: &SessionUser) -> HttpResponse {
        let mut res = HttpResponse::build(self.status_code())
        .body(page(match self {
            Self::BadLogin => html! {
                p { "The username or password you last signed in with have been invalidated. Please sign in again." }
                (login_form(false, req.path()))
            },
            Self::NotLoggedIn => html! {
                (login_form(false, req.path()))
            },
            Self::LoggedIn => html! {
                span.float:right {
                    a href={ (ARGS.dashboard) (LOGOUT_ROUTE) } { "Log out" }
                }
                h1 { "403 Forbidden" }
            },
        }));
        if let Self::BadLogin = self {
            session_user.logout(req, &mut res);
        }
        res
    }
}

impl Display for UnauthorizedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::NotLoggedIn => "Unauthorized: not logged in",
            Self::LoggedIn => "Unauthorized",
            Self::BadLogin => "Unauthorized: invalid credentials"
        })
    }
}

pub trait UnauthorizedResponse {
    fn basic(&self) -> Option<HttpResponse>;
    fn fancy(&self, req: &HttpRequest, session_user: &SessionUser) -> Option<HttpResponse>;
}

impl UnauthorizedResponse for crate::error::Result<Authorization> {
    fn basic(&self) -> Option<HttpResponse> {
        Some(match self {
            Ok(Ok(())) => return None,
            Ok(Err(unauthorized)) => unauthorized.error_response(),
            Err(err) => ErrorUnauthorized(err.to_string()).error_response(),
        })
    }

    fn fancy(&self, req: &HttpRequest, session_user: &SessionUser) -> Option<HttpResponse> {
        Some({
            let mut res = match self {
                Ok(Ok(())) => return None,
                Ok(Err(unauthorized)) => unauthorized.fancy_response(req, session_user),
                Err(err) => err.error_response(),
            };
            if req.headers().contains_key("hx-boosted") {
                *res.status_mut() = StatusCode::OK;
            }
            res
        })
    }
}

impl SessionUser {
    pub fn authorization_admin_fancy(&self, state: &State, req: &HttpRequest) -> Option<HttpResponse> {
        self.authorization_admin(state).fancy(req, self)
    }

    pub fn authorization_admin_basic(&self, state: &State) -> Option<HttpResponse> {
        self.authorization_admin(state).basic()
    }

    pub fn authorization_fancy(&self, state: &State, req: &HttpRequest, args: &Args) -> Option<HttpResponse> {
        self.authorization(req, state).fancy(req, self)
    }

    pub fn authorization_basic(&self, state: &State, req: &HttpRequest) -> Option<HttpResponse> {
        self.authorization(req, state).basic()
    }

    fn authorization_admin(&self, state: &State) -> crate::error::Result<Authorization> {
        use UnauthorizedError::*;
        let Some(cookies) = &self.0 else {
            return Ok(Err(NotLoggedIn));
        };
        match state.users
            .read()
            .or(Err(Error::InternalServer))?
            .get(&cookies.username)
            .map(|user| user.password.expose_secret() == &*cookies.password)
        {
            Some(true) if &*cookies.username == ADMIN_USERNAME => Ok(Ok(())),
            Some(true) => Ok(Err(LoggedIn)),
            _ => Ok(Err(BadLogin)),
        }
    }

    fn authorization(&self, req: &HttpRequest, state: &State) -> crate::error::Result<Authorization> {
        use UnauthorizedError::*;
        const OK: crate::error::Result<Authorization> = Ok(Authorization::Ok(()));
        let groups = state.groups
            .read()
            .or(Err(Error::InternalServer))?;
        // If resource has public access, session user has access regardless
        if groups
                .get(DEFAULT_GROUP)
                .map(|group| group
                    .read()
                    .map(|group| group
                        .allowed(req.path())
                        .unwrap_or_default())
                    .ok())
                .flatten()
                .ok_or(Error::InternalServer)? {
            return OK;
        }
        let Some(cookies) = &self.0 else {
            return OK;
        };
        let users = &*state.users.read().or(Err(Error::InternalServer))?;
        let Some(user) = users
            .get(&cookies.username)
            .filter(|true_user| true_user.password.expose_secret() == &*cookies.password) else {
                return Ok(Err(BadLogin));
            };
        let mut allowed = false;
        for group_name in &user.groups {
            let Some(group_lock) = groups.get(group_name.deref()) else {
                continue;
            };
            let group = group_lock.read().or(Err(Error::InternalServer))?;
            if let Some(group_allowed) = group.allowed(req.path()) {
                allowed = group_allowed;
            }
        }
        if allowed { OK } else { Ok(Err(LoggedIn)) }
    }

    pub fn logout<T>(&self, req: &HttpRequest, res: &mut HttpResponse<T>) {
        if let Some(username) = req.cookie(USERNAME_COOKIE) {
            res.add_removal_cookie(&username).unwrap();
        }
        if let Some(password) = req.cookie(PASSWORD_COOKIE) {
            res.add_removal_cookie(&password).unwrap();
        }
    }
}

impl FromRequest for SessionUser {
    type Error = Infallible;

    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        future::ready(Ok(Self((|| {
            let Some(username_cookie) = req.cookie(USERNAME_COOKIE) else {
                return None;
            };
            let Some(password_cookie) = req.cookie(PASSWORD_COOKIE) else {
                return None;
            };
            Some(SessionUserCookies {
                username: username_cookie.value().to_string().into_boxed_str(),
                password: password_cookie.value().to_string().into_boxed_str(),
            })
        })())))
    }
}