use std::{
    borrow::Cow, convert::Infallible, fmt::{Debug, Display}, future::Ready, ops::Deref, sync::RwLock
};

use crate::{
    ARGS, GROUPS_ROUTE, LOGIN_ROUTE, LOGOUT_ROUTE, PASSWORD_GENERATOR, USERS_ROUTE, error::{BasicError, Error}, models::{
        Group, State, User, group::{self, DEFAULT_GROUP, Rule}, state::{AddGroupError, UpdateGroupError, UpdateStateError}, user::{
            ADMIN_USERNAME, PASSWORD_COOKIE, SessionUser, USERNAME_COOKIE, UserDisplayMode, UserValidationError
        }
    }, templates::{const_icon_button, fancy_page}
};
use actix_htmx::{Htmx, SwapType};
use actix_web::{
    FromRequest, HttpRequest, HttpResponse, Responder, ResponseError, cookie::Cookie, error::{ErrorBadRequest, ErrorNotFound, InternalError}, http::header::{HeaderName, HeaderValue, REFERER}, web::{self, Redirect}
};
use awc::http::StatusCode;
use indexmap::{IndexMap, IndexSet};
use maud::{html, Markup, PreEscaped};
use qstring::{self};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer};
use thiserror::Error;
use webformd::{WebFomData, WebformDeserialize};

const TRASH_: &str = "trash";
pub const TRASH: &str = TRASH_;

const PLUS_: &str = "plus";
pub const PLUS: &str = PLUS_;

const PENCIL_SQUARE_: &str = "pencil-square";
pub const PENCIL_SQUARE: &str = PENCIL_SQUARE_;

const CHECK_: &str = "check";
pub const CHECK: &str = CHECK_;

const X_MARK_: &str = "x-mark";
pub const X_MARK: &str = X_MARK_;

pub async fn dashboard(
    req: HttpRequest,
    session_user: SessionUser,
    state: web::Data<State>,
) -> Result<HttpResponse, Error> {
    if let Some(res) = session_user.authorization_admin_fancy(&state, &req) {
        return Ok(res);
    }

    Ok(HttpResponse::Ok().body(fancy_page(html! {
        header.navbar {
            nav {
                ul role="list" {
                    li { a.allcaps href="#" { "pathguard" } }
                    li { a href="#groups" { "Groups" } }
                    li { a href="#users" { "Users" } }
                }
            }
            nav style="margin-left: auto" {
                "Hello, " strong { (ADMIN_USERNAME) } " "
                a href={(ARGS.dashboard) (LOGOUT_ROUTE)} { "Log out" }
            }
        }
    },html! {
        svg xmlns="http://www.w3.org/2000/svg" style="display: none" {
            symbol #(TRASH_) fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" {
                (PreEscaped(r#"<path stroke-linecap="round" stroke-linejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />"#))
            }
            symbol #(PLUS_) fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" {
                (PreEscaped(r#"<path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15" />"#))
            }
            symbol #(PENCIL_SQUARE_) fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" {
                (PreEscaped(r#"<path stroke-linecap="round" stroke-linejoin="round" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0 1 15.75 21H5.25A2.25 2.25 0 0 1 3 18.75V8.25A2.25 2.25 0 0 1 5.25 6H10" />"#))
            }
            symbol #(CHECK_) fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" {
                (PreEscaped(r#"<path stroke-linecap="round" stroke-linejoin="round" d="m4.5 12.75 6 6 9-13.5" />"#))
            }
            symbol #(X_MARK_) fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" {
                (PreEscaped(r#"<path stroke-linecap="round" stroke-linejoin="round" d="M6 18 18 6M6 6l12 12" />"#))
            }
        }
        h1 { "Dashboard" }
        h2 #groups { "Groups" }
        @let groups = state.groups.read().or(Err(Error::InternalServer))?;
        .table.rows {
            @for (group_name, group) in groups.iter() {
                @let group = group.read().or(Err(Error::InternalServer))?;
                (group.display(group_name))
            }
            form hx-post={ (ARGS.dashboard) (GROUPS_ROUTE) } hx-swap="beforebegin" hx-on::after-request="this.querySelector('input').value = ''" {
                div { (const_icon_button!(PLUS, "", "ok")) }
                input type="text" name="name" required;
            }
        }
        h2 #users { "Users" }
        p { label style="user-select: none" { "Show passwords? " input #show-passwords type="checkbox" autocomplete="off"; } }
        .table.rows {
            @for (user_name, user) in state.users.read().or(Err(Error::InternalServer))?.iter() {
                (user.display(user_name, UserDisplayMode::Normal))
            }
            (new_user_form_ok(false, &groups))
        }
    })))
}

fn new_user_form_ok(autofocus: bool, groups: &IndexMap<String, RwLock<Group>>) -> Markup {
    new_user_form(autofocus, Result::<&IndexMap<String, RwLock<Group>>, Infallible>::Ok(groups))
}

fn new_user_form<E: Display>(autofocus: bool, groups: Result<impl Deref<Target = IndexMap<String, RwLock<Group>>>, E>) -> Markup {
    html! {
        form
            autocomplete="off"
            hx-post={ (ARGS.dashboard) (USERS_ROUTE) }
            hx-swap="outerHTML"
        {
            div { (const_icon_button!(PLUS, "", "ok")) }
            div {
                .flex-row.align-items:center {
                    div { input type="text" name="name" placeholder="username" required autofocus[autofocus]; }
                    div { input type="text" name="password" placeholder="password" value=[PASSWORD_GENERATOR.generate_one().ok()] required; }
                    div {
                        details.inline {
                            summary { "Groups" }
                            (groups_select(groups, None))
                        }
                    }
                }
            }
        }
    }
}

pub async fn get_groups(state: web::Data<State>, session_user: SessionUser) -> Result<HttpResponse, BasicError> {
    if let Some(res) = session_user.authorization_admin_basic(&state) {
        return Ok(res);
    }
    Ok(HttpResponse::Ok().body(groups_select(state.groups.read(), None).0))
}

pub async fn get_user_groups(
    state: web::Data<State>,
    path: web::Path<String>,
    session_user: SessionUser
) -> Result<HttpResponse, Error> {
    if let Some(res) = session_user.authorization_admin_basic(&state) {
        return Ok(res);
    }
    let user_name = path.into_inner();
    let lock = state.users.read().or(Err(Error::InternalServer))?;
    let Some(user) = lock.get(&*user_name) else {
        return Ok(HttpResponse::NotFound().finish());
    };
    Ok(HttpResponse::Ok().body(user_groups(&user_name, user).0))
}

pub fn user_groups(name: &str, user: &User) -> Markup {
    html! {
        dd hx-trigger="groupsDeleted from:body" hx-swap="outerHTML" hx-get={ (ARGS.dashboard) (USERS_ROUTE) "/" (name) "/groups" } {
            @if user.groups.is_empty() { em { "None" } } @else {
                @for (i, group_name) in user.groups.iter().enumerate() {
                    @if i != 0 { ", " }
                    a href={ "#" (Group::id(group_name)) } { (group_name)};
                }
            }
        }
    }
}

pub fn groups_select_ok(groups: &IndexMap<String, RwLock<Group>>, user: Option<&User>) -> Markup {
    groups_select(Result::<&IndexMap<String, RwLock<Group>>, Infallible>::Ok(groups), user)
}

pub fn groups_select<E: Display>(groups: Result<impl Deref<Target = IndexMap<String, RwLock<Group>>>, E>, user: Option<&User>) -> Markup {
    match groups {
        Ok(groups) => html! {
            select hx-trigger="groups from:body" hx-get={ (ARGS.dashboard) (GROUPS_ROUTE) } name="groups" multiple {
                @for group_name in groups.keys() {
                    @if group_name != DEFAULT_GROUP {
                        option
                            value=(group_name)
                            selected[user
                                .map(|user| user.groups.contains(group_name.deref()))
                                .unwrap_or_default()]
                        { (group_name) }
                    }
                }
            }
        },
        Err(err) => {
            log::error!("{err}");
            html! {
                div hx-trigger="groups from:body" {
                    "Something went wrong fetching group list."
                }
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum AddUserError {
    #[error("{0}")]
    UpdateState(#[from] UpdateStateError),
    #[error("That user already exists")]
    AlreadyExists,
    #[error("{0}")]
    Validation(#[from] UserValidationError),
}

impl ResponseError for AddUserError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UpdateState(err) => err.status_code(),
            Self::AlreadyExists => StatusCode::CONFLICT,
            Self::Validation(err) => err.status_code(),
        }
    }
}

// webformd can't deserialize Box<str> or IndexSet<Box<str>> directly
// TODO: maybe open a PR?
#[derive(WebformDeserialize)]
pub struct UserFormRaw {
    password: String,
    groups: Vec<String>,
}

pub struct UserFormParsed {
    password: SecretString,
    groups: IndexSet<Box<str>>,
}

impl Into<UserFormParsed> for UserFormRaw {
    fn into(self) -> UserFormParsed {
        UserFormParsed {
            password: SecretString::new(self.password.into_boxed_str()),
            groups: IndexSet::from_iter(self.groups.into_iter().map(|str| str.into_boxed_str())),
        }
    }
}

impl Into<User> for UserFormParsed {
    fn into(self) -> User {
        User::new(self.password, self.groups)
    }
}

impl Into<User> for UserFormRaw {
    fn into(self) -> User {
        let parsed: UserFormParsed = self.into();
        parsed.into()
    }
}

pub async fn post_user(
    state: web::Data<State>,
    htmx: Htmx,
    web::Form(form): web::Form<Vec<(String, String)>>,
    session_user: SessionUser,
) -> Result<HttpResponse, AddUserError> {
    use AddUserError::*;
    if let Some(res) = session_user.authorization_admin_basic(&state) {
        return Ok(res);
    }
    let user: User = match UserFormRaw::deserialize(&form) {
        Ok(form) => form.into(),
        Err(err) => return Ok(ErrorBadRequest(err).error_response()),
    };
    let Some(name) = form
        .into_iter()
        .filter(|(key, _value)| key.as_str() == "name")
        .map(|(_key, value)| value.into_boxed_str())
        .next() else {
            return Ok(ErrorBadRequest("missing username field").error_response());
        };
    state.update_users(|users| {
        if users.contains_key(&name) {
            return Err(AlreadyExists);
        }
        user.validate(&*state.groups.read().or(Err(UpdateState(UpdateStateError::Poison)))?)?;
        let mut res = HttpResponse::Ok();
        let res = if htmx.is_htmx {
            res.body(html! {
                (user.display(&name, UserDisplayMode::Normal))
                (new_user_form(true, state.groups.read()))
            }.0)
        } else {
            res.finish()
        };
        users.insert(name, user);
        Ok(res)
    })?
}

pub fn get_user_generic(edit: bool) -> impl AsyncFn(web::Data<State>, web::Path<String>, SessionUser) -> Result<HttpResponse, BasicError> {
    async move |
        state: web::Data<State>,
        path: web::Path<String>,
        session_user: SessionUser,
    | -> Result<HttpResponse, BasicError> {
        if let Some(res) = session_user.authorization_admin_basic(&state) {
            return Ok(res);
        }
        let name = path.into_inner();
        let lock = state.users.read().or(Err(Error::InternalServer))?;
        let Some(user) = lock.get(&*name)  else {
            return Ok(ErrorNotFound("That user doesn't exist").error_response());
        };
        Ok(HttpResponse::Ok().body(user.display_partial(&name, if edit {
            UserDisplayMode::Edit { state: &state }
        } else {
            UserDisplayMode::Normal
        }).0))
    }
}

pub async fn get_user(
    state: web::Data<State>,
    path: web::Path<String>,
    session_user: SessionUser,
) -> Result<HttpResponse, BasicError> {
    get_user_generic(false)(state, path, session_user).await
}

pub async fn get_user_edit(
    state: web::Data<State>,
    path: web::Path<String>,
    session_user: SessionUser,
) -> Result<HttpResponse, BasicError> {
    get_user_generic(true)(state, path, session_user).await
}

pub async fn patch_user(
    state: web::Data<State>,
    htmx: Htmx,
    web::Form(form): web::Form<Vec<(String, String)>>,
    path: web::Path<String>,
    session_user: SessionUser,
) -> Result<HttpResponse, UpdateStateError> {
    if let Some(res) = session_user.authorization_admin_basic(&state) {
        return Ok(res);
    }
    let name = path.into_inner();
    let UserFormParsed { password, groups } = match UserFormRaw::deserialize(&form) {
        Ok(form) => form.into(),
        Err(err) => return Ok(ErrorBadRequest(err).error_response()),
    };
    state.update_users(|users| {
        let Some(user) = users.get_mut(&*name) else {
            return ErrorNotFound("that user doesn't exist").error_response();
        };
        user.password = password;
        user.groups = groups;
        let mut res = HttpResponse::Ok();
        if htmx.is_htmx {
            res.body(user.display_partial(&name, UserDisplayMode::Normal).0)
        } else {
            res.finish()
        }
    })
}

pub async fn delete_user(
    state: web::Data<State>,
    path: web::Path<String>,
    session_user: SessionUser,
) -> Result<HttpResponse, UpdateStateError> {
    if let Some(res) = session_user.authorization_admin_basic(&state) {
        return Ok(res);
    }
    let name = path.into_inner();
    if state.update_users(|users| users.shift_remove(&*name).is_none())? {
        return Ok(ErrorNotFound("that user doesn't exist").error_response());
    }
    Ok(HttpResponse::Ok().finish())
}

#[derive(Deserialize)]
pub struct NewRule {
    name: String,
}

#[derive(Error, Debug)]
pub enum AddRuleError {
    #[error("{0}")]
    UpdateGroup(#[from] UpdateGroupError),
    #[error("That rule already exists")]
    AlreadyExists,
}

impl ResponseError for AddRuleError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UpdateGroup(err) => err.status_code(),
            Self::AlreadyExists => StatusCode::CONFLICT,
        }
    }
}

pub async fn post_rule(
    state: web::Data<State>,
    path: web::Path<String>,
    htmx: Htmx,
    web::Form(NewRule { name }): web::Form<NewRule>,
    session_user: SessionUser,
) -> Result<HttpResponse, AddRuleError> {
    if let Some(res) = session_user.authorization_admin_basic(&state) {
        return Ok(res);
    }
    let group_name = path.into_inner();
    let body = htmx.is_htmx
        .then(|| Group::display_rule(&group_name, &name, &Default::default()).0);
    state.update_group(&group_name, |group| {
        if group.contains_key(&name) {
            return Err(AddRuleError::AlreadyExists);
        }
        group.insert(name, None);
        Ok(())
    })??;
    Ok({
        let mut res = HttpResponse::Ok();
        if let Some(body) = body {
            res.body(body)
        } else {
            res.finish()
        }
    })
}

#[derive(Error, Debug)]
pub enum UpdateRuleError{
    #[error("{0}")]
    UpdateGroup(#[from] UpdateGroupError),
    #[error("That rule doesn't exist")]
    RuleDoesNotExist,
}

impl ResponseError for UpdateRuleError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UpdateGroup(err) => err.status_code(),
            Self::RuleDoesNotExist => StatusCode::NOT_FOUND,
        }
    }
}

pub async fn delete_rule(
    state: web::Data<State>,
    path: web::Path<(String, String)>,
    session_user: SessionUser,
) -> Result<HttpResponse, UpdateRuleError> {
    if let Some(res) = session_user.authorization_admin_basic(&state) {
        return Ok(res);
    }

    let (group_name, path) = path.into_inner();
    let path = urlencoding::decode(&path).unwrap_or(Cow::Borrowed(&path));

    state.update_group(&group_name, |group| {
        if group.shift_remove(&*path).is_none() {
            return Err(UpdateRuleError::RuleDoesNotExist);
        };
        Ok(())
    })??;
    Ok(HttpResponse::Ok().finish())
}

#[derive(Deserialize)]
pub struct PatchRule {
    #[serde(deserialize_with = "deserialize_rule")]
    rule: Rule,
}

fn deserialize_rule<'de, D>(deserializer: D) -> Result<Rule, D::Error>
where D: Deserializer<'de> {
    Ok(match String::deserialize(deserializer)?.as_str() {
        group::RULE_OFF => Some(false),
        group::RULE_NA => None,
        group::RULE_ON => Some(true),
        _ => return Err(serde::de::Error::custom("rule must be off, na, or no")),
    })
}

pub async fn patch_rule(
    state: web::Data<State>,
    path: web::Path<(String, String)>,
    web::Form(form): web::Form<PatchRule>,
    session_user: SessionUser,
) -> Result<HttpResponse, UpdateRuleError> {
    if let Some(res) = session_user.authorization_admin_basic(&state) {
        return Ok(res);
    }

    let (group_name, path) = path.into_inner();
    let path = urlencoding::decode(&path).unwrap_or(Cow::Borrowed(&path));

    state.update_group(&group_name, |group| {
        let Some(rule) = group.get_mut(&*path) else {
            return Err(UpdateRuleError::RuleDoesNotExist);
        };
        *rule = form.rule;
        Ok(())
    })??;
    Ok(HttpResponse::Ok().finish())
}

#[derive(Deserialize)]
pub struct NewGroup {
    name: String,
}

fn refetch_groups(htmx: &Htmx) {
    htmx.trigger_event("groups".to_string(), None, Some(actix_htmx::TriggerType::AfterSwap));
}

fn refetch_groups_deleted(htmx: &Htmx) {
    refetch_groups(htmx);
    htmx.trigger_event("groupsDeleted".to_string(), None, Some(actix_htmx::TriggerType::AfterSwap));
}

pub async fn post_group(
    state: web::Data<State>,
    htmx: Htmx,
    web::Form(form): web::Form<NewGroup>,
    session_user: SessionUser,
) -> Result<HttpResponse, AddGroupError> {
    if let Some(res) = session_user.authorization_admin_basic(&state) {
        return Ok(res);
    }
    state.create_group(&form.name)?;
    Ok({
        let mut res = HttpResponse::Ok();
        if htmx.is_htmx {
            refetch_groups(&htmx);
            res.body(state
                .groups
                .read()
                .unwrap()
                .get(&*form.name)
                .unwrap()
                .read()
                .unwrap()
                .display(&form.name)
                .0)
        } else {
            res.finish()
        }
    })
}

fn api_error<T>(htmx: &Htmx, cause: T, status: StatusCode) -> HttpResponse
where T: Debug + Display
{
    if htmx.is_htmx {
        htmx.retarget("#error".to_string());
        htmx.reswap(SwapType::InnerHtml);
    }
    InternalError::new(
        cause,
        if htmx.is_htmx { StatusCode::OK } else { status }
    ).error_response()
}

pub async fn delete_group(
    htmx: Htmx,
    state: web::Data<State>,
    path: web::Path<String>,
    session_user: SessionUser,
) -> HttpResponse {
    if let Some(res) = session_user.authorization_admin_basic(&state) {
        return res;
    }
    let group_name = path.into_inner();
    if &group_name == DEFAULT_GROUP {
        return api_error(&htmx, "Can't delete default group", StatusCode::BAD_REQUEST);
    }
    if let Err(err) = state.remove_group(&group_name) {
        log::error!("{err}");
        return api_error(&htmx, err, StatusCode::INTERNAL_SERVER_ERROR);
    }
    if htmx.is_htmx {
        refetch_groups_deleted(&htmx);
    }
    HttpResponse::Ok().finish()
}

pub fn login_form(invalid: bool, return_uri: &str) -> Markup {
    html! {
        @let action = html! {
            (ARGS.dashboard) (LOGIN_ROUTE) "?r=" (return_uri)
        };
        form.table.rows action=(action) hx-post=(action) hx-swap="outerHTML" method="post" {
            div {
                label for="name" { "Username:" }
                input type="text" name="name" required;
            }
            div {
                label for="password" { "Password:" }
                input type="password" name="password" required;
            }
            input type="submit" value="Log in";
        }
        @if invalid {
            .bad.box {
                strong.titlebar { "Error" }
                p { "Incorrect username or password" }
            }
        }
    }
}

const QUERY_REDIRECT: &str = "r";

pub async fn logout(
    req: HttpRequest,
    session_user: SessionUser,
) -> impl Responder {
    let mut res = Redirect::to(
        req.headers()
            .get(REFERER)
            .map(|header| header.to_str().ok())
            .flatten()
            .unwrap_or(&ARGS.dashboard)
            .to_owned(),
    )
    .temporary()
    .respond_to(&req);
    session_user.logout(&req, &mut res);
    res
}

#[derive(Deserialize)]
pub struct Login {
    name: Box<str>,
    password: Box<str>,
}

pub async fn post_login(
    req: HttpRequest,
    web::Form(form): web::Form<Login>,
    state: web::Data<State>,
    return_uri: LoginReturnUri,
) -> Result<HttpResponse, Error> {
    let from_htmx = req.headers().contains_key("HX-Request");
    if state
        .users
        .read()
        .or(Err(Error::InternalServer))?
        .get(&form.name)
        .map(|user| user.password.expose_secret() == &*form.password)
        .unwrap_or_default()
    {
        let mut res = if from_htmx {
            let mut res = HttpResponse::Ok().respond_to(&req);
            res.headers_mut().append(
                HeaderName::from_static("hx-redirect"),
                HeaderValue::from_str(&return_uri).unwrap(),
            );
            res
        } else {
            Redirect::to(return_uri.deref().to_owned())
                .see_other()
                .respond_to(&req)
                .map_into_boxed_body()
        };
        res.add_cookie(&Cookie::build(USERNAME_COOKIE, form.name.to_string()).finish())
            .unwrap();
        res.add_cookie(&Cookie::build(PASSWORD_COOKIE, form.password.to_string()).finish())
            .unwrap();
        return Ok(res);
    }
    // Invalid credentials
    Ok(if from_htmx {
        HttpResponse::Ok().body(login_form(true, &return_uri).0)
    } else {
        HttpResponse::Unauthorized().body(html! {
            h1 { "Log in" }
            (login_form(true, &return_uri))
        }.0)
    })
}

pub struct LoginReturnUri(Box<str>);

impl Deref for LoginReturnUri {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for LoginReturnUri {
    type Error = Infallible;

    type Future = Ready<std::result::Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        fn from_headers(req: &HttpRequest) -> Option<&str> {
            req.headers()
                .get(REFERER)
                .map(|header| header.to_str().ok())
                .flatten()
        }
        fn from_query(req: &HttpRequest) -> Option<String> {
            let qstring = qstring::QString::from(req.query_string());
            qstring.get(QUERY_REDIRECT).map(|str| str.to_owned())
        }
        std::future::ready(Ok(Self(
            if req.headers().contains_key("HX-Request") {
                from_headers(req)
                    .map(|uri| Some(Cow::Borrowed(uri)))
                    .unwrap_or_else(|| from_query(req).map(|uri| Cow::Owned(uri)))
            } else {
                from_query(req)
                    .map(|uri| Some(Cow::Owned(uri)))
                    .unwrap_or_else(|| from_headers(req).map(|uri| Cow::Borrowed(uri)))
            }
            .unwrap_or(Cow::Borrowed("/"))
            .into_owned()
            .into_boxed_str(),
        )))
    }
}
