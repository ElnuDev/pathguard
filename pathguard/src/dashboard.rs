use std::{borrow::Cow, convert::Infallible, fmt::Debug, future::Ready, ops::Deref};

use crate::{
    auth::{AuthorizedAdmin, Fancy, PASSWORD_SESSION_KEY, USERNAME_SESSION_KEY},
    database::{self, DatabaseError},
    models::{
        group::{self, Rule, DEFAULT_GROUP},
        user::{UserDisplayMode, UserRenderContext, UserWithGroups, ADMIN_USERNAME},
        Activity, Group, User,
    },
    templates::{const_icon_button, fancy_page},
    ARGS, DATABASE, GROUPS_ROUTE, LOGIN_ROUTE, LOGOUT_ROUTE, PASSWORD_GENERATOR, USERS_ROUTE,
};
use actix_htmx::Htmx;
use actix_session::Session;
use actix_web::{
    error::{ErrorBadRequest, ErrorConflict, ErrorForbidden, ErrorNotFound}, http::header::REFERER, web::{self, Redirect}, FromRequest, HttpRequest, HttpResponse, Responder, ResponseError
};
use awc::http::StatusCode;
use chrono::NaiveDateTime;
use chrono_humanize::HumanTime;
use diesel::{
    dsl::{delete, exists, insert_into, max},
    prelude::*,
    r2d2::ConnectionManager,
    select, update,
};
use maud::{html, Markup, PreEscaped, Render};
use qstring::{self};
use r2d2::PooledConnection;
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

const CHEVRON_UP_: &str = "chevron-up";
pub const CHEVRON_UP: &str = CHEVRON_UP_;

const CHEVRON_DOWN_: &str = "chevron-down";
pub const CHEVRON_DOWN: &str = CHEVRON_DOWN_;

pub fn timestamp(utc: &NaiveDateTime) -> Markup {
    html! {
        @let datetime = utc.and_utc();
        time datetime=(datetime) title=(datetime) { (HumanTime::from(datetime)) }
    }
}

pub async fn dashboard(_auth: Fancy<AuthorizedAdmin>) -> database::Result<HttpResponse> {
    const ACTIVITY_LIMIT: i64 = 100;
    Ok(HttpResponse::Ok().body(fancy_page(html! {
        header.navbar {
            nav {
                ul role="list" {
                    li { a.allcaps href="#" { "pathguard" } }
                    li { a href="#groups" { "Groups" } }
                    li { a href="#users" { "Users" } }
                    li { a href="#activity" { "Activity" } }
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
            symbol #(CHEVRON_UP_) fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" {
                (PreEscaped(r#"<path stroke-linecap="round" stroke-linejoin="round" d="m4.5 15.75 7.5-7.5 7.5 7.5" />"#))
            }
            symbol #(CHEVRON_DOWN_) fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" {
                (PreEscaped(r#"<path stroke-linecap="round" stroke-linejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />"#))
            }
        }
        h1 { "Dashboard" }
        h2 #groups { "Groups" }
        @let groups = DATABASE.groups()?;
        .table.rows {
            @for group in groups.iter() {
                (group.display()?)
            }
            form hx-post={ (ARGS.dashboard) (GROUPS_ROUTE) } hx-swap="beforebegin" hx-on::after-request="this.querySelector('input').value = ''" {
                div { (const_icon_button!(PLUS, "", "ok")) }
                input type="text" name="name" placeholder="Add a new group" required;
            }
        }
        h2 #users { "Users" }
        p { label style="user-select: none" { "Show passwords? " input #show-passwords type="checkbox" autocomplete="off"; } }
        .table.rows {
            @for user in DATABASE.users()? {
                @let user: UserWithGroups = user.try_into()?;
                (user.display(UserRenderContext {
                    mode: UserDisplayMode::Normal,
                    last_active: user.last_active()?,
                }))
            }
            (new_user_form(false, &groups))
        }
        h2 #activity { "Activity" }
        p { "Only showing latest " (ACTIVITY_LIMIT) " activity items." }
        @let activities = DATABASE.run(|conn| {
            use crate::schema::activities::dsl;
            dsl::activities
                .select(Activity::as_select())
                .order(dsl::id.desc())
                .limit(ACTIVITY_LIMIT)
                .get_results(conn)
        })?;
        table style="width: 100%" {
            thead {
                tr {
                    th scope="col" { "User" }
                    th scope="col" { "IP" }
                    th scope="col" { "Path" }
                    th scope="col" { "Timestamp (UTC)" }
                }
            }
            tbody {
                @for activity in activities {
                    tr.bg[!activity.allowed].color[!activity.allowed].bad[!activity.allowed] {
                        td { @if let Some(user) = &activity.user { a href={ "#" (user) } { (user) } } }
                        td { (activity.ip.deref()) }
                        td {
                            a
                                target="_blank"
                                href=(activity.path)
                                hx-boost="false"
                            {
                                (activity.path)
                            }
                        }
                        td { (timestamp(&activity.timestamp)) }
                    }
                }
            }
        }
    })))
}

fn new_user_form(autofocus: bool, groups: &Vec<Group>) -> Markup {
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
                    div { input type="text" name="password" placeholder="password" value=[{
                        #[allow(clippy::match_result_ok)]
                        PASSWORD_GENERATOR.generate_one().ok()
                    }] required; }
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

pub async fn get_groups(_auth: AuthorizedAdmin) -> Result<HttpResponse, DatabaseError> {
    Ok(HttpResponse::Ok().body(groups_select(&DATABASE.groups()?, None)))
}

pub async fn get_user_groups(
    _auth: AuthorizedAdmin,
    path: web::Path<String>,
) -> Result<HttpResponse, DatabaseError> {
    let username = path.into_inner();
    let Some(user) = DATABASE.user(&username)? else {
        return Ok(HttpResponse::NotFound().finish());
    };
    let user: UserWithGroups = user.try_into()?;
    Ok(HttpResponse::Ok().body(user.display_groups()))
}

pub fn groups_select(groups: &Vec<Group>, user: Option<&UserWithGroups>) -> Markup {
    html! {
        select hx-trigger="groups from:body" hx-get={ (ARGS.dashboard) (GROUPS_ROUTE) } name="groups" multiple {
            @for group in groups {
                @if group.name != DEFAULT_GROUP {
                    option
                        value=(group.name)
                        selected[user
                            .map(|user| user.groups.contains(&group.name))
                            .unwrap_or_default()]
                    { (group.name) }
                }
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum PasswordValidationError {
    #[error("password strength must be at least {min}/100, provided password strength was only {strength:.1}")]
    WeakPassword { strength: f64, min: f64 },
    #[error("\"{0}\" is a common password and shouldn't be used")]
    CommonPassword(Box<str>),
}

impl ResponseError for PasswordValidationError {
    fn status_code(&self) -> StatusCode {
        StatusCode::UNPROCESSABLE_ENTITY
    }
}

pub fn validate_password(password: &str) -> Result<(), PasswordValidationError> {
    use PasswordValidationError::*;

    let analyzed = passwords::analyzer::analyze(password);
    if analyzed.is_common() {
        return Err(CommonPassword(password.to_string().into_boxed_str()));
    }

    let strength = passwords::scorer::score(&analyzed);
    if strength < ARGS.min_password_strength {
        return Err(WeakPassword {
            strength,
            min: ARGS.min_password_strength,
        });
    }

    Ok(())
}

#[derive(Error, Debug)]
pub enum UserError {
    #[error("{0}")]
    Database(#[from] DatabaseError),
    #[error("{0}")]
    Validation(#[from] PasswordValidationError),
}

impl ResponseError for UserError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Database(err) => err.status_code(),
            Self::Validation(err) => err.status_code(),
        }
    }
}

// webformd can't deserialize Box<str> or IndexSet<Box<str>> directly
// TODO: maybe open a PR?
#[derive(WebformDeserialize)]
pub struct UserForm {
    password: String,
    groups: Vec<String>,
}

fn add_groups<'a>(
    conn: &mut PooledConnection<ConnectionManager<SqliteConnection>>,
    username: &str,
    groups: impl Iterator<Item = &'a String>,
) -> QueryResult<()> {
    let mut add_group = |group| {
        use crate::schema::user_groups::dsl;
        insert_into(dsl::user_groups)
            .values((dsl::user.eq(username), dsl::group.eq(group)))
            .execute(conn)
    };
    add_group(DEFAULT_GROUP)?;
    for group in groups.filter(|group| *group != DEFAULT_GROUP) {
        add_group(group)?;
    }
    Ok(())
}

pub async fn post_user(
    _auth: AuthorizedAdmin,
    htmx: Htmx,
    web::Form(form): web::Form<Vec<(String, String)>>,
) -> Result<HttpResponse, UserError> {
    let user_form = match UserForm::deserialize(&form) {
        Ok(form) => form,
        Err(err) => return Ok(ErrorBadRequest(err).error_response()),
    };
    let Some(name) = form
        .into_iter()
        .filter(|(key, _value)| key.as_str() == "name")
        .map(|(_key, value)| value)
        .next()
    else {
        return Ok(ErrorBadRequest("missing username field").error_response());
    };
    validate_password(&user_form.password)?;
    let mut groups = user_form.groups;
    groups.insert(0, DEFAULT_GROUP.to_string());
    let user = User::new(name, user_form.password).with_groups(groups);

    DATABASE.run(|conn| {
        conn.transaction(|conn| {
            use crate::schema::users::dsl;
            insert_into(dsl::users).values(user.deref()).execute(conn)?;
            add_groups(conn, &user.name, user.groups.iter())?;
            Ok(())
        })
    })?;

    let mut res = HttpResponse::Ok();
    Ok(if htmx.is_htmx {
        res.body(html! {
            (user.display(UserRenderContext {
                mode: UserDisplayMode::Normal,
                last_active: None,
            }))
            (new_user_form(true, &DATABASE.groups()?))
        })
    } else {
        res.finish()
    })
}

pub fn get_user_generic(
    edit: bool,
) -> impl AsyncFn(AuthorizedAdmin, web::Path<String>) -> database::Result<HttpResponse> {
    async move |_auth: AuthorizedAdmin, path: web::Path<String>| -> database::Result<HttpResponse> {
        let username = path.into_inner();
        let Some(user) = DATABASE.user(&username)? else {
            return Ok(ErrorNotFound("That user doesn't exist").error_response());
        };
        let user: UserWithGroups = user.try_into()?;
        let global_groups = if edit { Some(DATABASE.groups()?) } else { None };
        let mode = global_groups
            .as_ref()
            .map(|global_groups| UserDisplayMode::Edit { global_groups })
            .unwrap_or_default();
        Ok(
            HttpResponse::Ok().body(user.display_partial(UserRenderContext {
                mode,
                last_active: user.last_active()?,
            })),
        )
    }
}

pub async fn get_user(
    auth: AuthorizedAdmin,
    path: web::Path<String>,
) -> database::Result<HttpResponse> {
    get_user_generic(false)(auth, path).await
}

pub async fn get_user_edit(
    auth: AuthorizedAdmin,
    path: web::Path<String>,
) -> database::Result<HttpResponse> {
    get_user_generic(true)(auth, path).await
}

pub async fn patch_user(
    _auth: AuthorizedAdmin,
    htmx: Htmx,
    web::Form(form): web::Form<Vec<(String, String)>>,
    path: web::Path<String>,
    session: Session,
) -> Result<HttpResponse, UserError> {
    let UserForm {
        password,
        mut groups,
    } = match UserForm::deserialize(&form) {
        Ok(form) => form,
        Err(err) => return Ok(ErrorBadRequest(err).error_response()),
    };
    let name = path.into_inner();
    validate_password(&password)?;
    groups.insert(0, DEFAULT_GROUP.to_string());

    // We want to give back 404 Not Found instead of 409 Conflict
    // if the given user doesn't exist. SQLite doesn't support reporting back
    // which foreign key violation there was (nonexistent user vs group),
    // so we have to make sure manually.
    let user = match DATABASE.run(|conn| {
        let Some(created): Option<NaiveDateTime> = ({
            use crate::schema::users::dsl;
            dsl::users
                .filter(dsl::name.eq(&name))
                .select(dsl::created)
                .get_result(conn)
                .optional()?
        }) else {
            return Ok(Err(ErrorNotFound("that user doesn't exist").error_response()));
        };

        conn.transaction(|conn| -> Result<(), diesel::result::Error> {
            {
                use crate::schema::user_groups::dsl;
                delete(dsl::user_groups.filter(dsl::user.eq(&name))).execute(conn)?;
                add_groups(conn, &name, groups.iter())?;
            }
            {
                use crate::schema::users::dsl;
                update(dsl::users)
                    .filter(dsl::name.eq(&name))
                    .set(dsl::password.eq(&password))
                    .execute(conn)?;
            }
            Ok(())
        })?;
        Ok(Ok(created))
    })? {
        Ok(created) => User { name, password, created }.with_groups(groups),
        Err(res) => return Ok(res),
    };

    if user.name == ADMIN_USERNAME {
        session.insert(PASSWORD_SESSION_KEY, &user.password).unwrap();
    }
    let mut res = HttpResponse::Ok();
    Ok(if htmx.is_htmx {
        res.body(user.display_partial(UserRenderContext {
            mode: UserDisplayMode::Normal,
            last_active: user.last_active()?,
        }))
    } else {
        res.finish()
    })
}

pub async fn delete_user(
    _auth: AuthorizedAdmin,
    path: web::Path<String>,
) -> database::Result<HttpResponse> {
    let name = path.into_inner();
    Ok(
        if DATABASE.run(|conn| {
            use crate::schema::users::dsl;
            delete(dsl::users.filter(dsl::name.eq(&name))).execute(conn)
        })? == 0
        {
            ErrorNotFound("that user doesn't exist").error_response()
        } else {
            HttpResponse::Ok().finish()
        },
    )
}

#[derive(Deserialize)]
pub struct NewRule {
    name: String,
}

pub async fn post_rule(
    _auth: AuthorizedAdmin,
    path: web::Path<String>,
    htmx: Htmx,
    web::Form(NewRule { name }): web::Form<NewRule>,
) -> database::Result<HttpResponse> {
    let group_name = path.into_inner();
    let rule = Rule {
        allowed: None,
        group: group_name,
        path: name,
    };
    DATABASE.run(|conn| {
        use crate::schema::rules::dsl;
        let sort = dsl::rules
            .select(max(dsl::sort))
            .get_result::<Option<i32>>(conn)?
            .map(|highest| highest + 1)
            .unwrap_or_default();
        insert_into(dsl::rules)
            .values((
                dsl::sort.eq(sort),
                dsl::group.eq(&rule.group),
                dsl::allowed.eq(&rule.allowed),
                dsl::path.eq(&rule.path),
            ))
            .execute(conn)
    })?;
    let mut res = HttpResponse::Ok();
    Ok(if htmx.is_htmx {
        res.body(rule.render())
    } else {
        res.finish()
    })
}

pub async fn delete_rule(
    _auth: AuthorizedAdmin,
    path: web::Path<(String, String)>,
) -> database::Result<HttpResponse> {
    let (group, path) = path.into_inner();
    let path = urlencoding::decode(&path).unwrap_or(Cow::Borrowed(&path));
    DATABASE.run(|conn| {
        use crate::schema::rules::dsl;
        delete(
            dsl::rules
                .filter(dsl::group.eq(&group))
                .filter(dsl::path.eq(&path)),
        )
        .execute(conn)
    })?;
    Ok(HttpResponse::Ok().finish())
}

#[derive(Deserialize)]
pub struct PatchRule {
    #[serde(deserialize_with = "deserialize_rule")]
    rule: Option<bool>,
}

fn deserialize_rule<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match String::deserialize(deserializer)?.as_str() {
        group::RULE_OFF => Some(false),
        group::RULE_NA => None,
        group::RULE_ON => Some(true),
        _ => return Err(serde::de::Error::custom("rule must be off, na, or no")),
    })
}

pub async fn patch_rule(
    _auth: AuthorizedAdmin,
    path: web::Path<(String, String)>,
    web::Form(form): web::Form<PatchRule>,
) -> database::Result<HttpResponse> {
    let (group, path) = path.into_inner();
    let path = urlencoding::decode(&path).unwrap_or(Cow::Borrowed(&path));

    Ok(
        if DATABASE.run(|conn| {
            use crate::schema::rules::dsl;
            update(dsl::rules)
                .filter(dsl::group.eq(&group))
                .filter(dsl::path.eq(&path))
                .set(dsl::allowed.eq(&form.rule))
                .execute(conn)
        })? == 0
        {
            ErrorNotFound("that rule doesn't exist").error_response()
        } else {
            HttpResponse::Ok().finish()
        },
    )
}

#[derive(Deserialize)]
pub struct NewGroup {
    name: String,
}

fn refetch_groups(htmx: &Htmx) {
    htmx.trigger_event(
        "groups".to_string(),
        None,
        Some(actix_htmx::TriggerType::AfterSwap),
    );
}

fn refetch_groups_deleted(htmx: &Htmx) {
    refetch_groups(htmx);
    htmx.trigger_event(
        "groupsDeleted".to_string(),
        None,
        Some(actix_htmx::TriggerType::AfterSwap),
    );
}

pub async fn post_group(
    _auth: AuthorizedAdmin,
    htmx: Htmx,
    web::Form(form): web::Form<NewGroup>,
) -> database::Result<HttpResponse> {
    let group = Group::new(form.name);
    DATABASE.run(|conn| {
        use crate::schema::groups::dsl;
        let sort = dsl::groups
            .select(max(dsl::sort))
            .get_result::<Option<i32>>(conn)?
            .map(|highest| highest + 1)
            .unwrap_or_default();
        insert_into(dsl::groups)
            .values((dsl::name.eq(&group.name), dsl::sort.eq(sort)))
            .execute(conn)
    })?;
    let mut res = HttpResponse::Ok();
    Ok(if htmx.is_htmx {
        refetch_groups(&htmx);
        res.body(group.display_without_rules())
    } else {
        res.finish()
    })
}

pub async fn delete_group(
    _auth: AuthorizedAdmin,
    htmx: Htmx,
    path: web::Path<String>,
) -> database::Result<HttpResponse> {
    let name = path.into_inner();
    if name == DEFAULT_GROUP {
        return Ok(ErrorForbidden("can't delete default group").error_response());
    }
    if DATABASE.run(|conn| {
        use crate::schema::groups::dsl;
        delete(dsl::groups.filter(dsl::name.eq(&name))).execute(conn)
    })? == 0
    {
        return Ok(ErrorNotFound("that group doesn't exist").error_response());
    }
    if htmx.is_htmx {
        refetch_groups_deleted(&htmx);
    }
    Ok(HttpResponse::Ok().finish())
}

pub async fn post_group_up(
    _auth: AuthorizedAdmin,
    path: web::Path<String>,
) -> database::Result<HttpResponse> {
    let name = path.into_inner();
    if name == DEFAULT_GROUP {
        return Ok(ErrorForbidden("can't move default group").error_response());
    }
    DATABASE.run(|conn| {
        use crate::schema::groups::dsl;
        let Some(current_sort): Option<i32> = dsl::groups
            .select(dsl::sort)
            .filter(dsl::name.eq(&name))
            .get_result(conn)
            .optional()?
        else
        {
            return Ok(HttpResponse::NotFound().finish());
        };
        let Some((previous_name, previous_sort)): Option<(String, i32)> = dsl::groups
            .select((dsl::name, dsl::sort))
            .filter(dsl::sort.lt(current_sort))
            .filter(dsl::name.ne(DEFAULT_GROUP))
            .order(dsl::sort.desc())
            .get_result(conn)
            .optional()?
        else
        {
            return Ok(ErrorConflict("can't move group above default group").error_response());
        };
        // Swap sort values with previous
        conn.transaction(|conn| {
            update(dsl::groups)
                .set(dsl::sort.eq(current_sort))
                .filter(dsl::name.eq(&previous_name))
                .execute(conn)?;
            update(dsl::groups)
                .set(dsl::sort.eq(previous_sort))
                .filter(dsl::name.eq(&name))
                .execute(conn)?;
            Result::<(), diesel::result::Error>::Ok(())
        })?;
        Ok(HttpResponse::Ok().finish())
    })
}

pub async fn post_group_down(
    _auth: AuthorizedAdmin,
    path: web::Path<String>,
) -> database::Result<HttpResponse> {
    let name = path.into_inner();
    if name == DEFAULT_GROUP {
        return Ok(ErrorForbidden("can't move default group").error_response());
    }
    DATABASE.run(|conn| {
        use crate::schema::groups::dsl;
        let Some(current_sort): Option<i32> = dsl::groups
            .select(dsl::sort)
            .filter(dsl::name.eq(&name))
            .get_result(conn)
            .optional()?
        else
        {
            return Ok(HttpResponse::NotFound().finish());
        };
        let Some((next_name, next_sort)): Option<(String, i32)> = dsl::groups
            .select((dsl::name, dsl::sort))
            .filter(dsl::sort.gt(current_sort))
            .order(dsl::sort)
            .get_result(conn)
            .optional()?
        else
        {
            return Ok(ErrorConflict("can't move final group down").error_response());
        };
        // Swap sort values with next
        conn.transaction(|conn| {
            update(dsl::groups)
                .set(dsl::sort.eq(current_sort))
                .filter(dsl::name.eq(&next_name))
                .execute(conn)?;
            update(dsl::groups)
                .set(dsl::sort.eq(next_sort))
                .filter(dsl::name.eq(&name))
                .execute(conn)?;
            Result::<(), diesel::result::Error>::Ok(())
        })?;
        Ok(HttpResponse::Ok().finish())
    })
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

pub async fn logout(req: HttpRequest, htmx: Htmx, session: Session) -> HttpResponse {
    let redirect = req
        .headers()
        .get(REFERER)
        .and_then(|header| header.to_str().ok())
        .unwrap_or(&ARGS.dashboard)
        .to_owned();
    session.purge();
    if htmx.is_htmx {
        htmx.redirect(redirect);
        HttpResponse::Ok().finish()
    } else {
        Redirect::to(redirect)
            .respond_to(&req)
            .map_into_boxed_body()
    }
}

#[derive(Deserialize)]
pub struct Login {
    name: String,
    password: String,
}

pub async fn post_login(
    req: HttpRequest,
    htmx: Htmx,
    web::Form(form): web::Form<Login>,
    return_uri: LoginReturnUri,
    session: Session,
) -> database::Result<HttpResponse> {
    let authorized: bool = DATABASE.run(|conn| {
        use crate::schema::users::dsl;
        select(exists(
            dsl::users
                .filter(dsl::name.eq(&form.name))
                .filter(dsl::password.eq(&form.password)),
        ))
        .get_result(conn)
    })?;
    if authorized {
        session.insert(USERNAME_SESSION_KEY, &form.name).unwrap();
        session.insert(PASSWORD_SESSION_KEY, &form.password).unwrap();
        return Ok(if htmx.is_htmx {
            htmx.redirect(return_uri.0);
            HttpResponse::Ok().finish()
        } else {
            Redirect::to(return_uri.deref().to_owned())
                .see_other()
                .respond_to(&req)
                .map_into_boxed_body()
        });
    }
    // Invalid credentials
    Ok(if htmx.is_htmx {
        HttpResponse::Ok().body(login_form(true, &return_uri))
    } else {
        HttpResponse::Unauthorized().body(html! {
            h1 { "Log in" }
            (login_form(true, &return_uri))
        })
    })
}

pub struct LoginReturnUri(String);

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
                .and_then(|header| header.to_str().ok())
        }
        fn from_query(req: &HttpRequest) -> Option<String> {
            let qstring = qstring::QString::from(req.query_string());
            qstring.get(QUERY_REDIRECT).map(|str| str.to_owned())
        }
        std::future::ready(Ok(Self(
            if req.headers().contains_key("hx-request") {
                from_headers(req)
                    .map(|uri| Some(Cow::Borrowed(uri)))
                    .unwrap_or_else(|| from_query(req).map(Cow::Owned))
            } else {
                from_query(req)
                    .map(|uri| Some(Cow::Owned(uri)))
                    .unwrap_or_else(|| from_headers(req).map(Cow::Borrowed))
            }
            .unwrap_or(Cow::Borrowed("/"))
            .into_owned(),
        )))
    }
}
