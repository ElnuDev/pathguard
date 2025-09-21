use chrono::{NaiveDateTime, Utc};
use maud::{html, Markup};
use std::{
    fmt::Debug, ops::{Deref, DerefMut}
};

use crate::{
    ARGS, DATABASE, USERS_ROUTE, dashboard::{CHECK, PENCIL_SQUARE, TRASH, X_MARK, groups_select}, database::{self}, models::{Group, group::group_id}, templates::icon_button
};

pub const ADMIN_USERNAME: &str = "admin";
pub const ADMIN_DEFAULT_PASSWORD: &str = "password";

use diesel::prelude::*;
use crate::schema;

#[derive(Queryable, Selectable, Insertable, Identifiable, Debug)]
#[diesel(primary_key(name))]
#[diesel(table_name = schema::users)]
pub struct User {
    pub name: String,
    pub password: String,
    pub created: NaiveDateTime,
}

impl User {
    pub fn new(name: String, password: String) -> Self {
        Self {
            name,
            password,
            created: Utc::now().naive_utc(),
        }
    }

    pub fn with_groups(self, groups: Vec<String>) -> UserWithGroups {
        UserWithGroups { user: self, groups }
    }

    pub fn default_admin() -> Self {
        Self::new(ADMIN_USERNAME.into(), ADMIN_DEFAULT_PASSWORD.into())
    }

    pub fn is_admin(&self) -> bool {
        &*self.name == ADMIN_USERNAME
    }

    pub fn last_active(&self) -> database::Result<Option<NaiveDateTime>> {
        DATABASE.run(|conn| {
            use crate::schema::activities::dsl::*;
            activities
                .order(timestamp.desc())
                .filter(user.eq(&self.name))
                .select(timestamp)
                .first(conn)
                .optional()
        })
    }
}

impl TryInto<UserWithGroups> for User {
    type Error = database::DatabaseError;

    fn try_into(self) -> Result<UserWithGroups, Self::Error> {
        Ok(UserWithGroups {
            groups: DATABASE.run(|conn| {
                use crate::schema::user_groups::dsl::*;
                use crate::schema::groups::dsl::*;
                user_groups
                    .inner_join(groups.on(name.eq(group)))
                    .filter(user.eq(&self.name))
                    .order(sort)
                    .select(group)
                    .load(conn)
            })?,
            user: self,
        })
    }
}

#[derive(Identifiable, Selectable, Queryable, Associations, Debug)]
#[diesel(primary_key(user, group))]
#[diesel(belongs_to(User, foreign_key = user))]
#[diesel(table_name = schema::user_groups)]
pub struct UserGroup {
    pub user: String,
    pub group: String,
}

pub struct UserWithGroups {
    pub user: User,
    pub groups: Vec<String>,
}

impl Deref for UserWithGroups {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.user
    }
}

impl DerefMut for UserWithGroups {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.user
    }
}

#[derive(Default)]
pub enum UserDisplayMode<'a> {
    #[default]
    Normal,
    Edit { global_groups: &'a Vec<Group> },
}

pub struct UserRenderContext<'a> {
    pub mode: UserDisplayMode<'a>,
    pub last_active: Option<NaiveDateTime>,
}

impl UserWithGroups {
    pub fn display_groups(&self) -> Markup {
        let Self { user, groups } = self;
        html! {
            dd hx-trigger="groupsDeleted from:body" hx-swap="outerHTML" hx-get={ (ARGS.dashboard) (USERS_ROUTE) "/" (user.name) "/groups" } {
                @if groups.is_empty() { em { "None" } } @else {
                    @for (i, group_name) in groups.iter().enumerate() {
                        @if i != 0 { ", " }
                        a href={ "#" (group_id(group_name)) } { (group_name) };
                    }
                }
            }
        }
    }

    pub fn display_partial(&self, UserRenderContext { mode, last_active }: UserRenderContext) -> Markup {
        let Self { user: User { name, password, created }, .. } = self;
        let name_encoded = urlencoding::encode(name);

        html! {
            dl {
                @match mode {
                    UserDisplayMode::Normal => {
                        (icon_button(
                            PENCIL_SQUARE,
                            &format!(
                                "hx-get=\"{dashboard}{USERS_ROUTE}/{name_encoded}/edit\" hx-target=\"closest dl\"",
                                dashboard=ARGS.dashboard
                            ),
                            Some("info float:right")
                        ))
                        div {
                            dt { "Password:" }
                            dd.password.mono-font { (password) }
                        }
                        @if name != ADMIN_USERNAME {
                            div {
                                dt { "Groups:" }
                                (self.display_groups())
                            }
                        }
                    },
                    UserDisplayMode::Edit { global_groups: groups } => form
                        hx-patch={ (ARGS.dashboard) (USERS_ROUTE) "/" (name_encoded) }
                        hx-target="closest dl"
                        hx-swap="outerHTML"
                    {
                        (icon_button(
                            X_MARK,
                            &format!(
                                // type="button" prevents this from acting like form submit and losing work
                                "type=\"button\" hx-get=\"{dashboard}{USERS_ROUTE}/{name_encoded}\" hx-target=\"closest dl\" hx-swap=\"outerHTML\" style=\"margin-left: 0.5em\"",
                                dashboard=ARGS.dashboard
                            ),
                            Some("bad float:right")
                        ))
                        (icon_button(CHECK, "", Some("ok float:right")))
                        div {
                            dt { "Password:" }
                            dd { input type="text" name="password" value=(password) placeholder="password" required; }
                        }
                        @if name != ADMIN_USERNAME {
                            div {
                                dt { "Groups:" }
                                dd { (groups_select(groups, Some(self))) }
                            }
                        }
                    }
                }
                div {
                    dt { "Created:" }
                    dd { (created) }
                }
                @if name != ADMIN_USERNAME {
                    div {
                        dt { "Last active:" }
                        dd { @if let Some(when) = last_active { (when) } @else { "Never" } }
                    }
                }
            }
        }
    }

    pub fn display(&self, UserRenderContext { mode, last_active }: UserRenderContext) -> Markup {
        let name = &self.name;
        html! {
            div {
                @let name_encoded = urlencoding::encode(name);
                div {
                    @if name != ADMIN_USERNAME {
                        (icon_button(
                            TRASH,
                            &format!("hx-delete=\"{dashboard}/users/{name_encoded}\" hx-swap=\"outerHTML\" hx-target=\"closest .table.rows > div\" hx-confirm=\"Are you sure you want to delete this user?\"", dashboard=ARGS.dashboard),
                            Some("bad")
                        ))
                    }
                }
                div {
                    details #(self.name) {
                        summary { (name) }
                        (self.display_partial(UserRenderContext { mode, last_active }))
                    }
                }
            }
        }
    }
}