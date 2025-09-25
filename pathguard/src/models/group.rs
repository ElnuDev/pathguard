use maud::{html, Markup, Render};

use crate::{
    dashboard::{CHEVRON_DOWN, CHEVRON_UP, PLUS, TRASH},
    database,
    templates::{const_icon_button, icon_button},
    ARGS, DATABASE, GROUPS_ROUTE,
};

use crate::schema::*;
use diesel::prelude::*;
use diesel::BelongingToDsl;

#[derive(Queryable, Selectable, Identifiable, PartialEq, Debug)]
#[diesel(primary_key(name))]
pub struct Group {
    pub name: String,
}

impl Group {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

#[derive(Queryable, Selectable, Identifiable, Associations, PartialEq, Debug)]
#[diesel(primary_key(group, path))]
#[diesel(belongs_to(Group, foreign_key = group))]
pub struct Rule {
    pub group: String,
    pub path: String,
    pub allowed: Option<bool>,
}

impl Render for Rule {
    fn render(&self) -> Markup {
        html! {
            div {
                @let path_encoded = urlencoding::encode(&self.path);
                div {
                    (icon_button(
                        TRASH,
                        &format!("hx-delete=\"{dashboard}/groups/{group}/rules/{path_encoded}\" hx-swap=\"outerHTML\" hx-target=\"closest .table.rows > div\" hx-confirm=\"Are you sure you want to delete this rule?\"",
                            dashboard=ARGS.dashboard,
                            group=self.group),
                        Some("bad")
                    ))
                }
                div { (self.path) }
                form.rule.float:right
                    autocomplete="off"
                    hx-trigger="change"
                    hx-patch={ (ARGS.dashboard) (GROUPS_ROUTE) "/" (self.group) "/rules/" (path_encoded) }
                    hx-swap="beforebegin"
                {
                    label { input name="rule" value=(RULE_OFF) type="radio" checked[self.allowed == Some(false)]; }
                    label { input name="rule" value=(RULE_NA) type="radio" checked[self.allowed.is_none()]; }
                    label { input name="rule" value=(RULE_ON) type="radio" checked[self.allowed == Some(true)]; }
                }
            }
        }
    }
}

pub const RULE_ON: &str = "on";
pub const RULE_NA: &str = "na";
pub const RULE_OFF: &str = "off";

pub const DEFAULT_GROUP: &str = "default";

pub fn group_id(name: &str) -> String {
    "group-".to_string() + &urlencoding::encode(name)
}

impl Group {
    pub fn rules(&self) -> database::Result<Vec<Rule>> {
        DATABASE.run(|conn| {
            use crate::schema::rules::dsl::*;
            Rule::belonging_to(self)
                .order(sort)
                .select(Rule::as_select())
                .load(conn)
        })
    }

    pub fn id(&self) -> String {
        group_id(&self.name)
    }

    pub fn display_without_rules(&self) -> Markup {
        self.display_with_rules(&vec![])
    }

    pub fn display(&self) -> database::Result<Markup> {
        Ok(self.display_with_rules(&self.rules()?))
    }

    fn display_with_rules(&self, rules: &Vec<Rule>) -> Markup {
        let name = &self.name;
        html! {
            div {
                div {
                    @if name != DEFAULT_GROUP {
                        (icon_button(
                            TRASH,
                            &format!("hx-delete=\"{}/groups/{name}\" hx-swap=\"outerHTML\" hx-target=\"closest .table.rows > div\" hx-confirm=\"Are you sure you want to delete this group?\"", ARGS.dashboard),
                            Some("bad")
                        ))
                        br;
                        (icon_button(
                            CHEVRON_UP,
                            &format!("hx-post=\"{dashboard}/groups/{name}/up\" hx-swap=\"none\" hx-on::after-swap=\"swapUp(this.parentElement.parentElement)\"",
                                dashboard=ARGS.dashboard),
                            None
                        ))
                        br;
                        (icon_button(
                            CHEVRON_DOWN,
                            &format!("hx-post=\"{dashboard}/groups/{name}/down\" hx-swap=\"none\" hx-on::after-swap=\"swapDown(this.parentElement.parentElement)\"",
                                dashboard=ARGS.dashboard),
                            None
                        ))
                    }
                }
                h3 #(self.id()) {
                    (name)
                }
                .table.rows {
                    @for rule in rules {
                        (rule)
                    }
                    form
                        hx-post={ (ARGS.dashboard) (GROUPS_ROUTE) "/" (name) }
                        hx-swap="beforebegin"
                        hx-on::after-request="this.querySelector('input').value = ''"
                    {
                        div { (const_icon_button!(PLUS, "", "ok")) }
                        input
                            type="text"
                            name="name"
                            pattern="\\/.*"
                            title="Must start with a /"
                            required;
                    }
                }
            }
        }
    }
}
