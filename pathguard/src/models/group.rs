use std::{
    fs::File,
    io,
    ops::{Deref, DerefMut},
    path::Path,
};

use csv::Writer;
use indexmap::IndexMap;
use maud::{html, Markup};
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use crate::{
    dashboard::{PLUS, TRASH},
    templates::{const_icon_button, icon_button},
    ARGS, GROUPS_ROUTE,
};

pub type Rule = Option<bool>;

pub const RULE_ON: &str = "on";
pub const RULE_NA: &str = "na";
pub const RULE_OFF: &str = "off";

#[derive(Deserialize)]
pub struct RuleData<N: AsRef<str>, Rule> {
    pub path: N,
    #[serde(flatten)]
    pub rule: Rule,
}

pub type OwnedRuleData = RuleData<Box<str>, Rule>;

impl<N> Serialize for RuleData<N, Rule>
where
    N: AsRef<str>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("rule", 2)?;
        s.serialize_field("path", self.path.as_ref())?;
        s.serialize_field("rule", &self.rule)?;
        s.end()
    }
}

#[derive(Default)]
pub struct Group(pub IndexMap<String, Rule>);

pub const DEFAULT_GROUP: &str = "default";

impl Deref for Group {
    type Target = IndexMap<String, Rule>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Group {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Group {
    pub fn allowed(&self, uri: &str) -> Option<bool> {
        self.iter()
            .filter_map(|(path, rule)| {
                rule.map(|allowed| uri.starts_with(path).then_some(allowed))
                    .flatten()
            })
            .last()
    }

    pub fn write(&self, path: &Path) -> io::Result<()> {
        let mut writer = Writer::from_writer(
            File::options()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)?,
        );
        for (path, rule) in self.iter() {
            writer.serialize(RuleData { path, rule: *rule })?;
        }
        writer.flush()?;
        Ok(())
    }

    pub fn id(name: &str) -> String {
        "group-".to_string() + &urlencoding::encode(name)
    }

    pub fn display(&self, name: &str) -> Markup {
        html! {
            div {
                div {
                    @if name != DEFAULT_GROUP {
                        (icon_button(
                            TRASH,
                            &format!("hx-delete=\"{}/groups/{name}\" hx-swap=\"outerHTML\" hx-target=\"closest .table.rows > div\" hx-confirm=\"Are you sure you want to delete this group?\"", ARGS.dashboard),
                            Some("bad")
                        ))
                    }
                }
                h3 #(Self::id(name)) { (name) }
                .table.rows {
                    @for (path_root, rule) in &self.0 {
                        (Self::display_rule(name, path_root, rule))
                    }
                    form
                        hx-post={ (ARGS.dashboard) (GROUPS_ROUTE) "/" (name) }
                        hx-swap="beforebegin"
                        hx-on::after-request="this.querySelector('input').value = ''"
                    {
                        div { (const_icon_button!(PLUS, "", "ok")) }
                        input type="text" name="name" required;
                    }
                }
            }
        }
    }

    pub fn display_rule(group_name: &str, path: &str, rule: &Rule) -> Markup {
        html! {
            div {
                @let path_encoded = urlencoding::encode(path);
                div {
                    (icon_button(
                        TRASH,
                        &format!("hx-delete=\"{dashboard}/groups/{group_name}/{path_encoded}\" hx-swap=\"outerHTML\" hx-target=\"closest .table.rows > div\" hx-confirm=\"Are you sure you want to delete this rule?\"",
                            dashboard=ARGS.dashboard),
                        Some("bad")
                    ))
                }
                div { (path) }
                form.rule.float:right
                    autocomplete="off"
                    hx-trigger="change"
                    hx-patch={ (ARGS.dashboard) (GROUPS_ROUTE) "/" (group_name) "/" (path_encoded) }
                    hx-swap="beforebegin"
                {
                    label { input name="rule" value=(RULE_OFF) type="radio" checked[*rule == Some(false)]; }
                    label { input name="rule" value=(RULE_NA) type="radio" checked[rule.is_none()]; }
                    label { input name="rule" value=(RULE_ON) type="radio" checked[*rule == Some(true)]; }
                }
            }
        }
    }
}
