use std::{fs::File, io, path::Path};

use actix_web::http::uri::Uri;
use csv::Writer;
use maud::{Markup, html};
use serde::{Serialize, Deserialize};

use crate::{Args, dashboard::TRASH, templates::icon_button};

#[derive(Serialize, Deserialize)]
pub struct Rule {
    path_root: String,
    allowed: bool,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Group(pub Vec<Rule>);

pub const DEFAULT_GROUP: &str = "default";

impl Group {
    pub fn allowed(&self, uri: &str) -> Option<bool> {
        self.0
            .iter()
            .filter_map(|rule| uri
                .starts_with(&rule.path_root)
                .then_some(rule.allowed))
            .last()
    }

    pub fn write(&self, path: &Path) -> io::Result<()> {
        let mut writer = Writer::from_writer(File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?);
        writer.serialize(self)?;
        writer.flush()?;
        Ok(())
    }

    pub fn display(&self, args: &Args, name: &str) -> Markup {
        html! {
            div {
                div {
                    @if name != DEFAULT_GROUP {
                        (icon_button(
                            TRASH,
                            &format!("hx-delete=\"{}/groups/{name}\" hx-target=\"closest .table.rows > div\"", args.dashboard),
                            Some("bad")
                        ))
                    }
                }
                div { (name) }
                div { "Info goes here" }
            }
        }
    }
}