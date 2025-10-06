use std::borrow::Cow;

use crate::{models::user::ADMIN_USERNAME, ARGS, HTMX, LOGOUT_ROUTE, MISSING_CSS, OVERRIDE_CSS, SCRIPT};
use maud::{html, Markup, PreEscaped, DOCTYPE};

pub fn page(main: Markup) -> Markup {
    fancy_page(html! {}, main)
}

pub fn fancy_page(before_main: Markup, main: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                title { "pathguard" }
                meta name="darkreader-lock";
                script src=(HTMX) {}
                script src=(SCRIPT) {}
                link rel="stylesheet" href=(MISSING_CSS);
                link rel="stylesheet" href=(OVERRIDE_CSS);
            }
            body hx-boost="true" {
                (before_main)
                main {
                    (main)
                }
                footer {
                    p { "Simple and easy path protection by " a target="_blank" href="https://github.com/ElnuDev/pathguard" { "pathguard" } "." }
                }
            }
        }
    }
}

pub fn dashboard_page(root: bool, main: Markup) -> Markup {
    let root = root
        .then_some(Cow::Borrowed("#"))
        .unwrap_or_else(|| Cow::Owned(ARGS.dashboard.to_string() + "#"));
    fancy_page(
        html! {
            header.navbar {
                nav {
                    ul role="list" {
                        li { a.allcaps href=(root) { "pathguard" } }
                        li { a href={ (root) "groups" } { "Groups" } }
                        li { a href={ (root) "users" } { "Users" } }
                        li { a href={ (ARGS.dashboard) "/activity" } { "Activity" } }
                    }
                }
                nav style="margin-left: auto" {
                    "Hello, " strong { (ADMIN_USERNAME) } " "
                    a href={(ARGS.dashboard) (LOGOUT_ROUTE)} { "Log out" }
                }
            }
        },
        main
    )
}

macro_rules! const_icon_raw {
    ($name:expr) => {
        const_format::concatcp!(
            r##"<svg class="icon"><use xlink:href="#"##,
            $name,
            r#"" /></svg>"#
        )
    };
}
pub(crate) use const_icon_raw;

macro_rules! const_icon {
    ($name:expr) => {
        PreEscaped(crate::templates::const_icon_raw!($name))
    };
}
pub(crate) use const_icon;

pub fn icon(name: &str) -> Markup {
    html! {
        svg.icon {
            use xlink:href={ "#" (name) } {}
        }
    }
}

macro_rules! const_icon_button {
    ($name:expr, $params:expr) => {
        maud::PreEscaped(const_format::concatcp!(
            r#"<button class="iconbutton" "#,
            $params,
            ">",
            crate::templates::const_icon_raw!($name),
            "</button>"
        ))
    };
    ($name:expr, $params:expr, $colorway:expr) => {
        maud::PreEscaped(const_format::concatcp!(
            r#"<button class="iconbutton "#,
            $colorway,
            r#"" "#,
            $params,
            ">",
            crate::templates::const_icon_raw!($name),
            "</button>"
        ))
    };
}
pub(crate) use const_icon_button;

pub fn icon_button(name: &str, attrs: &str, extra_classes: Option<&str>) -> Markup {
    html! {
        (PreEscaped(r#"<button class="iconbutton"#))
        @if let Some(extra_classes) = extra_classes { " " (extra_classes) }
        (PreEscaped(r#"" "#))
        (PreEscaped(attrs))
        (PreEscaped(">"))
        (icon(name))
        (PreEscaped("</button>"))
    }
}
