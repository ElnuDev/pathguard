use crate::{HTMX, MISSING_CSS, OVERRIDE_CSS, SCRIPT};
use maud::{html, Markup, PreEscaped, DOCTYPE};

pub fn page(main: Markup) -> String {
    fancy_page(html! {}, main)
}

pub fn fancy_page(before_main: Markup, main: Markup) -> String {
    html! {
        (DOCTYPE)
        html {
            head {
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
                    p { "Simple and easy path protection by " a href="/pathguard" { "pathguard" } "." }
                }
            }
        }
    }.0
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

#[allow(unused)]
macro_rules! const_icon {
    ($name:expr) => {
        PreEscaped(icon_raw!($name))
    };
}

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
