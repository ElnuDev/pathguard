use actix_web::{HttpResponse, ResponseError, body::BoxBody, http::{StatusCode, header::ContentType}};
use awc::error::SendRequestError;
use maud::html;
use thiserror::Error;

use crate::templates::page;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    SendRequest(#[from] SendRequestError),
    #[error("You are unauthorized to view this page.")]
    Unauthorized,
    #[error("Something went wrong.")]
    InternalServer,
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::SendRequest(_) => StatusCode::BAD_GATEWAY,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let status_code = self.status_code();
        HttpResponse::build(status_code)
            .insert_header(ContentType::html())
            .body(page(html! {
                h1 { (status_code) }
                p { (self) }
            }))
    }
}