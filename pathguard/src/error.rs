use std::{fmt::Display, ops::{Deref, DerefMut}};

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

#[derive(Debug)]
pub struct BasicError(pub Error);

impl Deref for BasicError {
    type Target = Error;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BasicError {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for BasicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl ResponseError for BasicError {
    fn status_code(&self) -> StatusCode {
        self.0.status_code()
    }
}

impl From<Error> for BasicError {
    fn from(value: Error) -> Self {
        Self(value)
    }
}