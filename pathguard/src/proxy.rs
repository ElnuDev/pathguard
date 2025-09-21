use actix_web::{HttpRequest, HttpResponse, ResponseError, web, http::StatusCode};
use awc::{Client, error::SendRequestError};
use maud::{Render, html};
use thiserror::Error;

use crate::auth::{Authorized, Fancy, FancyError};

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("{0}")]
    SendRequest(#[from] SendRequestError),
}

impl Render for ProxyError {
    fn render(&self) -> maud::Markup {
        html! { (self.to_string()) }
    }
}

impl ResponseError for ProxyError {
    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_GATEWAY
    }
}

pub async fn proxy(
    _auth: Fancy<Authorized>,
    req: HttpRequest,
    body: web::Bytes,
) -> Result<HttpResponse, FancyError<ProxyError>> {
    // We want to pass redirect headers to the client, not follow them ourselves
    let client = Client::builder().disable_redirects().finish();
    let forwarded_req = client.request_from(
        format!("http://127.0.0.1:{}{}", 1313, req.uri()),
        req.head(),
    );
    let res = forwarded_req.send_body(body).await.map_err(ProxyError::SendRequest)?;
    let mut client_res = {
        let mut builder = HttpResponse::build(res.status());
        for (key, value) in res.headers() {
            builder.insert_header((key, value));
        }
        builder
    };
    Ok(client_res.streaming(res))
}
