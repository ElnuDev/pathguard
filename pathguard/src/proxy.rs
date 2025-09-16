use actix_web::{HttpRequest, HttpResponse, ResponseError, body::BoxBody, http::{StatusCode, header::ContentType}, web};
use awc::{Client, error::SendRequestError};
use maud::html;
use thiserror::Error;

use crate::{Args, templates::page, error::Error};

pub async fn proxy(
    req: HttpRequest,
    body: web::Bytes,
) -> Result<HttpResponse, Error> {
    // We want to pass redirect headers to the client, not follow them ourselves
    let client = Client::builder().disable_redirects().finish();
    let forwarded_req = client
        .request_from(format!("http://127.0.0.1:{}{}", 1313, req.uri()), req.head());
    let res = forwarded_req.send_body(body).await?;
    let mut client_res = {
        let mut builder = HttpResponse::build(res.status());
        for (key, value) in res.headers() {
            builder.insert_header((key, value));
        }
        builder
    };
    Ok(client_res.streaming(res))
}
