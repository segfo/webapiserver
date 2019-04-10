use crate::http::{header, HttpTryFrom};
use actix_web::{App, HttpRequest, HttpResponse, Result};
use actix_web::middleware::{Middleware, Started, Response};

pub struct SecurityHeaders;
// HSTS / Cache-Control / Pragma / X-CTO / X-XSSP / CSPヘッダを出力する
// X-FOは出力しない。
impl<S> Middleware<S> for SecurityHeaders {
    fn response(&self, req: &HttpRequest<S>, mut resp: HttpResponse)
        -> Result<Response>
    {
        resp.headers_mut().insert(
            header::HeaderName::try_from("Strict-Transport-Security").unwrap(),
            header::HeaderValue::from_static("max-age=31536000;includeSubDomains")
        );
        resp.headers_mut().insert(
            header::HeaderName::try_from("Content-Security-Policy").unwrap(),
            header::HeaderValue::from_static("default-src 'self';frame-ancestors 'none'")
            // frame-ancestors 'none' は X-Frame-Options : deny と同じ
        );
        resp.headers_mut().insert(
            header::HeaderName::try_from("Cache-Control").unwrap(),
            header::HeaderValue::from_static("no-cache, no-store, must-revalidate")
        );
        resp.headers_mut().insert(
            header::HeaderName::try_from("Pragma").unwrap(),
            header::HeaderValue::from_static("no-cache")
        );
        resp.headers_mut().insert(
            header::HeaderName::try_from("X-Content-Type-Options").unwrap(),
            header::HeaderValue::from_static("nosniff")
        );
        resp.headers_mut().insert(
            header::HeaderName::try_from("X-XSS-Protection").unwrap(),
            header::HeaderValue::from_static("1; mode=block")
        );
        resp.headers_mut().insert(
            header::HeaderName::try_from("X-Frame-Options").unwrap(),
            header::HeaderValue::from_static("deny")
        );
        Ok(Response::Done(resp))
    }
}