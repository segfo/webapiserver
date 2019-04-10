use crate::http::{header, Uri, HttpTryFrom};
use actix_web::{App, HttpRequest, HttpResponse, Result};
use actix_web::middleware::{Middleware, Started, Response};
pub struct LoginChecker;
use actix_web::middleware::{
    session::{SessionStorage,RequestSession},
    identity::{CookieIdentityPolicy, IdentityService,RequestIdentity}
};
use std::sync::{Mutex,Arc};
use crate::AppState;

pub fn login_uri()->String{
    "/login_exec".to_owned()
}

pub fn unauthorized(s:&str)->Result<HttpResponse>{
    Ok(
        HttpResponse::Unauthorized()
        .body(s.to_owned())
    )
}
use crate::AUTH_TOKEN_NAME;
fn is_login(req: &HttpRequest<Arc<Mutex<AppState>>>) -> bool {
    let auth_token = match req.session().get::<String>(AUTH_TOKEN_NAME){
        Ok(token)=>token,
        Err(_)=>{return false;}
    };
    let recv_token = req.identity();
    // どちらかのCookie値が空の場合(1行目)、または乱数値が違う場合(2行目)は、ログインをしていない。
    if (auth_token==None || recv_token==None) || 
        auth_token.unwrap() != recv_token.unwrap(){
        false
    }else{
        true
    }
}

// startメソッドでログイン状態を確認。
// login_uriメソッドで得られるURI以外の場合は必ずログイン状態でないと401が返却される。
// https://github.com/actix/actix-web/issues/300
impl Middleware<Arc<Mutex<AppState>>> for LoginChecker {
    fn start(&self, req: &HttpRequest<Arc<Mutex<AppState>>>) -> Result<Started> {
        let uri = match login_uri().parse::<Uri>(){
            Ok(uri)=>uri,
            Err(e)=>{
                return Ok(Started::Response(unauthorized("unauthorized").unwrap()));
            }
        };
        if req.uri()!=&uri && !is_login(req){
            Ok(Started::Response(unauthorized("unauthorized").unwrap()))
        }else{
            Ok(Started::Done)
        }
    }
}
