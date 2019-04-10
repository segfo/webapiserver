// database(dependencies library)
#[macro_use] extern crate diesel;
// custom db util
mod database;
use database::*;
// config
extern crate dotenv;
#[macro_use] extern crate failure;

use actix_redis::RedisSessionBackend;

use rand::{RngCore,rngs::{OsRng}};
use base64::{encode, decode};
use std::sync::{Arc,Mutex};

// actix web
use actix_web::*;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_web::middleware::{
    session::{SessionStorage,RequestSession},
    identity::{CookieIdentityPolicy, IdentityService,RequestIdentity}
};
use actix_web::{ HttpResponse };
mod middleware;

// json serde
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;

// config
extern crate config;
mod app_config;

// crypto
extern crate crypto;

static AUTH_TOKEN_NAME:&str="X-auth-token";

mod auth;
use auth::*;

fn redirect_to(redirect_uri:&str)->Result<HttpResponse>{
    Ok(HttpResponse::Found().header("location", redirect_uri).finish())
}

// 唯一ログイン前でもアクセス可能なリクエスト
// 詳細は、middleware/login_checker.rs に記載
fn login_exec((req,authinfo):(HttpRequest<Arc<Mutex<AppState>>>,Json<AuthInfo>)) -> Result<HttpResponse> {
    // ログイン実行リクエスト
    let authinfo = authinfo.into_inner();
    let state = req.state().clone();
    if let Some(auth)=login_impl(state,authinfo){
        println!("authentication success : {:?}",auth);
        let _ = req.session().set("authinfo",auth);
    }else{
        return self::middleware::login_checker::unauthorized("Invalid credentials");
    }
    // ログイン成功
    let mut r = OsRng::new().unwrap();
    let mut auth_token=vec![0u8; 256/8]; // 256bit
    r.fill_bytes(&mut auth_token);
    let auth_token = encode(&auth_token);
    req.remember(auth_token.clone());
    let _ = req.session().set("counter",0);
    let _ = req.session().set::<String>(AUTH_TOKEN_NAME,auth_token.clone())?;
    redirect_to("/")
}

fn index(req: &HttpRequest<Arc<Mutex<AppState>>>) -> Result<HttpResponse> {
    let counter = req.session().get::<i64>("counter")?.unwrap();
    let authinfo = req.session().get::<auth::auth::AuthResult>("authinfo")?.unwrap();
    let _ = req.session().set("counter",counter+1);
    let mut groups=String::new();
    for group in authinfo.groups(){
        let mut group = group.name.clone();
        group.push_str(" / ");
        groups.push_str(&group);
    }
    for _ in 0..=2{let _ = groups.remove(groups.len()-1);}
    
    Ok(HttpResponse::Ok()
        .body(format!("welcome {} ({} group)\ncounter {:?}",authinfo.uname(),groups, counter)))
}

fn logout(req: HttpRequest<Arc<Mutex<AppState>>>) -> HttpResponse {
    // 認証トークンをクライアントのブラウザから削除する
    // 削除しなくても良い。無効な値として使われるので。あくまでもおせっかい。
    req.forget(); 
    // セッションから認証済みトークンなどの情報を全削除
    // これは必ず明示的なログアウト時にはやらなければならない。
    // 暗黙的なログアウトはタイムアウトが起きればされるが、
    // 「放置してれば切れるからいいや」というのは
    // ユーザの意に反するので設計としてあまり良くない。
    req.session().clear(); 
    HttpResponse::Found().header("location", "/").finish() 
}

#[derive(Debug)]
pub struct AppState{
    db:database::DBConnector,
    app_config:app_config::ServerConfig
}

impl AppState{
    fn new(db:database::DBConnector,app_config:app_config::ServerConfig)->Self{
        AppState{
            db:db,
            app_config:app_config
        }
    }
}

fn main() {
    let conf = app_config::load_config().unwrap();
    let sys = actix::System::new("http2_api-test");

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key_file("key.pem", SslFiletype::PEM).unwrap();
    builder.set_certificate_chain_file("cert.pem").unwrap();
    let state = Arc::new(Mutex::new(
            AppState::new(establish_connection().unwrap(),
            conf.clone()
        )));
    
    let cookie_salt = base64::decode(&conf.security.get_cookie_salt()).unwrap();
    let authtoken_salt = base64::decode(&conf.security.get_authtoken_salt()).unwrap();
    server::new(move|| {
        App::with_state(state.clone())
            .middleware(SessionStorage::new(
                RedisSessionBackend::new("127.0.0.1:6379", &cookie_salt)
                .ttl(60*5) // expire 1 hour
                .cookie_secure(true) // secure attribute
            ))
            .middleware(IdentityService::new(
                CookieIdentityPolicy::new(&authtoken_salt)
                .name(AUTH_TOKEN_NAME)
                .secure(true)
            ))
            .middleware(self::middleware::sec_header::SecurityHeaders)
            .middleware(self::middleware::login_checker::LoginChecker)
            .resource("/", |r| r.method(http::Method::GET).f(|req| index(req)))
            .resource(&self::middleware::login_checker::login_uri(),|r|r.method(http::Method::POST).with(login_exec))
            .route("/logout",http::Method::GET,logout)
    }).bind_ssl("127.0.0.1:8443", builder).unwrap().workers(128).start();
//    }).bind("127.0.0.1:8443").unwrap().start();
    println!("Started http server: 127.0.0.1:8443");
    let _ = sys.run();
}
