use actix_redis::RedisSessionBackend;

use rand::{RngCore};
use rand::os::{OsRng};
use base64::{encode, decode};

use actix_web::*;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_web::middleware::identity::{CookieIdentityPolicy, IdentityService,RequestIdentity};
use actix_web::middleware::session::{SessionStorage,RequestSession};
use actix_web::{HttpRequest, HttpResponse, http::ContentEncoding};

fn index(req: &HttpRequest) -> Result<HttpResponse> {
    // まだ「ログイン」をしていない状態だった。
    let not_login = Ok(HttpResponse::Ok()
            .content_encoding(ContentEncoding::Br)
            .body("Welcome Anonymous!".to_owned()));

    let auth_token = req.session().get::<String>(AUTH_TOKEN_NAME)?;
    let recv_token = req.identity();
    // どちらかのCookie値が空の場合は、ログインをしていない。
    if auth_token==None || recv_token==None{
        return not_login;
    }
    // セッション変数に格納した乱数値とログイン完了時に発行した
    // 乱数値が一致しなければ不正なものとしてログインしていない状態として扱う。
    if auth_token.unwrap() == recv_token.unwrap(){
        let counter = req.session().get::<i64>("counter")?.unwrap();
        req.session().set("counter",counter+1);
        Ok(HttpResponse::Ok()
            .content_encoding(ContentEncoding::Br)
            .body(format!("counter {:?}", counter))
        )
    }else{
        not_login
    }
}

static AUTH_TOKEN_NAME:&str="X-auth-token";

fn login(req: HttpRequest) -> Result<HttpResponse> {
    //　このあたりにログイン処理を書く
    
    // IDとパスワードが一致してログイン完了（したとして）
    // 乱数（本来はCSPRNGを使用するべき）を生成する。
    let mut r = OsRng::new().unwrap();
    let mut auth_token=vec![0u8; 256/8]; // 256bit
    r.fill_bytes(&mut auth_token);
    let auth_token = encode(&auth_token);
    req.remember(auth_token.clone());
    let token = req.session().set::<String>(AUTH_TOKEN_NAME,auth_token.clone())?;
    req.session().set("counter",0);
    Ok(HttpResponse::Found().header("location", "/").finish())
}

fn logout(req: HttpRequest) -> HttpResponse {
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

fn main() {
    let sys = actix::System::new("http2_api-test");

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key_file("key.pem", SslFiletype::PEM).unwrap();
    builder.set_certificate_chain_file("cert.pem").unwrap();
    
    server::new(|| {
        App::new()
            .middleware(SessionStorage::new(
                RedisSessionBackend::new("127.0.0.1:6379", &[0; 32])
                .ttl(60) // expire 1 hour
                .cookie_secure(true) // secure attribute
            ))
            .middleware(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                .name(AUTH_TOKEN_NAME)
                .secure(true)
            ))
            .resource("/", |r| r.method(http::Method::GET).f(|req| index(&req)))
            .route("/login",http::Method::GET,login)
            .route("/logout",http::Method::GET,logout)
    }).bind_ssl("127.0.0.1:8443", builder).unwrap().start();
//    }).bind("127.0.0.1:8443").unwrap().start();
    println!("Started http server: 127.0.0.1:8443");
    let _ = sys.run();
}
