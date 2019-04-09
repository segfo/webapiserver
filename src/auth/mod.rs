pub mod auth;
use std::sync::{Mutex,Arc};
use super::database::*;
use crate::AppState;

#[derive(Serialize,Deserialize)]
pub struct AuthInfo{
    mail:String,
    password:String
}

// ログイン処理用
pub fn login_impl(app_state:Arc<Mutex<AppState>>,authinfo:AuthInfo)->Option<auth::AuthResult>{
    match auth::id_password(app_state,&authinfo.mail,&authinfo.password){
        Ok(auth)=>{
            Some(auth)
        },
        Err(e)=>{
        //    log.warn("{}",e)
            None
        }
    }
}