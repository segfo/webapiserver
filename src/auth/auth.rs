
use std::sync::{Mutex,Arc};
use crate::AppState;
//use crate::user;

#[derive(Debug,Serialize,Deserialize)]
pub struct AuthResult{
    uid:i32,
    uname:String,
    groups:Vec<Group>
}

impl AuthResult{
    pub fn uid(&self)->i32{self.uid}
    pub fn uname(&self)->String{self.uname.to_owned()}
    pub fn groups(&self)->Vec<Group>{
        self.groups.clone()
    }
}

#[derive(Debug, Fail)]
pub enum AuthError {
    #[fail(display = "Access Denied : {}", user_name)]
    AccessDenied {
        user_name: String,
    },
    #[fail(display = "DB Access Error : {}", 0)]
    DBAccessError(diesel::result::Error)
}

impl std::convert::From<diesel::result::Error> for AuthError{
    fn from(e:diesel::result::Error)->AuthError{
        AuthError::DBAccessError(e)
    }
}

use diesel::prelude::*;

// crypt
use crypto::digest::Digest;
use crypto::sha2::Sha256;

use crate::models::*;
use crate::database::schema::users;
use crate::database::schema::groups;
use crate::database::schema::group_memberships;

pub fn id_password(app_state:Arc<Mutex<AppState>>,mail:&str,password:&str)->Result<AuthResult,AuthError>{
    let state = app_state.lock().unwrap();
    
    let salt = state.app_config.security.get_password_salt();
    let mut sha256 = Sha256::new();
    sha256.input_str(&format!("{}{}",salt,password));
    let hashed_password = sha256.result_str();
    #[cfg(debug_assertions)]
    {
        println!("{} + {}",salt,password);
        println!("-> {}",hashed_password);
    }
    
    // ユーザの検索
    let user = users::table.filter(users::mail_address.eq(mail.clone()))
        .filter(users::pass_hash.eq(hashed_password.clone()))
        .load::<User>(&state.db.conn);
    let user = user.unwrap();
    if user.len()==1{
        joinable!( group_memberships -> groups (group_id));
        allow_tables_to_appear_in_same_query!(groups, group_memberships);
        
        let group = group_memberships::table
                    .inner_join(groups::table)
                    .filter(group_memberships::user_id.eq(user[0].id))
                    .select((groups::id,groups::group_name)).load::<(Group)>(&state.db.conn)?;

        Ok(AuthResult{
            uid:user[0].id,
            uname:user[0].name.clone().to_owned(),
            groups:group
        })
    }else{
        Err(AuthError::AccessDenied{user_name:mail.to_owned()})
    }
    
}
