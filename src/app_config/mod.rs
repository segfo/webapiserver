use config::*;

#[derive(Debug)]
pub struct ServerConfigBuilder{
    config:ServerConfig
}

#[derive(Debug, Fail)]
pub enum ConfigError {
    #[fail(display = "LoadError : {}", 0)]
    LoadError(config::ConfigError),
}

impl std::convert::From<config::ConfigError> for self::ConfigError{
    fn from(e:config::ConfigError)->ConfigError{
        ConfigError::LoadError(e)
    }
}

#[allow(dead_code)]
impl ServerConfigBuilder{
    fn new()->Self{
        let server_conf = ServerConfig{
            security:Security{
                password_salt:None,
                authtoken_salt:None,
                cookie_salt:None
            }
        };

        ServerConfigBuilder{
            config:server_conf
        }
    }
    fn set_password_salt(mut self,salt:String)->Self{
        self.config.security.password_salt = Some(salt);
        self
    }
    fn set_authtoken_salt(mut self,salt:String)->Self{
        self.config.security.authtoken_salt = Some(salt);
        self
    }
    fn set_cookie_salt(mut self,salt:String)->Self{
        self.config.security.cookie_salt = Some(salt);
        self
    }
    fn build(self)->ServerConfig{
        self.config
    }
}

#[derive(Debug,Clone)]
pub struct ServerConfig{
    pub security:Security
}
#[derive(Debug,Clone)]
pub struct Security{
    password_salt:Option<String>,
    authtoken_salt:Option<String>,
    cookie_salt:Option<String>
}

impl Security{
    pub fn get_password_salt(&self)->String{
        match &self.password_salt{
            Some(s)=>s.clone(),
            None=>panic!("password salt None!(ServerConfigBuilder software Bug)")
        }
    }
    pub fn get_authtoken_salt(&self)->String{
        match &self.authtoken_salt{
            Some(s)=>s.clone(),
            None=>panic!("password salt None!(ServerConfigBuilder software Bug)")
        }
    }
    pub fn get_cookie_salt(&self)->String{
        match &self.cookie_salt{
            Some(s)=>s.clone(),
            None=>panic!("password salt None!(ServerConfigBuilder software Bug)")
        }
    }
}
use rand::rngs::OsRng;
use rand::RngCore;

fn gen_salt(bytes:usize)->String{
    let mut rng = OsRng::new().unwrap();
    let mut buff = vec![0u8;bytes];
    rng.fill_bytes(&mut buff);
    base64::encode(&buff)
}

pub fn load_config()->Result<ServerConfig,ConfigError>{
    let mut app_conf = config::Config::new();
    let sc_builder = ServerConfigBuilder::new();
    app_conf.merge(config::File::with_name("config/server"))?;
    
    let cookie_salt = match app_conf.get::<String>("security.cookie_salt"){
        Ok(salt)=>salt,
        Err(_e)=>{
            let salt = gen_salt(32);
            app_conf.set("security.cookie_salt",salt.clone())?;
            salt
        }
    };
    let authtoken_salt = match app_conf.get::<String>("security.authtoken_salt"){
        Ok(salt)=>salt,
        Err(_e)=>{
            let salt = gen_salt(32);
            app_conf.set("security.authtoken_salt",salt.clone())?;
            salt
        }
    };
    
    app_conf.refresh();
    Ok(
        sc_builder
        .set_password_salt(app_conf.get::<String>("security.password_salt")?)
        .set_authtoken_salt(authtoken_salt)
        .set_cookie_salt(cookie_salt)
        .build()
    )
}