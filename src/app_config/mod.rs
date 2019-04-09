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

impl ServerConfigBuilder{
    fn new()->Self{
        let server_conf = ServerConfig{
            security:Security{
                password_salt:None
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
    fn build(self)->ServerConfig{
        self.config
    }
}

#[derive(Debug)]
pub struct ServerConfig{
    pub security:Security
}
#[derive(Debug)]
pub struct Security{
    password_salt:Option<String>
}

impl Security{
    pub fn get_password_salt(&self)->String{
        match &self.password_salt{
            Some(s)=>s.clone(),
            None=>panic!("password salt None!(ServerConfigBuilder software Bug)")
        }
    }
}

pub fn load_config()->Result<ServerConfig,ConfigError>{
    let mut app_conf = config::Config::new();
    let sc_builder = ServerConfigBuilder::new();
    app_conf.merge(config::File::with_name("server"))?;
    
    Ok(
        sc_builder
        .set_password_salt(app_conf.get::<String>("security.password_salt")?)
        .build()
    )
}