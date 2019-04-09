pub mod schema;
pub mod models;

use diesel::prelude::*;
use dotenv::dotenv;
use std::env;
use std::sync::Arc;

#[derive(Debug, Fail)]
pub enum DatabaseError {
    #[fail(display = "Connection Failure : {}", 0)]
    VarError(std::env::VarError),
    #[fail(display = "Connection Failure : {}", 0)]
    ConnectionFailure(diesel::ConnectionError)

}

impl std::convert::From<std::env::VarError> for DatabaseError{
    fn from(e:std::env::VarError)->DatabaseError{
        DatabaseError::VarError(e)
    }
}

impl std::convert::From<diesel::ConnectionError> for DatabaseError{
    fn from(e:diesel::ConnectionError)->DatabaseError{
        DatabaseError::ConnectionFailure(e)
    }
}

pub fn establish_connection() -> Result<DBConnector, DatabaseError> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")?;
    let conn = PgConnection::establish(&database_url)?;
    Ok(DBConnector{conn:conn})
}

impl std::fmt::Debug for DBConnector{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f,"")
    }
}

pub struct DBConnector{
    pub conn : PgConnection
}
