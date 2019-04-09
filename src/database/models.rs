#[derive(Queryable,Debug,Serialize,Deserialize,Clone)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub mail_address: String,
    pub pass_hash: String,
}

#[derive(Queryable,Debug,Serialize,Deserialize,Clone)]
pub struct Group {
    pub id: i32,
    pub name: String,
}

// ユーザIDとグループID（外部キー）のみからなるテーブル
#[derive(Queryable,Debug,Serialize,Deserialize,Clone)]
pub struct GroupMembership {
    pub id: i64,
    pub user_id: i32,
    pub group_id: i32
}
