table! {
    users (id) {
        id -> Integer,
        user_name -> Text,
        mail_address -> Text,
        pass_hash -> Text,
    }
}

table! {
    groups (id) {
        id -> Integer,
        group_name -> Text,
    }
}

table! {
    group_memberships (id){
        id -> BigInt,
        user_id -> Integer,
        group_id -> Integer,
    }
}
