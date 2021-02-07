use std::collections::HashMap;

use openid::{Token, Userinfo};

use crate::entity::User;

#[derive(Default)]
pub struct Sessions {
    pub map: HashMap<String, (User, Token, Userinfo)>,
}
