use std::{net::{AddrParseError, IpAddr, Ipv4Addr}, ops::{Deref, DerefMut}, str::FromStr};

use actix_web::HttpRequest;
use chrono::NaiveDateTime;
use diesel::prelude::*;

use crate::schema::activities;

#[derive(Queryable, Selectable, Insertable, Debug, Default)]
#[diesel(table_name = activities)]
pub struct Activity {
    pub timestamp: NaiveDateTime,
    pub user: Option<String>,
    #[diesel(serialize_as = String)]
    #[diesel(deserialize_as = String)]
    pub ip: DbIpAddr,
    pub path: String,
    pub allowed: bool
}

impl Activity {
    /// Activity with ip and path set from given request,
    /// with all other fields left as default
    pub fn from_request(req: &HttpRequest) -> Self {
        Activity {
            ip: req.peer_addr().unwrap().ip().into(),
            path: req.path().to_string(),
            ..Default::default()
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DbIpAddr(pub IpAddr);

impl Default for DbIpAddr {
    fn default() -> Self {
        Self(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
    }
}

impl Deref for DbIpAddr {
    type Target = IpAddr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DbIpAddr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<IpAddr> for DbIpAddr {
    fn from(val: IpAddr) -> Self {
        DbIpAddr(val)
    }
}

impl From<DbIpAddr> for IpAddr {
    fn from(val: DbIpAddr) -> Self {
        val.0
    }
}

impl TryFrom<String> for DbIpAddr {
    type Error = AddrParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self(IpAddr::from_str(&value)?))
    }
}

impl From<DbIpAddr> for String {
    fn from(value: DbIpAddr) -> Self {
        value.to_string()
    }
}