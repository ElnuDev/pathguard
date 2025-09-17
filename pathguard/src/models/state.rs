use std::{f32::consts::E, fs::{self, File}, io, ops::Deref, path::PathBuf, sync::{Mutex, RwLock, RwLockReadGuard}};
use actix_web::{ResponseError, mime::CSV, http::StatusCode};
use clap::builder::Str;
use indexmap::IndexMap;
use thiserror::Error;

use serde::{Deserialize, Serialize};
use csv;

use crate::{Args, error::Error, models::{Group, User, UserData, group::{self, DEFAULT_GROUP, Rule}, user::{self, ADMIN_USERNAME, OwnedUserData}}};

pub type Users = IndexMap<Box<str>, User>;

pub struct State {
    users_file: PathBuf,
    pub users: RwLock<Users>,
    groups_dir: PathBuf,
    pub groups: RwLock<IndexMap<String, RwLock<Group>>>,
}

#[derive(Error, Debug)]
pub enum LoadStateError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("csv deserialization error: {0}")]
    Csv(#[from] csv::Error),
}

#[derive(Error, Debug)]
pub enum UpdateStateError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("csv serialization error: {0}")]
    Csv(#[from] csv::Error),
    #[error("state mutex poisoned")]
    Poison,
}

impl ResponseError for UpdateStateError {
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

#[derive(Error, Debug)]
pub enum AddGroupError {
    #[error("{0}")]
    UpdateState(#[from] UpdateStateError),
    #[error("That group already exists")]
    AlreadyExists,
    #[error("Bad group name")]
    BadGroupName,
}

impl ResponseError for AddGroupError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UpdateState(err) => err.status_code(),
            Self::AlreadyExists => StatusCode::CONFLICT,
            Self::BadGroupName => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }
}

#[derive(Error, Debug)]
pub enum UpdateGroupError {
    #[error("{0}")]
    UpdateState(#[from] UpdateStateError),
    #[error("That group doesn't exist")]
    DoesNotExist,
}

impl ResponseError for UpdateGroupError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UpdateState(err) => err.status_code(),
            Self::DoesNotExist => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }
}

const CSV_EXTENSION: &str = ".csv";

impl State {
    pub fn load(Args { users_file, groups_dir, .. }: &Args) -> Result<Self, LoadStateError> {
        let mut users = IndexMap::new();
        if fs::exists(users_file)? {
            let mut reader = csv::Reader::from_path(&users_file)?;
            for result in reader.deserialize::<OwnedUserData>() {
                let UserData { name, user } = result?;
                users.insert(name, user);
            }
        } else {
            let user = UserData {
                name: super::user::ADMIN_USERNAME.to_string().into_boxed_str(),
                user: User::default_admin(),
            };
            let mut writer = csv::Writer::from_path(&users_file)?;
            writer.serialize(&user)?;
            writer.flush()?;
            users.insert(user.name, user.user);
        }

        let mut groups = IndexMap::new();
        // Ensure default group is always first and always present
        groups.insert(DEFAULT_GROUP.to_string(), RwLock::new(Group::default()));
        if fs::exists(groups_dir)? {
            for entry in fs::read_dir(groups_dir)? {
                let entry = entry?;
                let file_name = entry.file_name();
                let file_name_lossy = file_name.to_string_lossy();
                if !file_name_lossy.ends_with(CSV_EXTENSION) {
                    panic!("Unexpected file in groups directory {file_name_lossy}");
                }
                let mut reader = csv::Reader::from_path(entry.path())?;
                let group_name = file_name_lossy[..file_name_lossy.len() - CSV_EXTENSION.len()].to_string();
                groups.insert(group_name, RwLock::new(Group(reader
                    .deserialize::<(String, Rule)>()
                    .collect::<Result<IndexMap<String, Rule>, csv::Error>>()?)));
            }
        } else {
            fs::create_dir(groups_dir)?;
            let default_group = Group::default();
            default_group.write(&{
                let mut path = groups_dir.clone();
                path.push(format!("{DEFAULT_GROUP}{CSV_EXTENSION}"));
                path
            })?;
        }

        Ok(Self {
            users_file: users_file.clone(),
            users: RwLock::new(users),
            groups_dir: groups_dir.clone(),
            groups: RwLock::new(groups),
        })
    }

    pub fn update_users<F, T>(&self, f: F) -> Result<T, UpdateStateError>
    where F: FnOnce(&mut Users) -> T
    {
        let result = f(&mut *self.users
            .write()
            .or(Err(UpdateStateError::Poison))?);
        let mut writer = csv::Writer::from_path(&self.users_file)?;
        for user in self.users.read()
            .or(Err(UpdateStateError::Poison))?
            .iter()
            .map(|(name, user)| UserData { name, user }) {
                writer.serialize(user)?;
            }
        writer.flush()?;
        Ok(result)
    }

    pub fn add_user(&self, name: &str, user: User) -> Result<(), UpdateStateError> {
        self.update_users(|users| {
            users.insert(name.to_string().into_boxed_str(), user);
        })
    }

    pub fn remove_user(&self, name: &str) -> Result<(), UpdateStateError> {
        self.update_users(|users| {
            users.shift_remove(name);
        })
    }

    fn group_file(&self, group_name: &str) -> PathBuf {
        let mut path = self.groups_dir.clone();
        path.push(format!("{group_name}{CSV_EXTENSION}"));
        path
    }

    pub fn update_group<F, T>(&self, group_name: &str, f: F) -> Result<T, UpdateGroupError>
    where F: FnOnce(&mut Group) -> T
    {
        let groups = self.groups
            .read()
            .map_err(|_| UpdateStateError::Poison)?;
        let Some(lock) = groups.get(group_name) else {
            return Err(UpdateGroupError::DoesNotExist);
        };
        let mut group = lock.write().or(Err(UpdateStateError::Poison))?;
        let result = f(&mut group);
        group.write(&self.group_file(group_name)).map_err(|err| UpdateStateError::Io(err))?;
        Ok(result)
    }

    pub fn create_group(&self, group_name: &str) -> Result<(), AddGroupError> {
        if group_name.is_empty() {
            return Err(AddGroupError::BadGroupName);
        }
        let mut groups = self.groups
            .write()
            .map_err(|_| UpdateStateError::Poison)?;
        if groups.contains_key(group_name) {
            return Err(AddGroupError::AlreadyExists);
        }
        let group = Group::default();
        group.write(&self.group_file(group_name)).map_err(|err| UpdateStateError::Io(err))?;
        groups.insert(group_name.to_string(), RwLock::new(Group::default()));
        Ok(())
    }

    pub fn remove_group(&self, group_name: &str) -> Result<(), UpdateStateError> {
        self.groups
            .write()
            .or(Err(UpdateStateError::Poison))?
            .shift_remove(group_name);
        self.update_users(|users| {
            for user in users.values_mut() {
                user.groups.shift_remove(group_name);
            }
        })?;
        fs::remove_file({
            let mut path = self.groups_dir.clone();
            path.push(format!("{group_name}{CSV_EXTENSION}"));
            path
        })?;
        Ok(())
    }
}