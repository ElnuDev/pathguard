use actix_web::{http::StatusCode, ResponseError};
use diesel::insert_or_ignore_into;
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use maud::html;
use maud::Render;
use r2d2::{Pool, PooledConnection};
use thiserror::Error;

use crate::models::group::DEFAULT_GROUP;
use crate::models::{Group, User};

pub struct Database {
    connection_pool: Pool<ConnectionManager<SqliteConnection>>,
}

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum DatabaseError {
    #[error("{0}")]
    Diesel(#[from] diesel::result::Error),
    #[error("{0}")]
    Pool(#[from] r2d2::Error),
}

impl Render for DatabaseError {
    fn render(&self) -> maud::Markup {
        html! { (self) }
    }
}

impl ResponseError for DatabaseError {
    fn status_code(&self) -> StatusCode {
        use diesel::result::{DatabaseErrorKind as Kind, Error};
        let Self::Diesel(diesel_error) = self else {
            return StatusCode::SERVICE_UNAVAILABLE;
        };
        match diesel_error {
            Error::DatabaseError(
                Kind::UniqueViolation | Kind::ForeignKeyViolation | Kind::ExclusionViolation,
                _,
            ) => StatusCode::CONFLICT,
            Error::DatabaseError(Kind::CheckViolation, _) => StatusCode::UNPROCESSABLE_ENTITY,
            Error::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

pub type Result<T> = std::result::Result<T, DatabaseError>;

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let manager = ConnectionManager::<SqliteConnection>::new(path);
        let connection_pool = Pool::builder()
            .test_on_check_out(true)
            .build(manager)
            .expect("Could not build connection pool");
        let this = Self { connection_pool };
        this.run(|conn| {
            {
                use crate::schema::users::dsl;
                insert_or_ignore_into(dsl::users)
                    .values(&User::default_admin())
                    .execute(conn)?;
            }
            {
                use crate::schema::groups::dsl;
                insert_or_ignore_into(dsl::groups)
                    .values((dsl::sort.eq(0), dsl::name.eq(DEFAULT_GROUP)))
                    .execute(conn)?;
            }
            Ok(())
        })?;
        Ok(this)
    }

    fn conn(
        &self,
    ) -> std::result::Result<PooledConnection<ConnectionManager<SqliteConnection>>, r2d2::Error>
    {
        self.connection_pool.get()
    }

    pub fn run<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut PooledConnection<ConnectionManager<SqliteConnection>>) -> QueryResult<R>,
    {
        let mut conn = self.conn()?;
        //sql_query("PRAGMA foreign keys = ON;").execute(&mut conn)?;
        Ok(f(&mut conn)?)
    }

    pub fn groups(&self) -> Result<Vec<Group>> {
        self.run(|conn| {
            use crate::schema::groups::dsl::*;
            groups.select(Group::as_select()).order_by(sort).load(conn)
        })
    }

    pub fn user(&self, username: &str) -> Result<Option<User>> {
        self.run(|conn| {
            use crate::schema::users::dsl::*;
            users
                .select(User::as_select())
                .filter(name.eq(username))
                .get_result(conn)
                .optional()
        })
    }

    pub fn users(&self) -> Result<Vec<User>> {
        self.run(|conn| {
            use crate::schema::users::dsl::*;
            users.select(User::as_select()).load(conn)
        })
    }
}
