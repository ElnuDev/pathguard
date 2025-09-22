CREATE TABLE IF NOT EXISTS users (
	name		TEXT PRIMARY KEY NOT NULL,
	password	TEXT NOT NULL,
	created		DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
	sort		INTEGER NOT NULL,
	name		TEXT PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS user_groups (
	user		TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
	[group]		TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
	PRIMARY KEY (user, [GROUP])
);

CREATE TABLE IF NOT EXISTS rules (
	sort		INTEGER NOT NULL,
	[group]		TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
	allowed		BOOLEAN,
	path		TEXT NOT NULL,
	PRIMARY KEY	([group], path)
);

CREATE TABLE IF NOT EXISTS activities (
	id			INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp	DATETIME NOT NULL,
	user		TEXT REFERENCES users(name),
	-- maximum string length of an IPv6 address
	-- https://stackoverflow.com/a/166157
	ip			VARCHAR(45) NOT NULL,
	path		TEXT NOT NULL,
	allowed		BOOLEAN NOT NULL
);