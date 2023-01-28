-- Add migration script here

CREATE TABLE IF NOT EXISTS users (
  id TEXT NOT NULL PRIMARY KEY ,
  name TEXT NOT NULL,
  notification_token TEXT
);

CREATE TABLE IF NOT EXISTS secret (
  id TEXT PRIMARY KEY NOT NULL,
  creator_id TEXT NOT NULL,
  limit_number INT,
  title TEXT NOT NULL,
  CONSTRAINT fk_creator
    FOREIGN KEY(creator_id) 
	  REFERENCES users(id) 
);

CREATE TABLE IF NOT EXISTS message (
  id TEXT PRIMARY KEY NOT NULL,
  creator_id TEXT NOT NULL,
  secret_id TEXT NOT NULL,
  message TEXT NOT NULL,


  CONSTRAINT fk_creator
    FOREIGN KEY(creator_id) 
	  REFERENCES users(id),
  
  CONSTRAINT fk_secret
    FOREIGN KEY(secret_id) 
	  REFERENCES secret(id) 
);