CREATE EXTENSION IF NOT EXISTS "uuid-ossp";  

CREATE TABLE IF NOT EXISTS user (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  notification_token TEXT,
);

CREATE TABLE IF NOT EXISTS secret {
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4 (),
  creator_id TEXT NOT NULL,
  limit_number INT,
  CONSTRAINT fk_creator
    FOREIGN KEY(creator_id) 
	  REFERENCES user(id) 
}

CREATE TABLE IF NOT EXISTS message {
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4 (),
  creator_id TEXT NOT NULL,
  secret_id UUID NOT NULL,
  message TEXT NOT NULL,


  CONSTRAINT fk_creator
    FOREIGN KEY(creator_id) 
	  REFERENCES user(id),
  
  CONSTRAINT fk_secret
    FOREIGN KEY(secret_id) 
	  REFERENCES secret(id) 
}