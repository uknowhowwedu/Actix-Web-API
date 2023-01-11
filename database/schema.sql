CREATE USER admin WITH PASSWORD '*7fjn_djpa9dHH78^';

CREATE SCHEMA IF NOT EXISTS main;

CREATE TABLE IF NOT EXISTS main.users (
	id UUID PRIMARY KEY,
	username VARCHAR(15) UNIQUE NOT NULL,
	acc_type VARCHAR(1) NOT NULL,
	password VARCHAR(192) NOT NULL,
	salt VARCHAR(22) NOT NULL,
	creation_date BIGINT NOT NULL,
	banned BOOLEAN DEFAULT false NOT NULL,
	ban_date BIGINT
);

CREATE TABLE IF NOT EXISTS main.transactions (
	tx_id VARCHAR(20) PRIMARY KEY,
	id UUID UNIQUE NOT NULL,
	first_name VARCHAR(50) NOT NULL,
	last_name VARCHAR(50) NOT NULL,
	address VARCHAR(125) NOT NULL,
	tx_timestamp BIGINT NOT NULL,
	CONSTRAINT fk_id
		FOREIGN KEY(id) 
			REFERENCES main.users(id)
			ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS main.data (
	id UUID PRIMARY KEY,
	save_one JSON,
	save_two JSON,
	save_three JSON,
	timestamp_one BIGINT,
	timestamp_two BIGINT,
	timestamp_three BIGINT,
	CONSTRAINT fk_id
		FOREIGN KEY(id) 
			REFERENCES main.users(id)
			ON DELETE CASCADE
);

GRANT ALL PRIVILEGES ON SCHEMA main TO admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA main TO admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA main TO admin;