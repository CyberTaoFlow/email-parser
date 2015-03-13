-- email-parser.py database schema
-- Currently set to store on MariaDB (RHEL7)
-- See comments below to adjust for MySQL
--
-- THIS SCHEMA INSERTS TEST ROWS AT THE BOTTOM
-- REMOVE OR COMMENT BEFORE PROD

DROP DATABASE IF EXISTS email;
CREATE DATABASE IF NOT EXISTS email;
USE email;

SELECT 'CREATING DATABASE STRUCTURE' as 'INFO';

DROP TABLE IF EXISTS email,
					 attachments;

-- Comment out if working w/ MySQL
set storage_engine = Maria;

select CONCAT('storage engine: ', @@storage_engine) as INFO;

CREATE TABLE email (
	id              INT          NOT NULL AUTO_INCREMENT,
	timestamp       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
	sessionstart    INT(11)      NOT NULL,
	ip_src          INT          UNSIGNED NOT NULL,
	ip_dst          INT          UNSIGNED NOT NULL,
	tcp_sport       INT          NOT NULL,
	tcp_dport       INT          NOT NULL,
	sender          VARCHAR(255) NOT NULL,
	recipients      INT          NOT NULL,
	subject         VARCHAR(255) NOT NULL,
	campaign        INT,
	message_body    BLOB,
	PRIMARY KEY (id),
	FOREIGN KEY (campaign) REFERENCES campaigns (id)
);

CREATE TABLE email_recipients (
	id        INT          NOT NULL AUTO_INCREMENT,
	email_id  INT          NOT NULL,
	recipient VARCHAR(255) NOT NULL,
	PRIMARY KEY (id, email_id),
	FOREIGN KEY (email_id) REFERENCES email (id)
);

CREATE TABLE attachment (
	id         INT        NOT NULL AUTO_INCREMENT,
	md5        CHAR(32)   NOT NULL,
	sha256     CHAR(64)   NOT NULL,
	count      INT        NOT NULL DEFAULT 1,
	suspicion  SMALLINT   NOT NULL DEFAULT 0,
	morphed    SMALLINT   NOT NULL DEFAULT 0,
	retention  TINYINT(1) NOT NULL DEFAULT 0,
	analyzed   TINYINT(1) NOT NULL DEFAULT 0,
	bywho      CHAR(32),
	payload    LONGBLOB   NOT NULL,
	PRIMARY KEY (id)
);

CREATE TABLE attachment_ref (
	id            INT          NOT NULL AUTO_INCREMENT,
	email_id      INT          NOT NULL,
	attachment_id INT          NOT NULL,
	name          VARCHAR(255) NOT NULL,
	PRIMARY KEY (id, email_id, attachment_id),
	FOREIGN KEY (email_id) REFERENCES email (id),
	FOREIGN KEY (attachment_id) REFERENCES attachment (id)
);

CREATE TABLE indicators (
	id        INT          NOT NULL AUTO_INCREMENT,
	timestamp TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
	type      CHAR(32)     NOT NULL,
	indicator VARCHAR(255) NOT NULL,
	PRIMARY KEY (id, type, indicator)
);

CREATE TABLE campaigns (
	id       INT          NOT NULL AUTO_INCREMENT,
	campaign VARCHAR(255) NOT NULL,
	PRIMARY KEY (id)
);
