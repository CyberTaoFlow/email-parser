-- email-parser.py database schema
-- Currently set to store on MySQL (EL6)
-- See comments below to adjust for Maria
SELECT 'CREATING DATABASE STRUCTURE' as 'INFO';

-- Comment out if working w/ Maria
-- set storage_engine = Maria;
select CONCAT('storage engine: ', @@storage_engine) as INFO;

-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

-- -----------------------------------------------------
-- Schema mail
-- -----------------------------------------------------
-- This is the email storage db to be used in with email-parser.py.
-- See https://github.com/JonPulsifer/email-parser for more info.
DROP SCHEMA IF EXISTS `mail` ;

-- -----------------------------------------------------
-- Schema mail
--
-- This is the email storage db to be used in with email-parser.py.
-- See https://github.com/JonPulsifer/email-parser for more info.
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `mail` DEFAULT CHARACTER SET utf8 ;
USE `mail` ;

-- -----------------------------------------------------
-- Table `mail`.`attachment`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `mail`.`attachment` ;

CREATE TABLE IF NOT EXISTS `mail`.`attachment` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `date` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `size` INT(11) NOT NULL,
  `md5` CHAR(32) NOT NULL,
  `sha256` CHAR(64) NOT NULL,
  `ssdeep` VARCHAR(255) NOT NULL,
  `count` INT(11) NOT NULL DEFAULT '1',
  `suspicion` SMALLINT(6) NOT NULL DEFAULT '0',
  `morphed` SMALLINT(6) NOT NULL DEFAULT '0',
  `retention` TINYINT(1) NOT NULL DEFAULT '0',
  `analyzed` TINYINT(1) NOT NULL DEFAULT '0',
  `payload` LONGBLOB NULL DEFAULT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
COMMENT = 'Attachment metadata — db.CleanUp() NULLs payload column.';


-- -----------------------------------------------------
-- Table `mail`.`email`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `mail`.`email` ;

CREATE TABLE IF NOT EXISTS `mail`.`email` (
  `eid` INT(11) NOT NULL AUTO_INCREMENT,
  `timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `sessionstart` INT(11) NOT NULL,
  `digraph` VARCHAR(2) NOT NULL,
  `country` VARCHAR(128) NOT NULL,
  `ip_src` INT(10) UNSIGNED NOT NULL,
  `ip_dst` INT(10) UNSIGNED NOT NULL,
  `tcp_sport` INT(11) NOT NULL,
  `tcp_dport` INT(11) NOT NULL,
  `sender` VARCHAR(255) NOT NULL,
  `recipients` INT(11) NOT NULL,
  `subject` VARCHAR(255) NOT NULL,
  `targeted` TINYINT(1) NOT NULL DEFAULT '0',
  `campaign` INT(11) NULL DEFAULT NULL,
  `message_body` BLOB NULL DEFAULT NULL,
  PRIMARY KEY (`eid`),
  INDEX `campaign` (`campaign` ASC))
ENGINE = InnoDB
COMMENT = 'All email metadata lives here';


-- -----------------------------------------------------
-- Table `mail`.`ref`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `mail`.`ref` ;

CREATE TABLE IF NOT EXISTS `mail`.`ref` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `email_id` INT(11) NOT NULL,
  `attachment_id` INT(11) NOT NULL,
  `name` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`, `email_id`, `attachment_id`),
  INDEX `email_id` (`email_id` ASC),
  INDEX `attachment_id` (`attachment_id` ASC),
  CONSTRAINT `fk_attachment_2_email`
    FOREIGN KEY (`email_id`)
    REFERENCES `mail`.`email` (`eid`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_attach_name_2_meta`
    FOREIGN KEY (`attachment_id`)
    REFERENCES `mail`.`attachment` (`id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB
COMMENT = 'Attachment name and email reference';


-- -----------------------------------------------------
-- Table `mail`.`email_recipients`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `mail`.`email_recipients` ;

CREATE TABLE IF NOT EXISTS `mail`.`email_recipients` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `email_id` INT(11) NOT NULL,
  `recipient` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`, `email_id`),
  INDEX `email_id` (`email_id` ASC),
  CONSTRAINT `fk_recipient_2_email`
    FOREIGN KEY (`email_id`)
    REFERENCES `mail`.`email` (`eid`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
COMMENT = 'Individual email recipients live here';


-- -----------------------------------------------------
-- Table `mail`.`target`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `mail`.`target` ;

CREATE TABLE IF NOT EXISTS `mail`.`target` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires` TIMESTAMP NULL DEFAULT NULL,
  `type` CHAR(32) NOT NULL,
  `target` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`, `target`))
ENGINE = InnoDB
COMMENT = 'Special targets live here. See db.InsertMeta()';


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
