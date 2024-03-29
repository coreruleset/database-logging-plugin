# OWASP ModSecurity Core Rule Set - Database Logging Plugin

## Description

This is a plugin that brings database logging to CRS.

Plugin runs in phase 5 and writes all logs genereated by all rules into SQL
database.

Logs are read from memory using `WEBSERVER_ERROR_LOG` variable, so plugin does
not need any permissions to access log files on filesystem.

Supported SQL database systems: MySQL, MariaDB, SQLite. Support for PostgreSQL
is planned.

## Prerequisities

 * ModSecurity compiled with Lua support
 * LuaDBI library
 * plugin is able to catch only messages returned by rules with `log` action

## How to determine whether you have Lua support in ModSecurity

Most modern distro packages come with Lua support compiled in. If you are
unsure, or if you get odd error messages (e.g. `EOL found`) chances are you are
unlucky. To be really sure look for ModSecurity announce Lua support when
launching your web server:

```
... ModSecurity for Apache/2.9.5 (http://www.modsecurity.org/) configured.
... ModSecurity: APR compiled version="1.7.0"; loaded version="1.7.0"
... ModSecurity: PCRE compiled version="8.39 "; loaded version="8.39 2016-06-14"
... ModSecurity: LUA compiled version="Lua 5.3"
...
```

If this line is missing, then you are probably stuck without Lua. Check out the
documentation at [coreruleset.org](https://coreruleset.org/docs) to learn how to
get Lua support for your installation.

## LuaDBI library installation

LuaDBI library should be part of your linux distribution. Here is an example
of installation LuaDBI with MySQL driver on Debian linux:  
`apt install lua-dbi-mysql`

## Plugin installation

For full and up to date instructions for the different available plugin
installation methods, refer to [How to Install a Plugin](https://coreruleset.org/docs/concepts/plugins/#how-to-install-a-plugin)
in the official CRS documentation.

## Configuration

All settings can be done in file `plugins/database-logging-config.conf`.

### tx.database-logging-plugin_db_type

SQL database type, supported values:
 * MySQL - MySQL / MariaDB
 * SQLite3 - SQLite

Default value: MySQL

### tx.database-logging-plugin_db_name

Depends on database type (see above):
 * database name in case of MySQL
 * full path and filename in case of SQLite

Default value:

### tx.database-logging-plugin_db_login

Database login name. Ignored for SQLite.

Default value:

### tx.database-logging-plugin_db_password

Database password. Ignored for SQLite.

Default:

### tx.database-logging-plugin_db_host

Database hostname or IP address. Ignored for SQLite.

Default: localhost

### tx.database-logging-plugin_db_port

Database port. Ignored for SQLite.

Default value: 3306

## Database structure

You need to prepare correct database structure for plugin to work.

### MySQL

```
CREATE TABLE `modsecurity_requests` (
        id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
        timestamp       DATETIME,
        score           TINYINT UNSIGNED,
        server_name     VARCHAR(255),
        remote_addr     VARCHAR(255),
        unique_id       VARCHAR(50),
        response_status TINYINT,
        PRIMARY KEY(id)) ENGINE=InnoDB;
CREATE TABLE `modsecurity_requests_rules` (
        id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
        id_request      INT UNSIGNED NOT NULL,
        rule_id         INT UNSIGNED,
        variable        VARCHAR(255),
        message         VARCHAR(255),
        data            VARCHAR(255),
        severity        VARCHAR(9),
        PRIMARY KEY(id), FOREIGN KEY(id_request) REFERENCES `modsecurity_requests`(id) ON DELETE CASCADE) ENGINE=InnoDB;
```

### SQLite

```
CREATE TABLE `modsecurity_requests` (
        id                 INTEGER PRIMARY KEY NOT NULL,
        timestamp          DATETIME,
        score              INTEGER UNSIGNED,
        server_name        TEXT,
        remote_addr        TEXT,
        unique_id          TEXT,
        response_status    INTEGER UNSIGNED
        );
CREATE TABLE `modsecurity_requests_rules` (
        id                 INTEGER PRIMARY KEY NOT NULL,
        id_request         INTEGER NOT NULL,
        rule_id            INTEGER,
        variable           TEXT,
        message            TEXT,
        data               TEXT,
        severity           TEXT,
        FOREIGN KEY(id_request) REFERENCES `modsecurity_requests`(id) ON DELETE CASCADE);
```

## Testing

After configuration, plugin should be tested, for example, using:  
...

## License

Copyright (c) 2024 OWASP ModSecurity Core Rule Set project. All rights reserved.

The OWASP ModSecurity Core Rule Set and its official plugins are distributed
under Apache Software License (ASL) version 2. Please see the enclosed LICENSE
file for full details.
