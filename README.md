# Spring MVC application with stateless security using JWT backed by LDAP[![Build Status](https://travis-ci.org/SNCF-SIV/spring-security-rest-jwt-ldap.svg?branch=master)](https://travis-ci.org/SNCF-SIV/spring-security-rest-jwt-ldap)

Forked from the [Spring Security REST JWT repository](https://github.com/SNCF-SIV/spring-security-rest-jwt) which is backed by MongoDB.
Instead of checking user authentication using MongoDB database, it uses a LDAP server.

#### Requirements

 * Java 8
 * LDAP server

#### LDAP Settings

 * Change your settings inside `src/main/resources/application.properties`
 * Change the role allowed inside `ProtectedController`

LDAP configuration is not provided here (depending on your IT Service).

#### Building and installing the application

 * Run `mvn clean install`.
 * deploy the built WAR on your favorite servlet container (JBoss, Tomcat, ...)

#### Testing authentication

see [Spring Security REST JWT repository](https://github.com/SNCF-SIV/spring-security-rest-jwt)

## Testing Authorization

[Spring Security REST JWT repository](https://github.com/SNCF-SIV/spring-security-rest-jwt)

## License

This project is released under version 2.0 of the
[Apache License](http://www.apache.org/licenses/LICENSE-2.0).
