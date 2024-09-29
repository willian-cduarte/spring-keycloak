package com.will.security.keycloak

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class SpringKeycloakApplication

fun main(args: Array<String>) {
	runApplication<SpringKeycloakApplication>(*args)
}
