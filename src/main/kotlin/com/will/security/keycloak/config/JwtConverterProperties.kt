package com.will.security.keycloak.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "jwt.auth.converter")
data class JwtConverterProperties(
    val resourceId: String,
    val principalAttribute: String,
)
