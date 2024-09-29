package com.will.security.keycloak.config

import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.stereotype.Component


@Component
@EnableConfigurationProperties(JwtConverterProperties::class)
class JwtConverter(val properties: JwtConverterProperties) : Converter<Jwt, AbstractAuthenticationToken> {
    private val jwtGrantedAuthoritiesConverter: JwtGrantedAuthoritiesConverter = JwtGrantedAuthoritiesConverter()

    override fun convert(jwt: Jwt): AbstractAuthenticationToken? {
        jwtGrantedAuthoritiesConverter.convert(jwt)
            .let {
                it?.addAll(extractResourceRoles(jwt))
                it
            }
            .also { authorities ->
                return JwtAuthenticationToken(jwt, authorities, getPrincipalClaimName(jwt))
            }
    }

    fun getPrincipalClaimName(jwt: Jwt): String {
        val claimName = properties.principalAttribute
        return jwt.getClaimAsString(claimName)
    }

    private fun extractResourceRoles(jwt: Jwt): Collection<GrantedAuthority> {
        val resourceAccess = jwt.getClaim<Map<String, Any>>(REALM_ACCESS)
        val resourceRoles = resourceAccess[ROLES] as Collection<String>
        return resourceRoles.map { role -> SimpleGrantedAuthority(role) }.toSet()
    }

    companion object {
        const val REALM_ACCESS = "realm_access"
        const val ROLES = "roles"
    }
}