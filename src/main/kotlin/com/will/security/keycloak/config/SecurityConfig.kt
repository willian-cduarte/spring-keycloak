package com.will.security.keycloak.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig(private val jwtConverter: JwtConverter) {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .oauth2Login(withDefaults())
            .authorizeHttpRequests {
                it
                    .requestMatchers("/login").permitAll()
                    .requestMatchers("/logout").permitAll()
                    .requestMatchers("/public").permitAll()
                    .requestMatchers("/private").authenticated()
                    .requestMatchers(HttpMethod.GET, "/admin").hasAuthority(ADMIN)
                    .requestMatchers(HttpMethod.GET, "/staff").hasAuthority(STAFF)
                    .requestMatchers(HttpMethod.GET, "/user").hasAuthority(USER)
                    .requestMatchers(HttpMethod.GET, "/guest").hasAuthority(GUEST)
                    .requestMatchers(HttpMethod.GET, "/any-role").hasAnyAuthority(ADMIN, STAFF, USER, GUEST)
                    .requestMatchers(HttpMethod.GET, "/admin/**").hasAuthority(ADMIN)
                    .requestMatchers(HttpMethod.GET, "/user/**").hasAuthority(USER)
                    .requestMatchers(HttpMethod.GET, "/admin-and-user/**").hasAnyAuthority(ADMIN, USER)
                    .anyRequest().authenticated()
            }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .oauth2ResourceServer { it.jwt { jwt -> jwt.jwtAuthenticationConverter(jwtConverter) } }
            .build()
    }

    companion object {
        private const val ADMIN: String = "ADMIN"
        private const val STAFF: String = "STAFF"
        private const val USER: String = "USER"
        private const val GUEST: String = "GUEST"
    }
}