package com.will.security.keycloak.`interface`

import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping
class IndexController {

    @GetMapping("/public")
    fun publicRoute(): String {
        return "<h1>Public route, feel free to look around! 🔓 </h1>"
    }

    @GetMapping("/private")
    fun privateRoute(): String {
        return """
            <h1>Private route, only authorized personal! 🔐  </h1>
        """.trimIndent()
    }

    @GetMapping("/user")
    fun userRoute(): String {
        return """
            <h1>Private user's route, only authorized personal with role user! 🔐  </h1>
        """.trimIndent()
    }

    @GetMapping("/staff")
    fun staffRoute(): String {
        return """
            <h1>Private staff's route, only authorized personal with role staff! 🔐  </h1>
        """.trimIndent()
    }

    @GetMapping("/guest")
    fun guestRoute(): String {
        return """
            <h1>Private guest's route, only authorized personal with role guest! 🔐  </h1>
        """.trimIndent()
    }

    @GetMapping("/admin")
    fun adminRoute(): String {
        return """
            <h1>Private admin's route, only authorized personal with role admin! 🔐  </h1>
        """.trimIndent()
    }

    @GetMapping("/any-role")
    fun anyRoute(): String {
        return """
            <h1>Private any-role's route, only authorized personal with roles admin, staff, user or guest! 🔐  </h1>
        """.trimIndent()
    }

    @GetMapping("/cookie")
    fun cookie(@AuthenticationPrincipal principal: OidcUser): String {
        return String.format(
            """
            		<h1>Oauth2 🔐  </h1>
				<h3>Principal: %s</h3>
				<h3>Email attribute: %s</h3>
				<h3>Authorities: %s</h3>
				<h3>JWT: %s</h3>
        """,
            principal,
            principal.getAttribute("email"),
            principal.authorities,
            principal.idToken.tokenValue
        )
    }

    @GetMapping("/jwt")
    fun jwt(@AuthenticationPrincipal jwt: Jwt): String {
        val authorities = if (jwt.hasClaim("authorities"))
            jwt.getClaim<Collection<*>>("authorities")
        else ""

        return """
                <h1>Oauth2 🔐  </h1>
				<h3>Principal: ${jwt.claims}</h3>
				<h3>Email attribute: ${jwt.getClaim<String>("email")}</h3>
				<h3>Authorities: $authorities</h3>
				<h3>JWT: ${jwt.tokenValue}</h3>
        """.trimIndent()
    }
}