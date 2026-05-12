package com.nguyennt1103.untitledbff;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OidcBackChannelLogoutHandler;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(BffProperties.class)
@RequiredArgsConstructor
public class SecurityConfig {

    private final BffProperties bff;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/actuator/health",
                                "/actuator/info",
                                "/actuator/prometheus"
                        ).permitAll()

                        .requestMatchers(
                                "/oauth2/**",
                                "/api/**"
                        ).permitAll()

                        .anyRequest()
                        .authenticated()
                )

                .cors(cors -> cors
                        .configurationSource(corsConfigurationSource()))

                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository())
                        .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
                )

                .oauth2Login(oauth2Login -> oauth2Login
                        .authorizationEndpoint(auth -> auth
                                .authorizationRedirectStrategy(new CustomRedirectStrategy())
                                .authorizationRequestResolver(authorizationRequestResolver()))

                        .userInfoEndpoint(userInfo -> userInfo
                                .userAuthoritiesMapper(userAuthoritiesMapper()))

                        .successHandler(authenticationSuccessHandler())
                        .failureHandler(authenticationFailureHandler()))

                .logout(logout -> logout
                        .logoutSuccessHandler(logoutSuccessHandler()))

                .oidcLogout(oidc -> oidc
                        .backChannel(Customizer.withDefaults()))

                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new CustomAuthenticationEntryPoint(bff.getLoginUrl())))

                .sessionManagement(session -> session
                        .invalidSessionStrategy(new CustomInvalidSessionStrategy()));

        return http.build();
    }

    @Bean
    public OidcSessionRegistry oidcSessionRegistry() {
        return new InMemoryOidcSessionRegistry();
    }

    @Bean
    public OidcBackChannelLogoutHandler oidcBackChannelLogoutHandler(OidcSessionRegistry sessionRegistry) {
        OidcBackChannelLogoutHandler logoutHandler = new OidcBackChannelLogoutHandler(sessionRegistry);
        logoutHandler.setLogoutUri(bff.getBaseUrl() + "/logout/connect/back-channel/{registrationId}");

        return logoutHandler;
    }

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver() {
        return new CustomAuthorizationRequestResolver(clientRegistrationRepository,
                bff.getAllowedRedirectUriPatterns());
    }

    private GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return new CustomGrantedAuthoritiesMapper(new RealmRolesAuthoritiesConverter());
    }

    private AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler(new CustomRedirectStrategy(), bff.getHomeUrl());
    }

    private AuthenticationFailureHandler authenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler(new CustomRedirectStrategy(), bff.getHomeUrl());
    }

    private LogoutSuccessHandler logoutSuccessHandler() {
        return new CustomLogoutSuccessHandler(
                clientRegistrationRepository,
                new CustomRedirectStrategy(),
                bff.getHomeUrl(),
                bff.getAllowedRedirectUriPatterns());
    }

    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of(bff.getAllowedOrigin()));
        config.setAllowedMethods(List.of(
                HttpMethod.GET.name(),
                HttpMethod.POST.name(),
                HttpMethod.PUT.name(),
                HttpMethod.PATCH.name(),
                HttpMethod.DELETE.name(),
                HttpMethod.OPTIONS.name()
        ));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of(HttpHeaders.LOCATION));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    private CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repo = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repo.setCookiePath("/");
        repo.setCookieCustomizer(cookie -> {
            var sessionCookie = bff.getSessionCookie();

            cookie.sameSite("Lax");
            cookie.secure(sessionCookie.isSecure());
            if (StringUtils.hasText(sessionCookie.getDomain())) {
                cookie.domain(sessionCookie.getDomain());
            }
        });

        return repo;
    }
}
