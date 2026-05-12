package com.nguyennt1103.untitledbff;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.nguyennt1103.untitledbff.BffConstants.POST_LOGOUT_SUCCESS_URI_HEADER;
import static com.nguyennt1103.untitledbff.BffConstants.POST_LOGOUT_SUCCESS_URI_PARAM;

@Slf4j
public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private static final String OIDC_RP_INITIATED_LOGOUT_CONFIGURATION_ENTRY = "end_session_endpoint";
    private static final String OIDC_RP_INITIATED_LOGOUT_ID_TOKEN_HINT_REQUEST_PARAM = "id_token_hint";
    private static final String OIDC_RP_INITIATED_LOGOUT_CLIENT_ID_REQUEST_PARAM = "client_id";
    private static final String OIDC_RP_INITIATED_LOGOUT_POST_LOGOUT_URI_REQUEST_PARAM = "post_logout_redirect_uri";

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final RedirectStrategy redirectStrategy;
    private final String defaultRedirectUri;
    private final List<Pattern> allowedRedirectUriPatterns;

    public CustomLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository,
                                      RedirectStrategy redirectStrategy,
                                      String postLogoutSuccessUri,
                                      List<Pattern> allowedRedirectUriPatterns) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.redirectStrategy = redirectStrategy;
        this.defaultRedirectUri = Optional.ofNullable(postLogoutSuccessUri)
                .orElse("/");
        this.allowedRedirectUriPatterns = allowedRedirectUriPatterns;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String redirectUri = determineTargetUrl(request, response, authentication);

        log.debug("OIDC Logout success. Location: {}", redirectUri);

        redirectStrategy.sendRedirect(request, response, redirectUri);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken oauth
                && oauth.getPrincipal() instanceof OidcUser oidcUser) {
            String redirectUri = Optional
                    .ofNullable(request.getHeader(POST_LOGOUT_SUCCESS_URI_HEADER))
                    .or(() -> Optional.ofNullable(request.getParameter(POST_LOGOUT_SUCCESS_URI_PARAM)))
                    .orElse(defaultRedirectUri);

            if (this.allowedRedirectUriPatterns
                    .stream().noneMatch(p -> p.matcher(redirectUri).matches())) {
                throw new IllegalArgumentException("invalid post logout redirect uri");
            }

            ClientRegistration clientRegistration = clientRegistrationRepository
                    .findByRegistrationId(oauth.getAuthorizedClientRegistrationId());

            return getLogoutRequestUri(clientRegistration, oidcUser.getIdToken().getTokenValue(), redirectUri);
        }

        return null;
    }

    private String getLogoutRequestUri(ClientRegistration clientRegistration, String idToken, String redirectUri) {
        URI logoutEndpointUri = getLogoutEndpointUri(clientRegistration);

        return UriComponentsBuilder
                .fromUri(logoutEndpointUri)
                .queryParam(OIDC_RP_INITIATED_LOGOUT_ID_TOKEN_HINT_REQUEST_PARAM, idToken)
                .queryParam(OIDC_RP_INITIATED_LOGOUT_CLIENT_ID_REQUEST_PARAM, clientRegistration.getClientId())
                .queryParam(OIDC_RP_INITIATED_LOGOUT_POST_LOGOUT_URI_REQUEST_PARAM, redirectUri)
                .encode(StandardCharsets.UTF_8)
                .build()
                .toUriString();
    }

    private URI getLogoutEndpointUri(ClientRegistration clientRegistration) {
        Map<String, Object> oidcConfig = clientRegistration.getProviderDetails().getConfigurationMetadata();

        return Optional
                .ofNullable(oidcConfig.get(OIDC_RP_INITIATED_LOGOUT_CONFIGURATION_ENTRY))
                .map(Objects::toString)
                .map(URI::create)
                .orElseThrow(() -> new RuntimeException(("OAuth2 client registration for %s RP-Initiated Logout " +
                        "is miss configured: it is neither OIDC compliant nor define in spring-addons properties")
                        .formatted(clientRegistration.getRegistrationId())));
    }
}
