package com.nguyennt1103.untitledbff;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.nguyennt1103.untitledbff.BffConstants.*;

public class CustomAuthorizationRequestResolver
        implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver defaultResolver;
    private final List<Pattern> allowedRedirectUriPatterns;

    public CustomAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
                                              List<Pattern> allowedRedirectUriPatterns) {
        this.defaultResolver =
                new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
                        OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);

        this.allowedRedirectUriPatterns = allowedRedirectUriPatterns;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        HttpSession session = request.getSession();

        savePostLoginUriInSession(request, session);

        return defaultResolver.resolve(request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        HttpSession session = request.getSession();

        savePostLoginUriInSession(request, session);

        return defaultResolver.resolve(request, clientRegistrationId);
    }

    private void savePostLoginUriInSession(HttpServletRequest request, HttpSession session) {
        Optional.ofNullable(request.getHeader(POST_AUTHENTICATION_SUCCESS_URI_HEADER))
                .or(() -> Optional.ofNullable(request.getParameter(POST_AUTHENTICATION_SUCCESS_URI_PARAM)))
                .filter(StringUtils::hasText)
                .filter(this::isAllowed)
                .ifPresent(uri -> session.setAttribute(POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE, uri));

        Optional.ofNullable(request.getHeader(POST_AUTHENTICATION_FAILURE_URI_HEADER))
                .or(() -> Optional.ofNullable(request.getParameter(POST_AUTHENTICATION_FAILURE_URI_PARAM)))
                .filter(StringUtils::hasText)
                .filter(this::isAllowed)
                .ifPresent(uri -> session.setAttribute(POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE, uri));
    }

    private boolean isAllowed(String uri) {
        return this.allowedRedirectUriPatterns.stream()
                .anyMatch(p -> p.matcher(uri).matches());
    }
}
