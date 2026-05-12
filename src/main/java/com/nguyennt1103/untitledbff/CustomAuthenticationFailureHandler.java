package com.nguyennt1103.untitledbff;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

import static com.nguyennt1103.untitledbff.BffConstants.POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE;
import static com.nguyennt1103.untitledbff.BffConstants.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE;

@Slf4j
public class CustomAuthenticationFailureHandler
        implements AuthenticationFailureHandler {

    private final RedirectStrategy redirectStrategy;
    private final String defaultRedirectUri;

    public CustomAuthenticationFailureHandler(RedirectStrategy redirectStrategy, String postLoginFailureUri) {
        this.redirectStrategy = redirectStrategy;
        this.defaultRedirectUri = Optional.ofNullable(postLoginFailureUri)
                .orElse("/");
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        HttpSession session = request.getSession(false);

        String redirectUri = Optional
                .ofNullable(session.getAttribute(POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE))
                .map(Objects::toString)
                .orElse(defaultRedirectUri);

        String location = UriComponentsBuilder
                .fromUriString(redirectUri)
                .queryParam(POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE, HtmlUtils.htmlEscape(exception.getMessage()))
                .build().encode().toUri()
                .toString();

        log.debug("Authentication failure. Message: {}, location: {}", exception.getMessage(), location);

        response.setHeader(POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE, exception.getMessage());

        redirectStrategy.sendRedirect(request, response, location);
    }
}
