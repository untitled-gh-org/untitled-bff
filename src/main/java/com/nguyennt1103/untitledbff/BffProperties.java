package com.nguyennt1103.untitledbff;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

@Data
@ConfigurationProperties(prefix = "bff")
public class BffProperties {

    private String homeUrl;
    private String clientUrl;
    private String loginUrl;

    private SessionCookie sessionCookie = new SessionCookie();

    @Data
    public static class SessionCookie {
        private String domain;
        private boolean secure;
    }

    public String getBaseUrl() {
        return getSchemeAndAuthority(clientUrl);
    }

    public String getAllowedOrigin() {
        return getSchemeAndAuthority(homeUrl);
    }

    public List<Pattern> getAllowedRedirectUriPatterns() {
        return List.of(
                toPattern(homeUrl),
                toPattern(clientUrl),
                Pattern.compile("^/[^/].*")
        );
    }

    private Pattern toPattern(String baseUrl) {
        return Pattern.compile("^" + Pattern.quote(baseUrl) + "(/.*)?$");
    }

    private String getSchemeAndAuthority(String url) {
        return Optional
                .ofNullable(url)
                .map(URI::create)
                .map(uri -> "%s://%s".formatted(uri.getScheme(), uri.getAuthority()))
                .orElseThrow(() -> new IllegalArgumentException("url must not be null"));
    }
}
