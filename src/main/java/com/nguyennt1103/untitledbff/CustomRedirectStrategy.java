package com.nguyennt1103.untitledbff;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.RedirectStrategy;

import java.util.Optional;

import static com.nguyennt1103.untitledbff.BffConstants.RESPONSE_STATUS_HEADER;
import static com.nguyennt1103.untitledbff.BffConstants.RESPONSE_STATUS_PARAM;

public class CustomRedirectStrategy implements RedirectStrategy {

    @Override
    public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) {
        int statusHeader = request.getIntHeader(RESPONSE_STATUS_HEADER);
        int statusParam = Integer.parseInt(Optional
                .ofNullable(request.getParameter(RESPONSE_STATUS_PARAM))
                .orElse("-1"));

        int status = statusHeader > -1 ? statusHeader : (statusParam > -1 ? statusParam : 302);

        response.setStatus(status);
        response.setHeader(HttpHeaders.LOCATION, url);
    }
}
