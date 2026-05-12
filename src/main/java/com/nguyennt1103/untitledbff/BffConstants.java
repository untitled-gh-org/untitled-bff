package com.nguyennt1103.untitledbff;

public final class BffConstants {

    public static final String RESPONSE_STATUS_HEADER = "X-RESPONSE-STATUS";
    public static final String RESPONSE_STATUS_PARAM = "response_http_status";

    public static final String POST_AUTHENTICATION_SUCCESS_URI_HEADER = "X-POST-LOGIN-SUCCESS-URI";
    public static final String POST_AUTHENTICATION_SUCCESS_URI_PARAM = "post_login_success_uri";
    public static final String POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE =
            POST_AUTHENTICATION_SUCCESS_URI_PARAM;

    public static final String POST_AUTHENTICATION_FAILURE_URI_HEADER = "X-POST-LOGIN-FAILURE-URI";
    public static final String POST_AUTHENTICATION_FAILURE_URI_PARAM = "post_login_failure_uri";
    public static final String POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE =
            POST_AUTHENTICATION_FAILURE_URI_PARAM;
    public static final String POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE = "error";

    public static final String POST_LOGOUT_SUCCESS_URI_HEADER = "X-POST-LOGOUT-SUCCESS-URI";
    public static final String POST_LOGOUT_SUCCESS_URI_PARAM = "post_logout_success_uri";

    private BffConstants() {}
}
