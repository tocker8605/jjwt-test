package my.tocker.jwt.config.filter;

public class SecurityConstants {
    static final String SECRET = "tockersecret";
    static final long EXPIRATION_TIME = 28_800_000; // 8hours
    static final String TOKEN_PREFIX = "Bearer ";
    static final String HEADER_STRING = "Authorization";
    public static final String SIGNUP_URL = "/user/signup";
    public static final String LOGIN_URL = "/user/login";
    static final String LOGIN_ID = "loginId"; // defalut:username
    static final String PASSWORD = "pass"; // default:password
}
