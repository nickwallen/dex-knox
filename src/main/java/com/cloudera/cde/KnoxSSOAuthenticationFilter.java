package com.cloudera.cde;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import jdk.nashorn.internal.runtime.ParserException;
import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.Objects;

/**
 * A servlet filter that authenticates a Knox SSO token.
 *
 * <p>The token is stored in a cookie and is validated against the Knox public key. The
 * token begin and expiration times are also validated.
 */
public class KnoxSSOAuthenticationFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(KnoxSSOAuthenticationFilter.class);
    private static final String AUTH_HEADER = "Authorization";
    private static final String BASIC_AUTH_PREFIX = "Basic";
    private static final JWSAlgorithm DEFAULT_WEB_SIGNATURE = JWSAlgorithm.RS256;

    // max clock skew
    private static final String MAX_CLOCK_SKEW_CONFIG = "max.clock.skew.seconds";
    private static final long DEFAULT_MAX_CLOCK_SKEW = 60;
    private long maxClockSkewSeconds;

    // knox x509 certificate
    private static final String KNOX_CERTIFICATE_CONFIG = "knox.certificate.pem";
    private static final String DEFAULT_KNOX_CERTIFICATE = "";
    private String knoxCertificatePEM;
    private X509Certificate knoxCertificate;

    // knox cookie name
    private static final String KNOX_COOKIE_NAME_CONFIG = "knox.cookie.name";
    private static final String DEFAULT_KNOX_COOKIE_NAME = "hadoop-jwt";
    private String knoxCookieName;

    public KnoxSSOAuthenticationFilter() {
        maxClockSkewSeconds = DEFAULT_MAX_CLOCK_SKEW;
        knoxCertificatePEM = DEFAULT_KNOX_CERTIFICATE;
        knoxCookieName = DEFAULT_KNOX_COOKIE_NAME;
    }

    public KnoxSSOAuthenticationFilter setMaxClockSkewSeconds(long maxClockSkewSeconds) {
        this.maxClockSkewSeconds = maxClockSkewSeconds;
        return this;
    }

    public String getKnoxCookieName() {
        return knoxCookieName;
    }

    public KnoxSSOAuthenticationFilter setKnoxCertificatePEM(String knoxCertificatePEM) {
        this.knoxCertificatePEM = knoxCertificatePEM;
        return this;
    }

    public KnoxSSOAuthenticationFilter setKnoxCookieName(String knoxCookieName) {
        this.knoxCookieName = knoxCookieName;
        return this;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // set the max clock skew
        String value = filterConfig.getInitParameter(MAX_CLOCK_SKEW_CONFIG);
        if (NumberUtils.isParsable(value)) {
            setMaxClockSkewSeconds(Long.parseLong(value));
        }
        logger.debug("Initializing filter with {}={}", MAX_CLOCK_SKEW_CONFIG, maxClockSkewSeconds);

        // set the knox cookie
        value = filterConfig.getInitParameter(KNOX_COOKIE_NAME_CONFIG);
        if (StringUtils.isNotBlank(value)) {
            setKnoxCookieName(value);
        }
        logger.debug("Initializing filter with {}={}", KNOX_COOKIE_NAME_CONFIG, knoxCookieName);

        // set the knox certificate
        value = filterConfig.getInitParameter(KNOX_CERTIFICATE_CONFIG);
        if (StringUtils.isNotBlank(value)) {
            setKnoxCertificatePEM(value);
        }
        logger.debug("Initializing filter with {}={}", KNOX_CERTIFICATE_CONFIG, knoxCertificatePEM);

        // verify the knox certificate
        try {
            knoxCertificate = parseCertificate(knoxCertificatePEM);
        } catch(CertificateException e) {
            throw new ServletException("Invalid Knox certificate. Cannot authenticate users.", e);
        }
    }

    @Override
    public void destroy() {
        // nothing to do
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("Expected HTTP request, but got " + ClassUtils.getCanonicalName(request));
        }
        // cast acceptable due to check above
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        // if a basic authentication header is present, use that to authenticate and skip SSO
        String authHeader = httpRequest.getHeader(AUTH_HEADER);
        if (authHeader == null || !authHeader.startsWith(BASIC_AUTH_PREFIX)) {
            boolean ok = authenticate(httpRequest);
            if(ok) {
                // authentication successful
                chain.doFilter(request, response);
            }
        }

        // otherwise, authentication failed
        // TODO what to do here?  success or failure?
        return;
    }

    /**
     * Performs authentication.
     * @param httpRequest The HTTP request.
     * @return True, if authentication is successful. Otherwise, false.
     */
    public boolean authenticate(HttpServletRequest httpRequest) {
        // the token is stored as a cookie
        String cookieValue = getTokenFromCookie(knoxCookieName, httpRequest);
        if (cookieValue == null) {
            logger.info("No cookies found. Expected to find {}. Authentication failed.", knoxCookieName);
            return false;
        }

        // parse the token
        SignedJWT token;
        try {
            token = SignedJWT.parse(cookieValue);
        } catch (ParseException e) {
            logger.info("Failed to parse the token. Authentication failed.", e);
            return false;
        }

        // validate the token
        return isValid(token);
    }

    /**
     * Validates a JWT token.
     * @param token The token to validate.
     * @return True, if the token is valid. Otherwise, false.
     */
    protected boolean isValid(SignedJWT token) {
        Date now = new Date();

        // the token must have claims
        JWTClaimsSet claims;
        try {
            claims = token.getJWTClaimsSet();
        } catch(ParseException e) {
            logger.info("Token has no claims. Authentication failed.", e);
            return false;
        }

        // verify the user name
        String username = claims.getSubject();
        if (username == null || username.isEmpty()) {
            logger.info("Token has no user. Authentication failed.");
            return false;
        }

        // verify that the token has not expired
        Date expirationTime = claims.getExpirationTime();
        if (expirationTime != null && DateUtils.isBefore(expirationTime, now, maxClockSkewSeconds)) {
            logger.info("Token has expired at {}.", expirationTime);
            return false;
        }

        // verify the token is valid according to the 'not before' time
        Date notBeforeTime = claims.getNotBeforeTime();
        if (notBeforeTime != null && DateUtils.isAfter(notBeforeTime, now, maxClockSkewSeconds)) {
            logger.info("Token will be valid after {}. Authentication failed.", notBeforeTime);
            return false;
        }

        // verify token signature algorithm
        String signature = token.getHeader().getAlgorithm().getName();
        if (!StringUtils.equals(signature, DEFAULT_WEB_SIGNATURE.getName())) {
            logger.info("Expected token to use {}, but got {}.", DEFAULT_WEB_SIGNATURE.getName(), signature);
            return false;
        }

        // verify token state
        if (token.getState() != JWSObject.State.SIGNED) {
            logger.info("Token state is {}, but expected SIGNED. Authentication failed.", token.getState());
            return false;
        }

        // verify token signature exists
        if (token.getSignature() == null) {
            logger.info("Token signature is missing. Authentication failed.");
            return false;
        }

        // verify the token signature
        PublicKey publicKey = knoxCertificate.getPublicKey();
        if(publicKey == null || !(publicKey instanceof RSAPublicKey)) {
            logger.info("Expected RSA public key, but got {}", publicKey);
            return false;
        }

        try {
            // cast acceptable due to the instanceof check above
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            boolean ok = token.verify(verifier);
            if(ok) {
                logger.info("Verified token signature successfully. Authentication successful.");
                return true;
            }
        } catch (JOSEException e) {
            logger.info("Unable to verify token signature. Authentication failed.", e);
            return false;
        }

        logger.info("Unable to verify token signature. Authentication failed.");
        return false;
    }

    private String getTokenFromCookie(String cookieName, HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie: cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        // the cookie was not found
        return null;
    }

    private X509Certificate parseCertificate(String pem) throws CertificateException {
        Objects.requireNonNull(pem, "Knox certificate PEM has not been defined.");
        return X509CertUtils.parseWithException(pem);
    }
}
