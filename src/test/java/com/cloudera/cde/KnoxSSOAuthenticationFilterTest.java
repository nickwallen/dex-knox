package com.cloudera.cde;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;

import static com.cloudera.cde.Certificates.createCertificate;
import static com.cloudera.cde.Certificates.createPEM;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class KnoxSSOAuthenticationFilterTest {
    @Mock HttpServletRequest request;
    @Mock ServletResponse response;
    @Mock FilterChain chain;
    @Mock FilterConfig filterConfig;
    String user;
    SignatureAlgorithm signature;
    KeyPair keyPair;
    X509Certificate certificate;
    String certificatePEM;
    String cookieName;
    KnoxSSOAuthenticationFilter filter;

    @BeforeEach
    void beforeEach() throws Exception {
        MockitoAnnotations.initMocks(this);
        cookieName = "hadoop-jwt";
        user = "C=US;O=Cloudera;CN=User1";
        signature = SignatureAlgorithm.RS256;
        keyPair = Keys.keyPairFor(signature);
        certificate = createCertificate(keyPair, signature, user, Duration.ofDays(1));
        certificatePEM = createPEM(certificate);
    }

    @Test
    void authenticated() throws Exception {
        String validToken = Jwts.builder()
                .setIssuedAt(now())
                .setExpiration(fromNow(Duration.ofDays(1)))
                .setSubject(user)
                .signWith(keyPair.getPrivate())
                .compact();
        setCookie(cookieName, validToken);
        execFilter();
        accessGranted();
    }

    @Test
    void tokenExpired() throws Exception {
        String expiredToken = Jwts.builder()
                .setExpiration(ago(Duration.ofDays(1)))
                .setSubject(user)
                .signWith(keyPair.getPrivate())
                .compact();
        setCookie(cookieName, expiredToken);
        execFilter();
        accessDenied();
    }

    @Test
    void tokenNotValidYet() throws Exception {
        // the token is not valid until tomorrow
        String invalidToken = Jwts.builder()
                .setNotBefore(fromNow(Duration.ofDays(1)))
                .setSubject(user)
                .signWith(keyPair.getPrivate())
                .compact();
        setCookie(cookieName, invalidToken);
        execFilter();
        accessDenied();
    }

    @Test
    void tokenNoSubject() throws Exception {
        String noSubject = Jwts.builder()
                .setIssuedAt(now())
                .setExpiration(fromNow(Duration.ofDays(1)))
                .signWith(keyPair.getPrivate())
                .compact();
        setCookie(cookieName, noSubject);
        execFilter();
        accessDenied();
    }

    @Test
    void tokenBadSignature() throws Exception {
        KeyPair differentKeyPair = Keys.keyPairFor(signature);
        String badSignature = Jwts.builder()
                .setIssuedAt(now())
                .setExpiration(fromNow(Duration.ofDays(1)))
                .setSubject(user)
                .signWith(differentKeyPair.getPrivate())
                .compact();
        setCookie(cookieName, badSignature);
        execFilter();
        accessDenied();
    }

    @Test
    void noCookie() throws Exception {
        // token not included with cookies
        execFilter();
        accessDenied();
    }

    @Test
    void wrongCookie() throws Exception {
        String validToken = Jwts.builder()
                .setIssuedAt(now())
                .setExpiration(fromNow(Duration.ofDays(1)))
                .setSubject(user)
                .signWith(keyPair.getPrivate())
                .compact();
        setCookie("wrongCookieName", validToken);
        execFilter();
        accessDenied();
    }

    private void setCookie(String cookieName, String jwtToken) {
        // embed the token in a cookie. the filter extracts the token from a cookie.
        Cookie[] cookies = new Cookie[]{new Cookie(cookieName, jwtToken)};
        when(request.getCookies()).thenReturn(cookies);
    }

    private void execFilter() throws ServletException, IOException {
        filter = new KnoxSSOAuthenticationFilter()
                .setKnoxCookieName(cookieName)
                .setKnoxCertificatePEM(certificatePEM);
        filter.init(filterConfig);
        filter.doFilter(request, response, chain);
    }

    private void accessGranted() throws Exception {
        // ensure authentication succeeded. access was granted.
        verify(chain).doFilter(request, response);
        verifyNoMoreInteractions(chain);
    }

    private void accessDenied() throws Exception {
        // ensure access was denied. the filter chain should not be called.
        verify(chain, times(0)).doFilter(request, response);
        verifyNoMoreInteractions(chain);
    }

    private Date now() {
        return new Date(System.currentTimeMillis());
    }

    private Date fromNow(Duration durationFromNow) {
        long nowMillis = System.currentTimeMillis();
        long thenMillis = nowMillis + durationFromNow.toMillis();
        return new Date(thenMillis);
    }

    private Date ago(Duration durationAgo) {
        long nowMillis = System.currentTimeMillis();
        long thenMillis = nowMillis - durationAgo.toMillis();
        return new Date(thenMillis);
    }

}
