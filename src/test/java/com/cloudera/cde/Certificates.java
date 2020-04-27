package com.cloudera.cde;

import com.nimbusds.jose.util.X509CertUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;

public class Certificates {

    /**
     * Creates a self-signed X.509 certificate.
     * @param pair A public-private key pair.
     * @param signature The signature algorithm to use.
     * @param dn The distinguished name like "CN=Test, L=London, C=GB".
     * @param timeToLive The time-to-live of the certificate.
     * @return
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static X509Certificate createCertificate(KeyPair pair, SignatureAlgorithm signature, String dn, Duration timeToLive)
            throws CertificateException, IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);

        Date from = new Date();
        Date to = new Date(from.getTime() + timeToLive.toMillis());
        CertificateValidity interval = new CertificateValidity(from, to);

        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
        info.set(X509CertInfo.SUBJECT, new X500Name(dn));
        info.set(X509CertInfo.ISSUER, new X500Name(dn));
        info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

        // sign the certificate to identify the algorithm in-use
        X509CertImpl certificate = new X509CertImpl(info);
        certificate.sign(pair.getPrivate(), signature.getJcaName());

        // update the algorithm and resign
        algo = (AlgorithmId) certificate.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        certificate = new X509CertImpl(info);
        certificate.sign(pair.getPrivate(), signature.getJcaName());

        return certificate;
    }

    /**
     * Creates a PEM from an X509 certificate.
     * @param certificate The X509 certificate.
     * @return The PEM-encoded X.509 certificate.
     */
    public static String createPEM(X509Certificate certificate) {
        return X509CertUtils.toPEMString(certificate);
    }
}
