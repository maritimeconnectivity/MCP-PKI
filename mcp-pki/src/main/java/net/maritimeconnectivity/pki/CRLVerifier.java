/*
 * Copyright 2017 Danish Maritime Authority.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

// Copied from Apache Xcf 2.4, with some updates and added functionality

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package net.maritimeconnectivity.pki;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.pki.ocsp.CertStatus;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

/**
 * Class that contains functions for retrieving and verifying certificate revocation lists
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CRLVerifier {

    /**
     * Extracts the CRL distribution points from the certificate (if available)
     * and checks the certificate revocation status against the CRLs coming from
     * the distribution points. Supports HTTP, HTTPS, FTP and LDAP based URLs.
     *
     * @param cert Certificate to verify
     * @return a RevocationInfo object with the validation result
     */
    public static RevocationInfo verifyCertificateCRL(X509Certificate cert) {
        try {
            List<String> crlDistPoints = getCrlDistributionPoints(cert);
            for (String crlDP : crlDistPoints) {
                X509CRL crl = downloadCRL(crlDP);
                if (crl.isRevoked(cert)) {
                    X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
                    return new RevocationInfo(entry.getSerialNumber(), entry.getRevocationReason(), entry.getRevocationDate(), CertStatus.REVOKED);
                }
            }
            return new RevocationInfo(cert.getSerialNumber(), null, null, CertStatus.GOOD);
        } catch (Exception ex) {
            log.error("An Exception was thrown during CRL verification!", ex);
            return new RevocationInfo(cert.getSerialNumber(), null, null, CertStatus.UNKNOWN);
        }
    }

    /**
     * Verifies the revocation status of a certificate against a CRL
     *
     * @param cert The certificate to verify
     * @param crl The CRL to use for verifying
     * @return a RevocationInfo object with the validation result
     */
    public static RevocationInfo verifyCertificateCRL(X509Certificate cert, X509CRL crl) {
        try {
            if (crl.isRevoked(cert)) {
                X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
                return new RevocationInfo(entry.getSerialNumber(), entry.getRevocationReason(), entry.getRevocationDate(), CertStatus.REVOKED);
            } else {
                return new RevocationInfo(cert.getSerialNumber(), null, null, CertStatus.GOOD);
            }
        } catch (Exception ex) {
            log.error("An Exception was thrown during CRL verification!", ex);
            return new RevocationInfo(cert.getSerialNumber(), null, null, CertStatus.UNKNOWN);
        }
    }

    /**
     * Downloads CRL from given URL. Supports http, https, ftp and ldap based URLs.
     *
     * @param crlURL The URL for downloading the CRL
     * @return a CRL
     * @throws IOException if a connection cannot be opened based on the given URL
     * @throws CertificateException if the retrieved CRL cannot be instantiated as a Java object
     * @throws NamingException if downloading CRL from ldap fails
     * @throws CRLException if the retrieved CRL cannot be instantiated as a Java object
     */
    public static X509CRL downloadCRL(String crlURL) throws IOException, CertificateException, NamingException, CRLException {
        if (crlURL.startsWith("http://") || crlURL.startsWith("https://") || crlURL.startsWith("ftp://")) {
            return downloadCRLFromWeb(crlURL);
        } else if (crlURL.startsWith("ldap://")) {
            return downloadCRLFromLDAP(crlURL);
        } else {
            throw new CRLException("Cannot download CRL from certificate distribution point: " + crlURL);
        }
    }

    /**
     * Downloads a CRL from given LDAP url, e.g.
     * ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
     *
     * @param ldapURL The URL for downloading the CRL from a ldap server
     * @return a CRL
     * @throws NamingException if downloading CRL from ldap fails
     * @throws CertificateException if a CertificateFactory cannot be instantiated
     * @throws CRLException if the retrieved CRL cannot be instantiated as a Java object
     */
    public static X509CRL downloadCRLFromLDAP(String ldapURL) throws NamingException, CertificateException, CRLException {
        Map<String, String> env = new HashMap<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        DirContext ctx = new InitialDirContext(new Hashtable<>(env));
        Attributes avals = ctx.getAttributes("");
        Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[]) aval.get();
        if ((val == null) || (val.length == 0)) {
            throw new CRLException("Can not download CRL from: " + ldapURL);
        } else {
            InputStream inStream = new ByteArrayInputStream(val);
            CertificateFactory cf = CertificateFactory.getInstance(PKIConstants.X509);
            return (X509CRL) cf.generateCRL(inStream);
        }
    }

    /**
     * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
     * http://crl.infonotary.com/crl/identity-ca.crl
     *
     * @param crlURL The URL for downloading the CRL
     * @return a CRL
     * @throws IOException if a connection cannot be opened based on the given URL
     * @throws CertificateException if a CertificateFactory cannot be instantiated
     * @throws CRLException if the retrieved CRL cannot be instantiated as a Java object
     */
    public static X509CRL downloadCRLFromWeb(String crlURL) throws IOException, CRLException, CertificateException {
        URL url = new URL(crlURL);
        try (InputStream crlStream = url.openStream()) {
            CertificateFactory cf = CertificateFactory.getInstance(PKIConstants.X509);
            return (X509CRL) cf.generateCRL(crlStream);
        }
    }

    /**
     * Load a CRL from given file
     *
     * @param path The path of the file that contains the CRL
     * @return a CRL
     * @throws IOException if the file cannot be opened
     * @throws CRLException if the loaded CRL cannot be instantiated as a Java object
     * @throws CertificateException if a CertificateFactory cannot be instantiated
     */
    public static X509CRL loadCRLFromFile(String path) throws IOException, CRLException, CertificateException {
        try (FileInputStream fis = new FileInputStream(path)) {
            CertificateFactory cf = CertificateFactory.getInstance(PKIConstants.X509);
            return (X509CRL) cf.generateCRL(fis);
        }
    }

    /**
     * Extracts all CRL distribution point URLs from the
     * "CRL Distribution Point" extension in a X.509 certificate. If CRL
     * distribution point extension is unavailable, returns an empty list.
     *
     * @param cert The certificate that should be used for extracting the distribution points
     * @return a list CRL distribution points
     * @throws IOException if the given certificate cannot be read
     */
    public static List<String> getCrlDistributionPoints(X509Certificate cert) throws IOException {
        byte[] crldpExt = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crldpExt == null) {
            return new ArrayList<>();
        }
        ASN1InputStream oAsnInStream2;
        CRLDistPoint crlDistPoint;
        try (ASN1InputStream oAsnInStream = new ASN1InputStream(crldpExt)) {
            DEROctetString dosCrlDP = (DEROctetString) oAsnInStream.readObject();
            byte[] crldpExtOctets = dosCrlDP.getOctets();
            oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
            crlDistPoint = CRLDistPoint.getInstance(oAsnInStream2.readObject());
            oAsnInStream2.close();
        }
        List<String> crlUrls = new ArrayList<>();
        for (DistributionPoint dp : crlDistPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                // Look for an URI
                for (GeneralName genName : genNames) {
                    if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = ASN1IA5String.getInstance(genName.getName()).getString();
                        crlUrls.add(url);
                    }
                }
            }
        }
        return crlUrls;
    }

}
