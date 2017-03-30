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
package net.maritimecloud.pki;

import net.maritimecloud.pki.ocsp.CertStatus;
import net.maritimecloud.pki.ocsp.OCSPClient;
import net.maritimecloud.pki.ocsp.OCSPValidationException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URL;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

import static net.maritimecloud.pki.TestUtils.getEcdisCert;
import static net.maritimecloud.pki.TestUtils.getMyBoatCert;
import static org.junit.jupiter.api.Assertions.*;


class OCSPVerifierTest {
    //@Test
    void verifyCertificateOCSP1() {
        X509Certificate cert = getMyBoatCert();
        PKIConfiguration pkiConf = new PKIConfiguration();
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mc-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);
        RevocationInfo info = null;
        try {
            info = OCSPVerifier.verifyCertificateOCSP(cert, kh.getTrustStore());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (OCSPValidationException e) {
            e.printStackTrace();
        }
        assertEquals(CertStatus.GOOD, info.getStatus());
    }

    //@Test
    void verifyCertificateOCSP2() {
        X509Certificate cert = getEcdisCert();
        PKIConfiguration pkiConf = new PKIConfiguration();
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mc-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);
        RevocationInfo info = null;
        try {
            info = OCSPVerifier.verifyCertificateOCSP(cert, kh.getTrustStore());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (OCSPValidationException e) {
            e.printStackTrace();
        }
        assertEquals(CertStatus.REVOKED, info.getStatus());
    }

    @Test
    void getOcspUrl1() {
        X509Certificate cert = getMyBoatCert();
        URL ocspUrl = ocspUrl = OCSPClient.getOcspUrlFromCertificate(cert);
        assertNotNull(ocspUrl);
        assertEquals("https://api.maritimecloud.net/x509/api/certificates/ocsp", ocspUrl.toString());
    }

    @Test
    void getOcspUrl2() {
        X509Certificate cert = getEcdisCert();
        URL ocspUrl = ocspUrl = OCSPClient.getOcspUrlFromCertificate(cert);
        assertNotNull(ocspUrl);
        assertEquals("https://api.maritimecloud.net/x509/api/certificates/ocsp", ocspUrl.toString());
    }

}