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
package net.maritimeconnectivity.pki;

import net.maritimeconnectivity.pki.ocsp.CertStatus;
import net.maritimeconnectivity.pki.ocsp.OCSPClient;
import net.maritimeconnectivity.pki.ocsp.OCSPValidationException;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class OCSPVerifierTest {
    //@Test
    void verifyCertificateOCSP1() {
        X509Certificate cert = TestUtils.getMyBoatCert();
        PKIConfiguration pkiConf = new PKIConfiguration(TestUtils.getRootCAAlias());
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mc-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);
        RevocationInfo info = null;
        try {
            info = OCSPVerifier.verifyCertificateOCSP(cert, kh.getTrustStore());
        } catch (KeyStoreException | OCSPValidationException e) {
            e.printStackTrace();
        }
        assertNotNull(info);
        assertEquals(CertStatus.GOOD, info.getStatus());
    }

    //@Test
    void verifyCertificateOCSP2(String rootCAAlias) {
        X509Certificate cert = TestUtils.getEcdisCert();
        PKIConfiguration pkiConf = new PKIConfiguration(rootCAAlias);
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mc-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);
        RevocationInfo info = null;
        try {
            info = OCSPVerifier.verifyCertificateOCSP(cert, kh.getTrustStore());
        } catch (KeyStoreException | OCSPValidationException e) {
            e.printStackTrace();
        }
        assertNotNull(info);
        assertEquals(CertStatus.REVOKED, info.getStatus());
    }

    @Test
    void getOcspUrl1() {
        X509Certificate cert = TestUtils.getMyBoatCert();
        URL ocspUrl = OCSPClient.getOcspUrlFromCertificate(cert);
        assertNotNull(ocspUrl);
        assertEquals("http://localhost:8888/x509/api/certificates/ocsp/urn:mrn:mcp:ca:idp1:mcp-idreg", ocspUrl.toString());
    }

    @Test
    void getOcspUrl2() {
        X509Certificate cert = TestUtils.getEcdisCert();
        URL ocspUrl = OCSPClient.getOcspUrlFromCertificate(cert);
        assertNotNull(ocspUrl);
        assertEquals("http://localhost:8888/x509/api/certificates/ocsp/urn:mrn:mcp:ca:idp1:mcp-idreg", ocspUrl.toString());
    }

}
