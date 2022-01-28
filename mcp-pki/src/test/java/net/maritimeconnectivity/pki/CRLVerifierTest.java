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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import static net.maritimeconnectivity.pki.TestUtils.getEcdisCert;
import static net.maritimeconnectivity.pki.TestUtils.getMyBoatCert;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

class CRLVerifierTest {
    @BeforeEach
    void setUp() {

    }

    @AfterEach
    void tearDown() {

    }

    //@Test
    void verifyCertificateCRL1() {
        X509Certificate cert = getMyBoatCert();
        RevocationInfo info = CRLVerifier.verifyCertificateCRL(cert);
        assertNotNull(info);
        assertEquals(CertStatus.GOOD, info.getStatus());
    }

    //@Test
    void verifyCertificateCRL2() {
        X509Certificate cert = getEcdisCert();
        RevocationInfo info = CRLVerifier.verifyCertificateCRL(cert);
        assertNotNull(info);
        assertEquals(CertStatus.REVOKED, info.getStatus());
    }

    @Test
    void verifyCertificateCRL3() {
        X509Certificate cert = getMyBoatCert();
        String crlFile = "src/test/resources/mc-2017-03-23.crl";
        X509CRL crl = null;
        try {
            crl = CRLVerifier.loadCRLFromFile(crlFile);
        } catch (IOException | CRLException | CertificateException e) {
            e.printStackTrace();
        }
        RevocationInfo info = CRLVerifier.verifyCertificateCRL(cert, crl);
        assertNotNull(info);
        assertEquals(CertStatus.GOOD, info.getStatus());
    }

    @Test
    void verifyCertificateCRL4() {
        X509Certificate cert = getEcdisCert();
        String crlFile = "src/test/resources/mc-2017-03-23.crl";
        X509CRL crl = null;
        try {
            crl = CRLVerifier.loadCRLFromFile(crlFile);
        } catch (IOException | CRLException | CertificateException e) {
            e.printStackTrace();
        }
        RevocationInfo info = CRLVerifier.verifyCertificateCRL(cert, crl);
        assertNotNull(info);
        assertEquals(CertStatus.REVOKED, info.getStatus());
    }

    @Test
    void loadCRLFromFile() {
        String crlFile = "src/test/resources/mc-2017-03-23.crl";
        X509CRL crl = null;
        try {
            crl = CRLVerifier.loadCRLFromFile(crlFile);
        } catch (IOException | CRLException | CertificateException e) {
            e.printStackTrace();
        }
        assertNotNull(crl);
        assertEquals("EMAILADDRESS=info@maritimecloud.net, CN=MaritimeCloud Identity Registry Certificate, OU=MaritimeCloud Identity Registry, O=MaritimeCloud, L=Copenhagen, ST=Denmark, C=DK", crl.getIssuerDN().getName());
        assertEquals(176, crl.getRevokedCertificates().size());
    }

    @Test
    void getCrlDistributionPoints() {
        X509Certificate cert = getMyBoatCert();
        List<String> crlDistPoints = null;
        try {
            crlDistPoints = CRLVerifier.getCrlDistributionPoints(cert);
        } catch (IOException e) {
            e.printStackTrace();
            fail("Extracting the CRL distribution point failed!");
        }
        assertNotNull(crlDistPoints);
        assertEquals(1, crlDistPoints.size());
        assertEquals("https://api.maritimecloud.net/x509/api/certificates/crl", crlDistPoints.get(0));
    }

}
