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

//import static org.junit.jupiter.api.Assertions.*;


import net.maritimecloud.pki.ocsp.CertStatus;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

import static net.maritimecloud.pki.CertificateHandler.getCertFromPem;
import static net.maritimecloud.pki.TestUtils.getMyBoatCert;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

class CRLVerifierTest {
    @org.junit.jupiter.api.BeforeEach
    void setUp() {

    }

    @org.junit.jupiter.api.AfterEach
    void tearDown() {

    }

    @org.junit.jupiter.api.Test
    void verifyCertificateCRLs() {

    }

    @org.junit.jupiter.api.Test
    void verifyCertificateCRL() {
        X509Certificate cert = getMyBoatCert();
        RevocationInfo info = CRLVerifier.verifyCertificateCRLs(cert);
        assertNotNull(info);
        assertEquals(info.getStatus(), CertStatus.GOOD);
    }

    @org.junit.jupiter.api.Test
    void loadCRLFromFile() {
        String crlFile = "src/test/resources/mc-2017-03-23.crl";
        X509CRL crl = null;
        try {
            crl = CRLVerifier.loadCRLFromFile(crlFile);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CRLException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        assertNotNull(crl);
        assertEquals("EMAILADDRESS=info@maritimecloud.net, CN=MaritimeCloud Identity Registry Certificate, OU=MaritimeCloud Identity Registry, O=MaritimeCloud, L=Copenhagen, ST=Denmark, C=DK", crl.getIssuerDN().getName());
        assertEquals(176, crl.getRevokedCertificates().size());
    }

    @org.junit.jupiter.api.Test
    void getCrlDistributionPoints() {
        X509Certificate cert = getMyBoatCert();
        List<String> crlDistPoints = null;
        try {
            crlDistPoints = CRLVerifier.getCrlDistributionPoints(cert);
        } catch (CertificateParsingException e) {
            e.printStackTrace();
            fail("Extracting the CRL distribution point failed!");
        } catch (IOException e) {
            e.printStackTrace();
            fail("Extracting the CRL distribution point failed!");
        }
        assertNotNull(crlDistPoints);
        assertEquals(1, crlDistPoints.size());
        assertEquals("https://api.maritimecloud.net/x509/api/certificates/crl", crlDistPoints.get(0));
    }

}