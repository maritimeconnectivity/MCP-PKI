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

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import static net.maritimecloud.pki.TestUtils.getEcdisCertPem;
import static net.maritimecloud.pki.TestUtils.getMyBoatCert;
import static net.maritimecloud.pki.TestUtils.getMyBoatCertPem;
import static org.junit.jupiter.api.Assertions.*;


public class CertificateHandlerTest {
    @Test
    void verifyCertificate() {

    }

    @Test
    void getPemFromEncoded() {

    }

    @Test
    void getCertFromNginxHeader() {

    }

    @Test
    void getCertFromPem1() {
        String certPem = getMyBoatCertPem();
        X509Certificate cert = CertificateHandler.getCertFromPem(certPem);
        assertNotNull(cert);
        assertEquals(BigInteger.valueOf(193), cert.getSerialNumber());
    }

    @Test
    void getCertFromPem2() {
        String certPem = getEcdisCertPem();
        X509Certificate cert = CertificateHandler.getCertFromPem(certPem);
        assertNotNull(cert);
        assertEquals(BigInteger.valueOf(35), cert.getSerialNumber());
    }

    @Test
    void getIdentityFromCert() {
        X509Certificate cert = getMyBoatCert();

        PKIIdentity identity = CertificateHandler.getIdentityFromCert(cert);
        assertNotNull(identity);
        assertEquals("UID=urn:mrn:mcl:vessel:dma:myboat, CN=My Boat, OU=vessel, O=urn:mrn:mcl:org:dma, C=DK", identity.getDn());
        assertEquals("urn:mrn:mcl:org:dma", identity.getO());
        assertEquals("My Boat", identity.getCn());
        assertEquals("12345678", identity.getImoNumber());
        assertEquals("urn:mrn:mcl:vessel:dma:myboat", identity.getUid());
        assertEquals(null, identity.getPermissions());
    }

    @Test
    void getElement() {

    }

}