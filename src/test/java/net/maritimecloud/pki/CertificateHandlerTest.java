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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static net.maritimecloud.pki.TestUtils.*;
import static org.junit.jupiter.api.Assertions.*;


public class CertificateHandlerTest {

    //@Test
    void verifyCertificateChain1() {
        X509Certificate cert = getMyBoatCert();
        PKIConfiguration pkiConf = new PKIConfiguration();
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mc-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);

        boolean valid = false;
        try {
            valid = CertificateHandler.verifyCertificateChain(cert, kh.getTrustStore());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CertPathValidatorException e) {
            e.printStackTrace();
        }
        assertTrue(valid);
    }

    @Test
    void verifyCertificateChain2() {
        X509Certificate cert = getEcdisCert();
        PKIConfiguration pkiConf = new PKIConfiguration();
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mc-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);

        boolean valid = false;
        String exception = "None";
        String reason = "None";
        try {
            valid = CertificateHandler.verifyCertificateChain(cert, kh.getTrustStore());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CertPathValidatorException e) {
            reason = e.getReason().toString();
            exception = "CertPathValidatorException";
        }
        assertFalse(valid);
        assertEquals("CertPathValidatorException", exception);
        assertEquals("NO_TRUST_ANCHOR", reason);
    }


    @Test
    void verifyCertificate() {
        X509Certificate cert = getMyBoatCert();
        PKIConfiguration pkiConf = new PKIConfiguration();
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mc-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);

        boolean valid = CertificateHandler.verifyCertificate(kh.getPubKey("imcert"), cert, null);
        assertTrue(valid);
    }

    @Test
    void getPemFromEncoded() {

    }

    @Test
    void getCertFromNginxHeader() {
        String nginxFormatedPemCert = TestUtils.loadTxtFile("src/test/resources/thc-cert-nginx-format.pem");
        X509Certificate cert = CertificateHandler.getCertFromNginxHeader(nginxFormatedPemCert);
        assertNotNull(cert);
        assertEquals("EMAILADDRESS=thc@dma.dk, UID=urn:mrn:mcl:user:dma:thc, CN=Thomas Christensen, OU=user, O=urn:mrn:mcl:org:dma, C=DK", cert.getSubjectDN().getName());
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
        assertEquals("urn:mrn:mcl:vessel:dma:myboat", identity.getMrn());
        assertEquals(null, identity.getPermissions());
    }

    @Test
    void getElement() {

    }

}