/*
 * Copyright 2017 Danish Maritime Authority.
 * Copyright 2020 Maritime Connectivity Platform Consortium
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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CertificateBuilderTest {

    private KeystoreHandler kh;

    private CertificateBuilder cb;

    @BeforeEach
    void setUp() {
        PKIConfiguration pkiConf = new PKIConfiguration(TestUtils.getRootCAAlias());
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/ca/mcp-truststore.jks");
        pkiConf.setSubCaKeystorePath("src/test/resources/ca/subca-keystore.jks");
        pkiConf.setSubCaKeystorePassword("changeit");
        pkiConf.setSubCaKeyPassword("changeit");
        kh = new KeystoreHandler(pkiConf);
        cb = new CertificateBuilder(kh);
    }

    @Test
    void generateCertForEntity() {
        KeyPair certKeyPair = CertificateBuilder.generateKeyPair(null);
        String userMrn = "urn:mrn:mcl:user:dma:thc";
        String permissions = "NONE";
        String baseCrlOcspPath = "https://localhost/x509/api/certificates/";
        String signingAlias = "urn:mrn:mcp:ca:idp1:mcp-idreg";
        int validityPeriod = 6;
        Map<String, String> attrs = new HashMap<>();
        attrs.put(PKIConstants.MC_OID_MRN, userMrn);
        attrs.put(PKIConstants.MC_OID_PERMISSIONS, permissions);
        attrs.put(PKIConstants.MC_OID_MRN_SUBSIDIARY, "urn:mrn:stm:user:dmc:thc");
        attrs.put(PKIConstants.MC_OID_HOME_MMS_URL, "http://smartnav.org/");
        X509Certificate userCert;
        try {
            userCert = cb.generateCertForEntity(BigInteger.ONE, "DK", "urn:mrn:mcl:org:dma", "user", "Thomas Christensen", "thc@dma.dk", userMrn, validityPeriod, certKeyPair.getPublic(), attrs, signingAlias, baseCrlOcspPath, null);
        } catch (Exception e) {
            fail("An exception was thrown!", e);
            return;
        }
        assertNotNull(userCert);
        assertEquals("C=DK,O=urn:mrn:mcl:org:dma,OU=user,CN=Thomas Christensen,UID=urn:mrn:mcl:user:dma:thc,E=thc@dma.dk", userCert.getSubjectDN().getName());

        // check the validity period
        Calendar cal = Calendar.getInstance();
        // Add the validity period plus an hour to get an invalid date
        cal.add(Calendar.MONTH, validityPeriod);
        cal.add(Calendar.HOUR_OF_DAY, 1);

        Date outOfBorder = cal.getTime();
        cal.add(Calendar.DAY_OF_MONTH, -1); // and minus one day from the invalid date to make it valid.
        Date withinBorder = cal.getTime();
        boolean withinBorderResult = CertificateHandler.verifyCertificate(kh.getPubKey(signingAlias), userCert, withinBorder);
        assertTrue(withinBorderResult);
        boolean outOfBorderResult = CertificateHandler.verifyCertificate(kh.getPubKey(signingAlias), userCert, outOfBorder);
        assertFalse(outOfBorderResult);
    }

    @Test
    void generateCertWithReservedCharactersForEntity() {
        KeyPair certKeyPair = CertificateBuilder.generateKeyPair(null);
        String userMrn = "urn:mrn:mcl:user:dma:thc";
        String permissions = "NONE";
        String baseCrlOcspPath = "https://localhost/x509/api/certificates/";
        String signingAlias = "urn:mrn:mcp:ca:idp1:mcp-idreg";
        int validityPeriod = 6;
        Map<String, String> attrs = new HashMap<>();
        attrs.put(PKIConstants.MC_OID_MRN, userMrn);
        attrs.put(PKIConstants.MC_OID_PERMISSIONS, permissions);
        attrs.put(PKIConstants.MC_OID_MRN_SUBSIDIARY, "urn:mrn:stm:user:dmc:thc");
        attrs.put(PKIConstants.MC_OID_HOME_MMS_URL, "http://smartnav.org/");
        X509Certificate userCert;
        try {
            // include reserved characters in some of the attributes
            userCert = cb.generateCertForEntity(BigInteger.ONE, "DK", "urn:mrn:mcl:org:dma", "user", "#Thomas Christensen, extra content ", "thc+bla@dma.dk", userMrn, validityPeriod, certKeyPair.getPublic(), attrs, signingAlias, baseCrlOcspPath, null);
        } catch (Exception e) {
            fail("An exception was thrown!", e);
            return;
        }
        assertNotNull(userCert);
        // assert that the reserved characters have been escaped
        assertEquals("C=DK,O=urn:mrn:mcl:org:dma,OU=user,CN=\\#Thomas Christensen\\, extra content\\ ,UID=urn:mrn:mcl:user:dma:thc,E=thc\\+bla@dma.dk", userCert.getSubjectDN().getName());

        // check the validity period
        Calendar cal = Calendar.getInstance();
        // Add the validity period plus an hour to get an invalid date
        cal.add(Calendar.MONTH, validityPeriod);
        cal.add(Calendar.HOUR_OF_DAY, 1);

        Date outOfBorder = cal.getTime();
        cal.add(Calendar.DAY_OF_MONTH, -1); // and minus one day from the invalid date to make it valid.
        Date withinBorder = cal.getTime();
        boolean withinBorderResult = CertificateHandler.verifyCertificate(kh.getPubKey(signingAlias), userCert, withinBorder);
        assertTrue(withinBorderResult);
        boolean outOfBorderResult = CertificateHandler.verifyCertificate(kh.getPubKey(signingAlias), userCert, outOfBorder);
        assertFalse(outOfBorderResult);
    }

    @Test
    void generateCertWithNonDefaultCountryNameForEntity() {
        KeyPair certKeyPair = CertificateBuilder.generateKeyPair(null);
        String userMrn = "urn:mrn:mcp:entity:idp1:org1:user";
        String permissions = "NONE";
        String baseCrlOcspPath = "https://localhost/x509/api/certificates/";
        String signingAlias = "urn:mrn:mcp:ca:idp1:mcp-idreg";
        int validityPeriod = 6;
        Map<String, String> attrs = new HashMap<>();
        attrs.put(PKIConstants.MC_OID_MRN, userMrn);
        attrs.put(PKIConstants.MC_OID_PERMISSIONS, permissions);

        X509Certificate userCert;
        try {
            userCert = cb.generateCertForEntity(BigInteger.ONE, "Korea (the Republic of)", "urn:mrn:mcp:entity:idp1:org1", "user", "User User", "user@example.com", userMrn, validityPeriod, certKeyPair.getPublic(), attrs, signingAlias, baseCrlOcspPath, null);
        } catch (Exception e) {
            fail("An exception was thrown!", e);
            return;
        }
        assertNotNull(userCert);

        assertEquals("C=KR,O=urn:mrn:mcp:entity:idp1:org1,OU=user,CN=User User,UID=urn:mrn:mcp:entity:idp1:org1:user,E=user@example.com", userCert.getSubjectDN().getName());
    }

    @Test
    void generateCertWithCountryCodeAsCountryNameForEntity() {
        KeyPair certKeyPair = CertificateBuilder.generateKeyPair(null);
        String userMrn = "urn:mrn:mcp:entity:idp1:org1:user";
        String permissions = "NONE";
        String baseCrlOcspPath = "https://localhost/x509/api/certificates/";
        String signingAlias = "urn:mrn:mcp:ca:idp1:mcp-idreg";
        int validityPeriod = 6;
        Map<String, String> attrs = new HashMap<>();
        attrs.put(PKIConstants.MC_OID_MRN, userMrn);
        attrs.put(PKIConstants.MC_OID_PERMISSIONS, permissions);

        X509Certificate userCert;
        try {
            userCert = cb.generateCertForEntity(BigInteger.ONE, "KR", "urn:mrn:mcp:entity:idp1:org1", "user", "User User", "user@example.com", userMrn, validityPeriod, certKeyPair.getPublic(), attrs, signingAlias, baseCrlOcspPath, null);
        } catch (Exception e) {
            fail("An exception was thrown!", e);
            return;
        }
        assertNotNull(userCert);

        assertEquals("C=KR,O=urn:mrn:mcp:entity:idp1:org1,OU=user,CN=User User,UID=urn:mrn:mcp:entity:idp1:org1:user,E=user@example.com", userCert.getSubjectDN().getName());
    }

    @Test
    void generateCertWithUnknownCountryNameForEntity() {
        KeyPair certKeyPair = CertificateBuilder.generateKeyPair(null);
        String userMrn = "urn:mrn:mcp:entity:idp1:org1:user";
        String permissions = "NONE";
        String baseCrlOcspPath = "https://localhost/x509/api/certificates/";
        String signingAlias = "urn:mrn:mcp:ca:idp1:mcp-idreg";
        int validityPeriod = 6;
        Map<String, String> attrs = new HashMap<>();
        attrs.put(PKIConstants.MC_OID_MRN, userMrn);
        attrs.put(PKIConstants.MC_OID_PERMISSIONS, permissions);

        X509Certificate userCert;
        try {
            userCert = cb.generateCertForEntity(BigInteger.ONE, "Narnia", "urn:mrn:mcp:entity:idp1:org1", "user", "User User", "user@example.com", userMrn, validityPeriod, certKeyPair.getPublic(), attrs, signingAlias, baseCrlOcspPath, null);
        } catch (Exception e) {
            fail("An exception was thrown!", e);
            return;
        }
        assertNotNull(userCert);

        assertEquals("C=XX,O=urn:mrn:mcp:entity:idp1:org1,OU=user,CN=User User,UID=urn:mrn:mcp:entity:idp1:org1:user,E=user@example.com", userCert.getSubjectDN().getName());
    }

    @Test
    void generateRootCACertHasCorrectKeyUsage() throws Exception {
        X509Certificate rootCert = buildSelfSignedCACert("ROOTCA");

        // keyCertSign and cRLSign only
        assertKeyUsage(rootCert, false, true, true);
        assertTrue(rootCert.getBasicConstraints() >= 0, "Root CA certificate must have cA=true");
        assertTrue(rootCert.getCriticalExtensionOIDs().contains(Extension.keyUsage.getId()));
        assertTrue(rootCert.getCriticalExtensionOIDs().contains(Extension.basicConstraints.getId()));
    }

    @Test
    void generateIntermediateCACertHasCorrectKeyUsage() throws Exception {
        KeyPair rootKeyPair = CertificateBuilder.generateKeyPair(null);
        KeyPair subCaKeyPair = CertificateBuilder.generateKeyPair(null);
        X509Certificate subCaCert = cb.buildAndSignCert(BigInteger.TWO, rootKeyPair.getPrivate(), rootKeyPair.getPublic(),
                subCaKeyPair.getPublic(), new X500Name("CN=Test Root CA"), new X500Name("CN=Test Intermediate CA"),
                null, "INTERMEDIATE", null, "https://localhost/crl", null, 6, null);

        // digitalSignature (for OCSP response signing), keyCertSign and cRLSign
        assertKeyUsage(subCaCert, true, true, true);
        assertTrue(subCaCert.getBasicConstraints() >= 0, "Intermediate CA certificate must have cA=true");
        assertTrue(subCaCert.getCriticalExtensionOIDs().contains(Extension.keyUsage.getId()));
        assertTrue(subCaCert.getCriticalExtensionOIDs().contains(Extension.basicConstraints.getId()));
    }

    private X509Certificate buildSelfSignedCACert(String type) throws Exception {
        KeyPair keyPair = CertificateBuilder.generateKeyPair(null);
        X500Name name = new X500Name("CN=Test Root CA");
        return cb.buildAndSignCert(BigInteger.ONE, keyPair.getPrivate(), keyPair.getPublic(), keyPair.getPublic(),
                name, name, null, type, null, "https://localhost/crl", null, 6, null);
    }

    private static void assertKeyUsage(X509Certificate cert, boolean digitalSignature, boolean keyCertSign, boolean cRLSign) {
        // Index order as defined in RFC 5280 section 4.2.1.3
        boolean[] keyUsage = cert.getKeyUsage();
        assertNotNull(keyUsage, "Certificate must have a key usage extension");
        assertEquals(digitalSignature, keyUsage[0], "digitalSignature");
        assertFalse(keyUsage[1], "nonRepudiation must not be set on CA certificates");
        assertFalse(keyUsage[2], "keyEncipherment must not be set for EC keys");
        assertFalse(keyUsage[3], "dataEncipherment must not be set for EC keys");
        assertFalse(keyUsage[4], "keyAgreement");
        assertEquals(keyCertSign, keyUsage[5], "keyCertSign");
        assertEquals(cRLSign, keyUsage[6], "cRLSign");
    }

    @Test
    void generateKeyPairTest() {
        KeyPair keyPair = CertificateBuilder.generateKeyPair(null);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    @Test
    void generateSerialNumber() {
        BigInteger sn = cb.generateSerialNumber(null);
        assertNotNull(sn);
    }

}
