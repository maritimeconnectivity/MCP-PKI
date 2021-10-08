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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


class CertificateHandlerTest {

    @BeforeAll
    static void setUp() {
        Security.addProvider(new BouncyCastleProvider()); // Before Bouncy Castle as crypto provider
    }

    @Test
    void verifyCertificateChain1() {
        X509Certificate cert = TestUtils.getMyBoatCert();
        PKIConfiguration pkiConf = new PKIConfiguration(TestUtils.getRootCAAlias());
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mc-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);

        boolean valid = false;
        try {
            valid = CertificateHandler.verifyCertificateChain(cert, kh.getTrustStore());
        } catch (KeyStoreException | CertPathValidatorException | InvalidAlgorithmParameterException | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assertTrue(valid);
    }

    @Test
    void verifyCertificateChain2() {
        X509Certificate cert = TestUtils.getEcdisCert();
        PKIConfiguration pkiConf = new PKIConfiguration(TestUtils.getRootCAAlias());
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mc-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);

        boolean valid = false;
        String exception = "None";
        String reason = "None";
        try {
            valid = CertificateHandler.verifyCertificateChain(cert, kh.getTrustStore());
        } catch (KeyStoreException | InvalidAlgorithmParameterException | CertificateException | NoSuchAlgorithmException e) {
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
        X509Certificate cert = TestUtils.getMyBoatCert();
        PKIConfiguration pkiConf = new PKIConfiguration(TestUtils.getRootCAAlias());
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mc-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);

        boolean valid = CertificateHandler.verifyCertificate(kh.getPubKey("imcert"), cert, null);
        assertTrue(valid);
    }

    @Test
    void getPemFromEncoded() {
        X509Certificate cert = TestUtils.getMyBoatCert();
        try {
            String newlineChar = System.lineSeparator();
            String pemCertificate = CertificateHandler.getPemFromEncoded("CERTIFICATE", cert.getEncoded());
            assertEquals(pemCertificate, String.format("-----BEGIN CERTIFICATE-----%1$s" +
                    "MIID6DCCA2+gAwIBAgICAMEwCgYIKoZIzj0EAwIwgdMxCzAJBgNVBAYTAkRLMRAw%1$s" +
                    "DgYDVQQIDAdEZW5tYXJrMRMwEQYDVQQHDApDb3BlbmhhZ2VuMRYwFAYDVQQKDA1N%1$s" +
                    "YXJpdGltZUNsb3VkMSgwJgYDVQQLDB9NYXJpdGltZUNsb3VkIElkZW50aXR5IFJl%1$s" +
                    "Z2lzdHJ5MTQwMgYDVQQDDCtNYXJpdGltZUNsb3VkIElkZW50aXR5IFJlZ2lzdHJ5%1$s" +
                    "IENlcnRpZmljYXRlMSUwIwYJKoZIhvcNAQkBFhZpbmZvQG1hcml0aW1lY2xvdWQu%1$s" +
                    "bmV0MB4XDTE3MDExMzEwNTIyNVoXDTI1MDEwMTAwMDAwMFowfTELMAkGA1UEBhMC%1$s" +
                    "REsxHDAaBgNVBAoME3Vybjptcm46bWNsOm9yZzpkbWExDzANBgNVBAsMBnZlc3Nl%1$s" +
                    "bDEQMA4GA1UEAwwHTXkgQm9hdDEtMCsGCgmSJomT8ixkAQEMHXVybjptcm46bWNs%1$s" +
                    "OnZlc3NlbDpkbWE6bXlib2F0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEx8Dz55UD%1$s" +
                    "4GzAHVOM7DB76/Abig+rQl8mLgEqFNCk8ZzbG8VryMmIWIq2j4dJqsGqwwAqFcJl%1$s" +
                    "vchJdx5Hz1brSbffCBwGJ4QqhxJm85NQx4vU6iWiP3o0nDC11enk1lppo4IBaTCC%1$s" +
                    "AWUwHwYDVR0jBBgwFoAUWDdhX43k8x4PdkyZx3OiZdl1FjIwHQYDVR0OBBYEFGYx%1$s" +
                    "dChhVfJWPcQa6rx+Tj1vXRraMIGCBgNVHREEezB5oCIGFGmDtqOX2Juv+MfLmeyA%1$s" +
                    "gKqu14oboAoMCDEyMzQ1Njc4oBoGFGmChru7yJuwqMfLntmAgKqu14oboAIMAKA3%1$s" +
                    "BhRpg5i818Ce8PDHy6qdgICqrteKG6AfDB11cm46bXJuOm1jbDp2ZXNzZWw6ZG1h%1$s" +
                    "Om15Ym9hdDBIBgNVHR8EQTA/MD2gO6A5hjdodHRwczovL2FwaS5tYXJpdGltZWNs%1$s" +
                    "b3VkLm5ldC94NTA5L2FwaS9jZXJ0aWZpY2F0ZXMvY3JsMFQGCCsGAQUFBwEBBEgw%1$s" +
                    "RjBEBggrBgEFBQcwAYY4aHR0cHM6Ly9hcGkubWFyaXRpbWVjbG91ZC5uZXQveDUw%1$s" +
                    "OS9hcGkvY2VydGlmaWNhdGVzL29jc3AwCgYIKoZIzj0EAwIDZwAwZAIwIyCgTm1W%1$s" +
                    "dc8VlwF5RNYVziG5KWJw+YVO5MirhcISDnPNkUAabZzDwNPUoIZImRaCAjB8MIF6%1$s" +
                    "laWn9dLCvirTEuYJDSS3x9DJzIiQa/aJRSLSuFDu/g6Dw5TmQGbl5kg5Crs=%1$s" +
                    "-----END CERTIFICATE-----%1$s", newlineChar));
        } catch (CertificateEncodingException e) {
            fail("Unexpected Exception", e);
        }

    }

    @Test
    void createOutputKeystore1() {
        FileInputStream is;
        try {
            is = new FileInputStream("src/test/resources/mc-sub-ca-keystore.jks");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        KeyStore keystore;
        X509Certificate cert;
        PrivateKey privateKey;
        try {
            keystore = KeyStore.getInstance("JKS");
            keystore.load(is, "changeit".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("changeit".toCharArray());
            KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry) keystore.getEntry("urn:mrn:mcl:ca:maritimecloud-idreg", protParam);
            cert = (X509Certificate) key.getCertificate();
            privateKey = key.getPrivateKey();
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        byte[] p12Keystore = CertificateHandler.createOutputKeystore("PKCS12","urn:mrn:mcl:ca:maritimecloud-idreg", "changeit", privateKey, cert);
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(p12Keystore);
            keystore = KeyStore.getInstance("PKCS12");
            keystore.load(inputStream, "changeit".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("changeit".toCharArray());
            KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry) keystore.getEntry("urn:mrn:mcl:ca:maritimecloud-idreg", protParam);
            X509Certificate certP12 = (X509Certificate) key.getCertificate();
            assertEquals(certP12.getSubjectDN().toString(), cert.getSubjectDN().toString());

        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Test
    void createOutputKeystore2() {
        FileInputStream is;
        try {
            is = new FileInputStream("src/test/resources/mc-sub-ca-keystore.jks");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        KeyStore keystore;
        X509Certificate cert;
        PrivateKey privateKey;
        try {
            keystore = KeyStore.getInstance("JKS");
            keystore.load(is, "changeit".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("changeit".toCharArray());
            KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry) keystore.getEntry("urn:mrn:mcl:ca:maritimecloud-idreg", protParam);
            cert = (X509Certificate) key.getCertificate();
            privateKey = key.getPrivateKey();
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        byte[] jksKeystore = CertificateHandler.createOutputKeystore("JKS","urn:mrn:mcl:ca:maritimecloud-idreg", "changeit", privateKey, cert);
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(jksKeystore);
            keystore = KeyStore.getInstance("JKS");
            keystore.load(inputStream, "changeit".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("changeit".toCharArray());
            KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry) keystore.getEntry("urn:mrn:mcl:ca:maritimecloud-idreg", protParam);
            X509Certificate certJks = (X509Certificate) key.getCertificate();
            assertEquals(certJks.getSubjectDN().toString(), cert.getSubjectDN().toString());

        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }


    @Test
    void getCertFromNginxHeader() {
        String nginxFormatedPemCert = TestUtils.loadTxtFile("src/test/resources/thc-cert-nginx-format.pem");
        X509Certificate cert = null;
        try {
            cert = CertificateHandler.getCertFromNginxHeader(nginxFormatedPemCert);
        } catch (UnsupportedEncodingException e) {
            fail("Could not decode certificate", e);
        }
        assertNotNull(cert);
        assertEquals("EMAILADDRESS=thc@dma.dk, UID=urn:mrn:mcl:user:dma:thc, CN=Thomas Christensen, OU=user, O=urn:mrn:mcl:org:dma, C=DK", cert.getSubjectDN().getName());
    }

    @Test
    void getCertFromPem1() {
        String certPem = TestUtils.getMyBoatCertPem();
        X509Certificate cert = CertificateHandler.getCertFromPem(certPem);
        assertNotNull(cert);
        assertEquals(BigInteger.valueOf(193), cert.getSerialNumber());
    }

    @Test
    void getCertFromPem2() {
        String certPem = TestUtils.getEcdisCertPem();
        X509Certificate cert = CertificateHandler.getCertFromPem(certPem);
        assertNotNull(cert);
        assertEquals(BigInteger.valueOf(35), cert.getSerialNumber());
    }

    @Test
    void getIdentityFromCert() {
        X509Certificate cert = TestUtils.getMyBoatCert();

        PKIIdentity identity = CertificateHandler.getIdentityFromCert(cert);
        assertNotNull(identity);
        assertEquals("UID=urn:mrn:mcl:vessel:dma:myboat, CN=My Boat, OU=vessel, O=urn:mrn:mcl:org:dma, C=DK", identity.getDn());
        assertEquals("urn:mrn:mcl:org:dma", identity.getO());
        assertEquals("My Boat", identity.getCn());
        assertEquals("12345678", identity.getImoNumber());
        assertEquals("urn:mrn:mcl:vessel:dma:myboat", identity.getMrn());
        assertNull(identity.getPermissions());
    }

    @Test
    void getIdentityFromCertWithEscapedCharacters() {
        X509Certificate cert = TestUtils.getTestUserCert();

        String certDN = cert.getSubjectDN().getName();
        X500Name x500Name = new X500Name(certDN);
        String email = CertificateHandler.getElement(x500Name, BCStyle.EmailAddress);
        assertEquals("info\\+test@maritimeconnectivity.net", email);

        PKIIdentity identity = CertificateHandler.getIdentityFromCert(cert);
        assertNotNull(identity);
        assertEquals("info+test@maritimeconnectivity.net", identity.getEmail());
    }

}
