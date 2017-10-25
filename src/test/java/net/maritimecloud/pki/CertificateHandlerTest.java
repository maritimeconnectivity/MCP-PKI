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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static net.maritimecloud.pki.TestUtils.getEcdisCert;
import static net.maritimecloud.pki.TestUtils.getEcdisCertPem;
import static net.maritimecloud.pki.TestUtils.getMyBoatCert;
import static net.maritimecloud.pki.TestUtils.getMyBoatCertPem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


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
        X509Certificate cert = getMyBoatCert();
        try {
            String pemCertificate = CertificateHandler.getPemFromEncoded("CERTIFICATE", cert.getEncoded());
            assertEquals(pemCertificate, "-----BEGIN CERTIFICATE-----\n" +
                    "MIID6DCCA2+gAwIBAgICAMEwCgYIKoZIzj0EAwIwgdMxCzAJBgNVBAYTAkRLMRAw\n" +
                    "DgYDVQQIDAdEZW5tYXJrMRMwEQYDVQQHDApDb3BlbmhhZ2VuMRYwFAYDVQQKDA1N\n" +
                    "YXJpdGltZUNsb3VkMSgwJgYDVQQLDB9NYXJpdGltZUNsb3VkIElkZW50aXR5IFJl\n" +
                    "Z2lzdHJ5MTQwMgYDVQQDDCtNYXJpdGltZUNsb3VkIElkZW50aXR5IFJlZ2lzdHJ5\n" +
                    "IENlcnRpZmljYXRlMSUwIwYJKoZIhvcNAQkBFhZpbmZvQG1hcml0aW1lY2xvdWQu\n" +
                    "bmV0MB4XDTE3MDExMzEwNTIyNVoXDTI1MDEwMTAwMDAwMFowfTELMAkGA1UEBhMC\n" +
                    "REsxHDAaBgNVBAoME3Vybjptcm46bWNsOm9yZzpkbWExDzANBgNVBAsMBnZlc3Nl\n" +
                    "bDEQMA4GA1UEAwwHTXkgQm9hdDEtMCsGCgmSJomT8ixkAQEMHXVybjptcm46bWNs\n" +
                    "OnZlc3NlbDpkbWE6bXlib2F0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEx8Dz55UD\n" +
                    "4GzAHVOM7DB76/Abig+rQl8mLgEqFNCk8ZzbG8VryMmIWIq2j4dJqsGqwwAqFcJl\n" +
                    "vchJdx5Hz1brSbffCBwGJ4QqhxJm85NQx4vU6iWiP3o0nDC11enk1lppo4IBaTCC\n" +
                    "AWUwHwYDVR0jBBgwFoAUWDdhX43k8x4PdkyZx3OiZdl1FjIwHQYDVR0OBBYEFGYx\n" +
                    "dChhVfJWPcQa6rx+Tj1vXRraMIGCBgNVHREEezB5oCIGFGmDtqOX2Juv+MfLmeyA\n" +
                    "gKqu14oboAoMCDEyMzQ1Njc4oBoGFGmChru7yJuwqMfLntmAgKqu14oboAIMAKA3\n" +
                    "BhRpg5i818Ce8PDHy6qdgICqrteKG6AfDB11cm46bXJuOm1jbDp2ZXNzZWw6ZG1h\n" +
                    "Om15Ym9hdDBIBgNVHR8EQTA/MD2gO6A5hjdodHRwczovL2FwaS5tYXJpdGltZWNs\n" +
                    "b3VkLm5ldC94NTA5L2FwaS9jZXJ0aWZpY2F0ZXMvY3JsMFQGCCsGAQUFBwEBBEgw\n" +
                    "RjBEBggrBgEFBQcwAYY4aHR0cHM6Ly9hcGkubWFyaXRpbWVjbG91ZC5uZXQveDUw\n" +
                    "OS9hcGkvY2VydGlmaWNhdGVzL29jc3AwCgYIKoZIzj0EAwIDZwAwZAIwIyCgTm1W\n" +
                    "dc8VlwF5RNYVziG5KWJw+YVO5MirhcISDnPNkUAabZzDwNPUoIZImRaCAjB8MIF6\n" +
                    "laWn9dLCvirTEuYJDSS3x9DJzIiQa/aJRSLSuFDu/g6Dw5TmQGbl5kg5Crs=\n" +
                    "-----END CERTIFICATE-----\n");
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
            fail("Unexpected Exception");
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