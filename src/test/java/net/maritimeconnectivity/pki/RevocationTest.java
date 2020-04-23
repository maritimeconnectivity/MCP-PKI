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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.X509CRL;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


class RevocationTest {
    @BeforeEach
    void setUp() {
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void generateCRL() {
        // Generate the RevocationInfo list for generating the CRL
        RevocationInfo info = new RevocationInfo(BigInteger.valueOf(42), CRLReason.AFFILIATION_CHANGED, new Date(), CertStatus.REVOKED);
        List<RevocationInfo> infos = Arrays.asList(info);

        // Load a subCA key used for siging
        PKIConfiguration pkiConf = new PKIConfiguration(TestUtils.getRootCAAlias());
        pkiConf.setSubCaKeystorePath("src/test/resources/ca/subca-keystore.jks");
        pkiConf.setSubCaKeystorePassword("changeit");
        pkiConf.setSubCaKeyPassword("changeit");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);

        // Generate the CRL
        KeyStore.PrivateKeyEntry keyEntry = kh.getSigningCertEntry("urn:mrn:mcl:ca:maritimecloud-idreg");
        X509CRL crl = Revocation.generateCRL(infos, keyEntry, null);

        // Verify that the CRL was signed
        try {
            crl.verify(keyEntry.getCertificate().getPublicKey());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException | CRLException e) {
            e.printStackTrace();
            fail(e);
        }
        // Check that the serial number is included
        assertNotNull(crl.getRevokedCertificate(BigInteger.valueOf(42)));

    }

}
