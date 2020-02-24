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


import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import static net.maritimecloud.pki.PKIConstants.KEYSTORE_TYPE;

@Slf4j
public class KeystoreHandler {

    private PKIConfiguration pkiConfiguration;

    public KeystoreHandler(PKIConfiguration pkiConfiguration) {
        this.pkiConfiguration = pkiConfiguration;
        // Set Bouncy Castle as Provider, used for Certificates.
        Security.addProvider(new BouncyCastleProvider());

    }
    /**
     * Loads the MCP certificate used for signing from the (jks) keystore
     *
     * @param alias Alias of the signing certificate
     * @return a PrivateKeyEntry of the signing certificate
     */
    public KeyStore.PrivateKeyEntry getSigningCertEntry(String alias) {
        FileInputStream is;
        try {
            is = new FileInputStream(pkiConfiguration.getSubCaKeystorePath());
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(is, pkiConfiguration.getSubCaKeystorePassword().toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(pkiConfiguration.getSubCaKeyPassword().toCharArray());
            return (KeyStore.PrivateKeyEntry) keystore.getEntry(alias, protParam);

        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException | UnrecoverableEntryException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns a MCP certificate from the truststore
     *
     * @param alias Either ROOT_CERT_ALIAS or INTERMEDIATE_CERT_ALIAS
     * @return a certificate
     */
    public Certificate getMCPCertificate(String alias) {
        log.debug(pkiConfiguration.getTruststorePath());
        FileInputStream is;
        try {
            is = new FileInputStream(pkiConfiguration.getTruststorePath());
        } catch (FileNotFoundException e) {
            log.error("Could not open truststore", e);
            throw new RuntimeException(e.getMessage(), e);
        }
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(is, pkiConfiguration.getTruststorePassword().toCharArray());
            return keystore.getCertificate(alias);

        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            log.error("Could not load root certificate", e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns the truststore defined in PKIConfiguration.
     *
     * @return a truststore
     */
    public KeyStore getTrustStore() {
        FileInputStream is;
        try {
            is = new FileInputStream(pkiConfiguration.getTruststorePath());
        } catch (FileNotFoundException e) {
            log.error("Could not open truststore", e);
            throw new RuntimeException(e.getMessage(), e);
        }
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(is, pkiConfiguration.getTruststorePassword().toCharArray());
            return keystore;

        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            log.error("Could not load truststore!", e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns the public key of the sub CA certificate with the given alias
     *
     * @param alias Alias of a sub CA
     * @return
     */
    public PublicKey getPubKey(String alias) {
        Certificate cert = getMCPCertificate(alias);
        return cert.getPublicKey();
    }

}
