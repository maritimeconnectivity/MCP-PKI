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


import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.pki.exception.PKIRuntimeException;
import net.maritimeconnectivity.pki.pkcs11.P11PKIConfiguration;
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

/**
 * Class that contains functions for handling keystores
 */
@Slf4j
public class KeystoreHandler {

    private final PKIConfiguration pkiConfiguration;

    public KeystoreHandler(PKIConfiguration pkiConfiguration) {
        this.pkiConfiguration = pkiConfiguration;
        // Set Bouncy Castle as Provider, used for Certificates.
        Security.addProvider(new BouncyCastleProvider());

    }

    /**
     * Loads the MCP certificate used for signing from the (jks) keystore
     * Note that if this KeyStoreHandler has been instantiated with an {@link P11PKIConfiguration} object you will need to call
     * the function P11PKIConfiguration.providerLogin() before calling this function.
     * Likewise, when you are finished with using the private key handle returned by this function you should call
     * P11PKIConfiguration.providerLogout().
     *
     * @param alias Alias of the signing certificate
     * @return a PrivateKeyEntry of the signing certificate
     */
    public KeyStore.PrivateKeyEntry getSigningCertEntry(String alias) {
        if (pkiConfiguration instanceof P11PKIConfiguration p11PKIConfiguration) {
            try {
                KeyStore keyStore = KeyStore.getInstance(PKIConstants.PKCS11, p11PKIConfiguration.getProvider());
                keyStore.load(null, p11PKIConfiguration.getPkcs11Pin());
                return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            } catch (KeyStoreException e) {
                log.error("Could not create PKCS#11 keystore");
                p11PKIConfiguration.providerLogout();
                throw new PKIRuntimeException(e.getMessage(), e);
            } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
                log.error("Could not open PKCS#11 keystore");
                p11PKIConfiguration.providerLogout();
                throw new PKIRuntimeException(e.getMessage(), e);
            } catch (UnrecoverableEntryException e) {
                log.error("Could not get CA entry from PKCS#11 keystore");
                p11PKIConfiguration.providerLogout();
                throw new PKIRuntimeException(e.getMessage(), e);
            }
        }
        try (FileInputStream is = new FileInputStream(pkiConfiguration.getSubCaKeystorePath())) {
            KeyStore keyStore = KeyStore.getInstance(PKIConstants.KEYSTORE_TYPE);
            keyStore.load(is, pkiConfiguration.getSubCaKeystorePassword().toCharArray());
            KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(pkiConfiguration.getSubCaKeyPassword().toCharArray());
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, protectionParameter);
        } catch (FileNotFoundException e) {
            log.error("Could not open CA keystore", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException |
                 UnrecoverableEntryException e) {
            log.error("Could not get CA entry", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns an MCP certificate from the truststore
     *
     * @param alias Either ROOT_CERT_ALIAS or INTERMEDIATE_CERT_ALIAS
     * @return a certificate
     */
    public Certificate getMCPCertificate(String alias) {
        log.debug(pkiConfiguration.getTruststorePath());
        try (FileInputStream is = new FileInputStream(pkiConfiguration.getTruststorePath())) {
            KeyStore keyStore = KeyStore.getInstance(PKIConstants.KEYSTORE_TYPE);
            keyStore.load(is, pkiConfiguration.getTruststorePassword().toCharArray());
            return keyStore.getCertificate(alias);
        } catch (FileNotFoundException e) {
            log.error("Could not open truststore", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            log.error("Could not load CA certificate", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns the truststore defined in PKIConfiguration.
     *
     * @return a truststore
     */
    public KeyStore getTrustStore() {
        try (FileInputStream is = new FileInputStream(pkiConfiguration.getTruststorePath())) {
            KeyStore keyStore = KeyStore.getInstance(PKIConstants.KEYSTORE_TYPE);
            keyStore.load(is, pkiConfiguration.getTruststorePassword().toCharArray());
            return keyStore;
        } catch (FileNotFoundException e) {
            log.error("Could not open truststore", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            log.error("Could not load truststore", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns the public key of the sub CA certificate with the given alias
     *
     * @param alias Alias of a sub CA
     * @return the public key of the specified sub CA
     */
    public PublicKey getPubKey(String alias) {
        Certificate cert = getMCPCertificate(alias);
        return cert.getPublicKey();
    }

}
