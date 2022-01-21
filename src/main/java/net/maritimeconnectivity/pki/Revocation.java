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

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.pki.exception.PKIRuntimeException;
import net.maritimeconnectivity.pki.pkcs11.P11PKIConfiguration;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import static net.maritimeconnectivity.pki.CertificateHandler.getPemFromEncoded;
import static net.maritimeconnectivity.pki.PKIConstants.BC_PROVIDER_NAME;
import static net.maritimeconnectivity.pki.PKIConstants.SIGNER_ALGORITHM;

/**
 * Class that contains functions that are relevant for providing revocation information
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Revocation {

    /**
     * Returns the int value associated with a revocation status
     *
     * @param certReason The string representation of the status. Should be lowercase with no spaces or underscore
     * @return The int value associated with the revocation status
     */
    public static int getCRLReasonFromString(String certReason) {
        switch (certReason) {
            case "keycompromise":
                return CRLReason.keyCompromise;
            case "cacompromise":
                return CRLReason.cACompromise;
            case "affiliationchanged":
                return CRLReason.affiliationChanged;
            case "superseded":
                return CRLReason.superseded;
            case "cessationofoperation":
                return CRLReason.cessationOfOperation;
            case "certificatehold":
                return CRLReason.certificateHold;
            case "removefromcrl":
                return CRLReason.removeFromCRL;
            case "privilegewithdrawn":
                return CRLReason.privilegeWithdrawn;
            case "aacompromise":
                return CRLReason.aACompromise;
            default:
                return CRLReason.unspecified;
        }
    }

    /**
     * Creates a Certificate RevocationInfo List (CRL) for the certificate serialnumbers given.
     *
     * @param revokedCerts     List of the serialnumbers that should be revoked.
     * @param keyEntry         Private key to sign the CRL
     * @param pkiConfiguration A PKIConfiguration
     * @return a CRL
     */
    public static X509CRL generateCRL(List<RevocationInfo> revokedCerts, KeyStore.PrivateKeyEntry keyEntry, PKIConfiguration pkiConfiguration) {
        Date now = Date.from(Instant.now());
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.setTime(now);
        cal.add(Calendar.DATE, 7); // Add a week to the calendar
        String signCertX500Name;
        try {
            signCertX500Name = new JcaX509CertificateHolder((X509Certificate) keyEntry.getCertificate()).getSubject().toString();
        } catch (CertificateEncodingException e) {
            log.error(e.getMessage(), e);
            return null;
        }
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(signCertX500Name), now);
        crlBuilder.setNextUpdate(cal.getTime()); // The next CRL is next week (dummy value)
        for (RevocationInfo cert : revokedCerts) {
            crlBuilder.addCRLEntry(cert.getSerialNumber(), cert.getRevokedAt(), cert.getRevokeReason().ordinal());
        }

        JcaContentSignerBuilder signBuilder = new JcaContentSignerBuilder(SIGNER_ALGORITHM);
        if (pkiConfiguration instanceof P11PKIConfiguration) {
            P11PKIConfiguration p11PKIConfiguration = (P11PKIConfiguration) pkiConfiguration;
            signBuilder.setProvider(p11PKIConfiguration.getProvider());
        } else {
            signBuilder.setProvider(BC_PROVIDER_NAME);
        }
        ContentSigner signer;
        try {
            signer = signBuilder.build(keyEntry.getPrivateKey());
        } catch (OperatorCreationException e1) {
            log.error(e1.getMessage(), e1);
            return null;
        }

        X509CRLHolder cRLHolder = crlBuilder.build(signer);
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        converter.setProvider(BC_PROVIDER_NAME);
        X509CRL crl = null;
        try {
            crl = converter.getCRL(cRLHolder);
        } catch (CRLException e) {
            log.error(e.getMessage(), e);
        }
        return crl;
    }

    /**
     * Creates a Certificate RevocationInfo List (CRL) for the certificate serialnumbers given.
     *
     * @param signName        DN name of the signing certificate
     * @param revokedCerts    List of the serialnumbers that should be revoked.
     * @param keyEntry        Private key to sign the CRL
     * @param outputCaCrlPath Where to place the CRL
     * @param pkcs11Provider  PKCS#11 provider. If null default BC provider will be used.
     */
    public static void generateRootCACRL(String signName, List<RevocationInfo> revokedCerts, KeyStore.PrivateKeyEntry keyEntry, String outputCaCrlPath, AuthProvider pkcs11Provider) {
        Date now = Date.from(Instant.now());
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.setTime(now);
        cal.add(Calendar.YEAR, 1);
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(signName), now);
        crlBuilder.setNextUpdate(cal.getTime()); // The next CRL is next year (dummy value)
        if (revokedCerts != null) {
            for (RevocationInfo cert : revokedCerts) {
                crlBuilder.addCRLEntry(cert.getSerialNumber(), cert.getRevokedAt(), cert.getRevokeReason().ordinal());
            }
        }

        JcaContentSignerBuilder signBuilder = new JcaContentSignerBuilder(SIGNER_ALGORITHM);
        if (pkcs11Provider != null) {
            signBuilder.setProvider(pkcs11Provider);
        } else {
            signBuilder.setProvider(BC_PROVIDER_NAME);
        }
        ContentSigner signer;
        try {
            signer = signBuilder.build(keyEntry.getPrivateKey());
        } catch (OperatorCreationException e1) {
            log.error(e1.getMessage(), e1);
            return;
        }

        X509CRLHolder cRLHolder = crlBuilder.build(signer);
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        converter.setProvider(BC_PROVIDER_NAME);
        X509CRL crl;
        try {
            crl = converter.getCRL(cRLHolder);
        } catch (CRLException e) {
            throw new PKIRuntimeException(e.getMessage(), e);
        }
        String pemCrl;
        try {
            pemCrl = getPemFromEncoded("X509 CRL", crl.getEncoded());
        } catch (CRLException e) {
            log.error("unable to generate RootCACRL", e);
            return;
        }
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputCaCrlPath))) {
            writer.write(pemCrl);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }

    /**
     * @param request              The incoming issue
     * @param caPublicKey          The public key of the signing CA
     * @param signingCA            The keystore entry for the signing CA
     * @param certificateStatusMap A mapping from CertificateID to CertificateStatus
     * @param pkiConfiguration     A PKIConfiguration
     * @return An OCSP response
     */
    public static OCSPResp handleOCSP(OCSPReq request, PublicKey caPublicKey, KeyStore.PrivateKeyEntry signingCA,
                                      Map<CertificateID, CertificateStatus> certificateStatusMap,
                                      PKIConfiguration pkiConfiguration) {
        if (request == null) {
            OCSPResponse response = new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.MALFORMED_REQUEST), null);
            return new OCSPResp(response);
        }

        BasicOCSPRespBuilder respBuilder;
        try {
            respBuilder = initOCSPRespBuilder(request, caPublicKey);
        } catch (OCSPException | OperatorCreationException e) {
            log.error("Could not build OCSP responder", e);
            OCSPResponse response = new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.INTERNAL_ERROR), null);
            return new OCSPResp(response);
        }
        certificateStatusMap.forEach(respBuilder::addResponse);

        P11PKIConfiguration p11PKIConfiguration = null;
        if (pkiConfiguration instanceof P11PKIConfiguration) {
            p11PKIConfiguration = (P11PKIConfiguration) pkiConfiguration;
            p11PKIConfiguration.providerLogin();
        }

        OCSPResp ocspResp;
        try {
            ocspResp = generateOCSPResponse(respBuilder, signingCA, p11PKIConfiguration);
        } catch (OCSPException | IOException | OperatorCreationException | CertificateEncodingException e) {
            log.error("Could not generate OCSP response", e);
            OCSPResponse response = new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.INTERNAL_ERROR), null);
            if (p11PKIConfiguration != null)
                p11PKIConfiguration.providerLogout();
            return new OCSPResp(response);
        }
        if (p11PKIConfiguration != null)
            p11PKIConfiguration.providerLogout();
        return ocspResp;
    }

    /**
     * Generate a BasicOCSPRespBuilder.
     *
     * @param request   The incoming request.
     * @param publicKey Public key of the issuer.
     * @return a BasicOCSPRespBuilder
     */
    public static BasicOCSPRespBuilder initOCSPRespBuilder(OCSPReq request, PublicKey publicKey) throws OCSPException, OperatorCreationException {
        SubjectPublicKeyInfo keyinfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        BasicOCSPRespBuilder respBuilder;
        respBuilder = new BasicOCSPRespBuilder(keyinfo, new JcaDigestCalculatorProviderBuilder()
                .setProvider(BC_PROVIDER_NAME).build().get(CertificateID.HASH_SHA1)); // Create builder

        Extension ext = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (ext != null) {
            respBuilder.setResponseExtensions(new Extensions(new Extension[]{ext})); // Put the nonce back in the response
        }
        return respBuilder;
    }

    /**
     * Generates a OCSPResp.
     *
     * @param respBuilder         A BasicOCSPRespBuilder
     * @param signingCert         PrivateKeyEntry of the signing certificate.
     * @param p11PKIConfiguration A P11PKIConfiguration. Can be null
     * @return a OCSPResp
     */
    public static OCSPResp generateOCSPResponse(BasicOCSPRespBuilder respBuilder, KeyStore.PrivateKeyEntry signingCert, P11PKIConfiguration p11PKIConfiguration) throws OCSPException, IOException, OperatorCreationException, CertificateEncodingException {
        try {
            JcaContentSignerBuilder signBuilder = new JcaContentSignerBuilder(SIGNER_ALGORITHM);
            if (p11PKIConfiguration != null) {
                p11PKIConfiguration.providerLogin();
                signBuilder.setProvider(p11PKIConfiguration.getProvider());
            } else {
                signBuilder.setProvider(BC_PROVIDER_NAME);
            }
            ContentSigner contentSigner = signBuilder.build(signingCert.getPrivateKey());
            BasicOCSPResp basicResp = respBuilder.build(contentSigner,
                    new X509CertificateHolder[]{new X509CertificateHolder(signingCert.getCertificate().getEncoded())}, Date.from(Instant.now()));
            // Set response as successful
            int response = OCSPRespBuilder.SUCCESSFUL;
            // build the response
            OCSPResp ocspResp = new OCSPRespBuilder().build(response, basicResp);
            if (p11PKIConfiguration != null) {
                p11PKIConfiguration.providerLogout();
            }
            return ocspResp;
        } catch (CertificateEncodingException e) {
            // If an exception is thrown we need to first catch it, logout of the PKCS#11 provider if we use one
            // and then throw the exception again
            if (p11PKIConfiguration != null) {
                p11PKIConfiguration.providerLogout();
            }
            throw e;
        }
    }

}
