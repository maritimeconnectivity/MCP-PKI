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
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
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
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static net.maritimecloud.pki.CertificateHandler.getPemFromEncoded;
import static net.maritimecloud.pki.PKIConstants.BC_PROVIDER_NAME;
import static net.maritimecloud.pki.PKIConstants.SIGNER_ALGORITHM;

@Slf4j
public class Revocation {

    /**
     * Returns the int value associated with a revocation status
     *
     * @param certReason The string representation of the status. Should be lowercase with no spaces or underscore
     * @return The int value associated with the revocation status
     */
    public static int getCRLReasonFromString(String certReason) {
        int reason = CRLReason.unspecified;
        if ("unspecified".equals(certReason)) {
            reason = CRLReason.unspecified;
        } else if ("keycompromise".equals(certReason)) {
            reason = CRLReason.keyCompromise;
        } else if ("cacompromise".equals(certReason)) {
            reason = CRLReason.cACompromise;
        } else if ("affiliationchanged".equals(certReason)) {
            reason = CRLReason.affiliationChanged;
        } else if ("superseded".equals(certReason)) {
            reason = CRLReason.superseded;
        } else if ("cessationofoperation".equals(certReason)) {
            reason = CRLReason.cessationOfOperation;
        } else if ("certificatehold".equals(certReason)) {
            reason = CRLReason.certificateHold;
        } else if ("removefromcrl".equals(certReason)) {
            reason = CRLReason.removeFromCRL;
        } else if ("privilegewithdrawn".equals(certReason)) {
            reason = CRLReason.privilegeWithdrawn;
        } else if ("aacompromise".equals(certReason)) {
            reason = CRLReason.aACompromise;
        }
        return reason;
    }

    /**
     * Creates a Certificate RevocationInfo List (CRL) for the certificate serialnumbers given.
     *
     * @param revokedCerts  List of the serialnumbers that should be revoked.
     * @param keyEntry Private key to sign the CRL
     * @param signCertX500Name DN name of the signing certificate
     * @return a CRL
     */
    public static X509CRL generateCRL(List<RevocationInfo> revokedCerts, KeyStore.PrivateKeyEntry keyEntry, String signCertX500Name) {
        Date now = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(now);
        cal.add(Calendar.DATE, 7);
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(signCertX500Name), now);
        crlBuilder.setNextUpdate(new Date(now.getTime() + 24 * 60 * 60 * 1000 * 7)); // The next CRL is next week (dummy value)
        for (RevocationInfo cert : revokedCerts) {
            crlBuilder.addCRLEntry(cert.getSerialNumber(), cert.getRevokedAt(), cert.getRevokeReason().ordinal());
        }
        //crlBuilder.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        //crlBuilder.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));

        JcaContentSignerBuilder signBuilder = new JcaContentSignerBuilder(SIGNER_ALGORITHM);
        signBuilder.setProvider(BC_PROVIDER_NAME);
        ContentSigner signer;
        try {
            signer = signBuilder.build(keyEntry.getPrivateKey());
        } catch (OperatorCreationException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        }

        X509CRLHolder cRLHolder = crlBuilder.build(signer);
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        converter.setProvider(BC_PROVIDER_NAME);
        X509CRL crl = null;
        try {
            crl = converter.getCRL(cRLHolder);
        } catch (CRLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return crl;
    }

    /**
     * Creates a Certificate RevocationInfo List (CRL) for the certificate serialnumbers given.
     *
     * @param signName DN name of the signing certificate
     * @param revokedCerts  List of the serialnumbers that should be revoked.
     * @param keyEntry Private key to sign the CRL
     * @param outputCaCrlPath Where to place the CRL
     */
    public static void generateRootCACRL(String signName, List<RevocationInfo> revokedCerts, KeyStore.PrivateKeyEntry keyEntry, String outputCaCrlPath) {
        Date now = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(now);
        cal.add(Calendar.YEAR, 1);
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(signName), now);
        crlBuilder.setNextUpdate(cal.getTime()); // The next CRL is next year (dummy value)
        if (revokedCerts !=  null) {
            for (RevocationInfo cert : revokedCerts) {
                crlBuilder.addCRLEntry(cert.getSerialNumber(), cert.getRevokedAt(), cert.getRevokeReason().ordinal());
            }
        }
        //crlBuilder.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        //crlBuilder.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));

        JcaContentSignerBuilder signBuilder = new JcaContentSignerBuilder(SIGNER_ALGORITHM);
        signBuilder.setProvider(BC_PROVIDER_NAME);
        ContentSigner signer;
        try {
            signer = signBuilder.build(keyEntry.getPrivateKey());
        } catch (OperatorCreationException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return;
        }

        X509CRLHolder cRLHolder = crlBuilder.build(signer);
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        converter.setProvider(BC_PROVIDER_NAME);
        X509CRL crl;
        try {
            crl = converter.getCRL(cRLHolder);
        } catch (CRLException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        String pemCrl;
        try {
            pemCrl = getPemFromEncoded("X509 CRL", crl.getEncoded());
        } catch (CRLException e) {
            //log.warn("unable to generate RootCACRL", e);
            return;
        }
        try {
            BufferedWriter writer = new BufferedWriter( new FileWriter(outputCaCrlPath));
            writer.write(pemCrl);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate a BasicOCSPRespBuilder.
     *
     * @param request The incoming request.
     * @param publicKey Public key of the issuer.
     * @return a BasicOCSPRespBuilder
     */
    public static BasicOCSPRespBuilder initOCSPRespBuilder(OCSPReq request, PublicKey publicKey) {
        SubjectPublicKeyInfo keyinfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        BasicOCSPRespBuilder respBuilder;
        try {
            respBuilder = new BasicOCSPRespBuilder(keyinfo,
                    new JcaDigestCalculatorProviderBuilder().setProvider(BC_PROVIDER_NAME).build().get(CertificateID.HASH_SHA1)); // Create builder
        } catch (Exception e) {
            return null;
        }

        Extension ext = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (ext != null) {
            respBuilder.setResponseExtensions(new Extensions(new Extension[] { ext })); // Put the nonce back in the response
        }
        return respBuilder;
    }

    /**
     * Generates a OCSPResp.
     *
     * @param respBuilder A BasicOCSPRespBuilder
     * @param signingCert PrivateKeyEntry of the signing certificate.
     * @return a OCSPResp
     */
    public static OCSPResp generateOCSPResponse(BasicOCSPRespBuilder respBuilder, KeyStore.PrivateKeyEntry signingCert) {
        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNER_ALGORITHM).setProvider(BC_PROVIDER_NAME).build(signingCert.getPrivateKey());
            BasicOCSPResp basicResp = respBuilder.build(contentSigner,
                    new X509CertificateHolder[] { new X509CertificateHolder(signingCert.getCertificate().getEncoded()) }, new Date());
            // Set response as successful
            int response = OCSPRespBuilder.SUCCESSFUL;
            // build the response
            return new OCSPRespBuilder().build(response, basicResp);
        } catch (Exception e) {
            return null;
        }
    }

}
