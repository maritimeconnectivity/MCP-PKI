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
import net.maritimeconnectivity.pki.ocsp.OCSPClient;
import net.maritimeconnectivity.pki.ocsp.OCSPValidationException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.ocsp.RevokedStatus;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CRLReason;
import java.security.cert.X509Certificate;
import java.util.Optional;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class OCSPVerifier {

    /**
     * Verifies a certificate against a its issuer using OCSP. In most cases you should probably use
     * {@link CertificateHandler#verifyCertificateChain(X509Certificate, KeyStore) verifyCertificateChain}
     * instead to verify the complete chain.
     *
     * @param cert Certificate to validate
     * @param trustStore Truststore containing the issuer certificate
     * @return an OCSP result
     * @throws IOException
     * @throws KeyStoreException
     * @throws OCSPValidationException
     */
    public static RevocationInfo verifyCertificateOCSP(X509Certificate cert, KeyStore trustStore) throws KeyStoreException, OCSPValidationException {
        X500Name x500name = new X500Name(cert.getIssuerDN().getName());
        String issuerAlias = CertificateHandler.getElement(x500name, BCStyle.UID);
        X509Certificate issuerCert =  (X509Certificate) trustStore.getCertificate(issuerAlias);
        return verifyCertificateOCSP(cert, issuerCert);
    }

    /**
     * Verifies a certificate against a its issuer using OCSP. In most cases you should probably use
     * {@link CertificateHandler#verifyCertificateChain(X509Certificate, KeyStore) verifyCertificateChain}
     * instead to verify the complete chain.
     *
     * @param cert Certificate to validate
     * @param issuerCert The issuer certificate
     * @return an OCSP result
     * @throws IOException
     * @throws OCSPValidationException
     */
    public static RevocationInfo verifyCertificateOCSP(X509Certificate cert, X509Certificate issuerCert) throws OCSPValidationException {
        OCSPClient ocspClient = new OCSPClient(issuerCert, cert);
        RevocationInfo info = new RevocationInfo();
        if (ocspClient.checkOCSP()) {
            info.setStatus(ocspClient.getCertificateStatus());
        } else {
            info.setStatus(ocspClient.getCertificateStatus());
            Optional<RevokedStatus> revokedStatus = ocspClient.getRevokedStatus();
            if (revokedStatus.isPresent()) {
                RevokedStatus rs = revokedStatus.get();
                info.setRevokeReason(CRLReason.values()[rs.getRevocationReason()]);
                info.setRevokedAt(rs.getRevocationTime());
            }
        }
        return info;
    }

}
