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

import net.maritimecloud.pki.ocsp.OCSPClient;
import net.maritimecloud.pki.ocsp.OCSPValidationException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.ocsp.RevokedStatus;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CRLReason;
import java.security.cert.X509Certificate;

public class OCSPVerifier {

    public static RevocationInfo verifyCertificateOCSP(X509Certificate cert, KeyStore trustStore) throws IOException, KeyStoreException, OCSPValidationException {
        X500Name x500name = new X500Name(cert.getIssuerDN().getName());
        String issuerAlias = CertificateHandler.getElement(x500name, BCStyle.UID);
        X509Certificate issuerCert =  (X509Certificate) trustStore.getCertificate(issuerAlias);
        return verifyCertificateOCSP(cert, issuerCert);
    }

    public static RevocationInfo verifyCertificateOCSP(X509Certificate cert, X509Certificate issuerCert) throws IOException, OCSPValidationException {
        OCSPClient ocspClient = new OCSPClient(issuerCert, cert);
        RevocationInfo info = new RevocationInfo();
        if (ocspClient.checkOCSP()) {
            info.setStatus(ocspClient.getCertificateStatus());
        } else {
            info.setStatus(ocspClient.getCertificateStatus());
            if (ocspClient.getRevokedStatus().isPresent()) {
                RevokedStatus rs = ocspClient.getRevokedStatus().get();
                info.setRevokeReason(CRLReason.values()[rs.getRevocationReason()]);
                info.setRevokedAt(rs.getRevocationTime());
            }
        }
        return info;
    }

}
