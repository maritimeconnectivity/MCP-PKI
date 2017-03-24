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

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import net.maritimecloud.pki.ocsp.CertStatus;

import java.math.BigInteger;
import java.security.cert.CRLReason;
import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
public class RevocationInfo {

    public RevocationInfo() {
    }
    private BigInteger serialNumber;
    private CRLReason revokeReason;
    private Date RevokedAt;
    private CertStatus status;

}
