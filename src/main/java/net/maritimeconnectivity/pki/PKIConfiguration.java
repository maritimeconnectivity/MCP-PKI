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

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class PKIConfiguration {

    // Values below are loaded from application.yaml
    //@Value("${net.maritimecloud.pki.mcidreg-cert-x500-name}")
    //public String mcidregCertX500Name;

    //@Value("${net.maritimecloud.pki.root-keystore}")
    private String rootCaKeystorePath;

    //@Value("${net.maritimecloud.pki.keystore-password}")
    private String rootCaKeystorePassword;

    private String rootCaKeyPassword;

    //@Value("${net.maritimecloud.pki.it-keystore}")
    private String subCaKeystorePath;

    private String subCaKeystorePassword;

    private String subCaKeyPassword;

    //@Value("${net.maritimecloud.pki.truststore}")
    private String truststorePath;

    //@Value("${net.maritimecloud.pki.truststore-password}")
    private String truststorePassword;

    //@Value("${net.maritimecloud.pki.root-ca-alias}")
    @NonNull
    private String rootCAAlias;

    public PKIConfiguration(@NonNull String rootCAAlias){
        this.rootCAAlias = rootCAAlias;
    }

}
