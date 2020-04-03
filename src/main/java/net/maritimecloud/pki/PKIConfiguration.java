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

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;
import sun.security.pkcs11.SunPKCS11;

import java.io.Console;
import java.security.Provider;
import java.security.Security;

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

    private boolean isUsingPkcs11;

    private String pkcs11ProviderName;

    private char[] pkcs11Pin;

    public PKIConfiguration(String rootCAAlias){
        this.rootCAAlias = rootCAAlias;
    }

    public PKIConfiguration(String rootCAAlias, String pkcs11ConfigPath, String pkcs11Pin) {
        this(rootCAAlias);
        Provider provider = new SunPKCS11(pkcs11ConfigPath);
        Security.addProvider(provider);
        this.isUsingPkcs11 = true;
        this.pkcs11ProviderName = provider.getName();
        // If pkcs11Pin is null the user will be prompted to input it in the console
        System.out.println("Bla");
        if (pkcs11Pin == null) {
            System.out.println("Got here!");
            Console console = System.console();
            System.out.println("Please input HSM slot pin: ");
            this.pkcs11Pin = console.readPassword();
        } else {
            this.pkcs11Pin = pkcs11Pin.toCharArray();
        }
    }
}
