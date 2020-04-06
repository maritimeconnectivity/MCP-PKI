/*
 * Copyright 2020 Maritime Connectivity Platform Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.maritimecloud.pki.pkcs11;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.maritimecloud.pki.PKIConfiguration;
import net.maritimecloud.pki.exception.PKIRuntimeException;
import sun.security.pkcs11.SunPKCS11;

import javax.security.auth.login.LoginException;
import java.io.Console;
import java.security.AuthProvider;
import java.security.Security;

@Slf4j
public class P11PKIConfiguration extends PKIConfiguration {

    @Getter
    private String pkcs11ProviderName;

    @Getter
    private AuthProvider provider;

    @Getter
    private char[] pkcs11Pin;

    private boolean loggedIn;

    public P11PKIConfiguration(String rootCAAlias, String pkcs11ConfigPath, String pkcs11Pin) {
        super(rootCAAlias);
        AuthProvider provider = new SunPKCS11(pkcs11ConfigPath);
        Security.addProvider(provider);
        this.provider = provider;
        this.pkcs11ProviderName = provider.getName();
        // If pkcs11Pin is null the user will be prompted to input it in the console
        if (pkcs11Pin == null) {
            Console console = System.console();
            log.error("Please input HSM slot pin: ");
            this.pkcs11Pin = console.readPassword();
        } else {
            this.pkcs11Pin = pkcs11Pin.toCharArray();
        }
        this.loggedIn = false;
    }

    public void providerLogin() {
        if (loggedIn) {
            return;
        }
        try {
            provider.login(null, new PasswordHandler(pkcs11Pin));
        } catch (LoginException e) {
            throw new PKIRuntimeException(e.getMessage(), e);
        }
    }

    public void providerLogout() {
        if (!loggedIn) {
            return;
        }
        try {
            provider.logout();
        } catch (LoginException e) {
            throw new PKIRuntimeException(e.getMessage(), e);
        }
    }
}
