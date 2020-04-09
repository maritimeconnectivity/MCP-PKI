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
        AuthProvider authProvider = new SunPKCS11(pkcs11ConfigPath);
        Security.addProvider(authProvider);
        this.provider = authProvider;
        this.pkcs11ProviderName = authProvider.getName();
        // If pkcs11Pin is null the user will be prompted to input it in the console
        if (pkcs11Pin == null) {
            Console console = System.console();
            if (console != null) {
                log.error("Please input HSM slot pin: ");
                this.pkcs11Pin = console.readPassword();
                console.flush();
            } else {
                throw new PKIRuntimeException("Could not get a system console");
            }
        } else {
            this.pkcs11Pin = pkcs11Pin.toCharArray();
        }
        this.loggedIn = false;
    }

    public P11PKIConfiguration(String rootCAAlias, String pkcs11ConfigPath, char[] pkcs11Pin) {
        super(rootCAAlias);
        AuthProvider authProvider = new SunPKCS11(pkcs11ConfigPath);
        Security.addProvider(authProvider);
        this.provider = authProvider;
        this.pkcs11ProviderName = authProvider.getName();
        // If pkcs11Pin is null the user will be prompted to input it in the console
        if (pkcs11Pin == null) {
            Console console = System.console();
            log.error("Please input HSM slot pin: ");
            this.pkcs11Pin = console.readPassword();
            console.flush();
        } else {
            this.pkcs11Pin = pkcs11Pin;
        }
        this.loggedIn = false;
    }

    public void providerLogin() {
        if (loggedIn) {
            return;
        }
        try {
            provider.login(null, new PasswordHandler(pkcs11Pin));
            loggedIn = true;
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
            loggedIn = false;
        } catch (LoginException e) {
            throw new PKIRuntimeException(e.getMessage(), e);
        }
    }
}
