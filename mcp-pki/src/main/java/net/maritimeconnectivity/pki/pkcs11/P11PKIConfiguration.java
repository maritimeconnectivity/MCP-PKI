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

package net.maritimeconnectivity.pki.pkcs11;

import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.pki.PKIConfiguration;
import net.maritimeconnectivity.pki.exception.PKIRuntimeException;

import javax.security.auth.login.LoginException;
import java.io.Console;
import java.security.AuthProvider;
import java.security.Provider;
import java.security.Security;

/**
 * Class for holding the configuration for PKCS#11 of an instance of the PKI
 */
@Slf4j
public class P11PKIConfiguration extends PKIConfiguration {

    @Getter
    private final String pkcs11ProviderName;

    @Getter
    private final AuthProvider provider;

    @Getter
    private final char[] pkcs11Pin;

    private boolean loggedIn = false;

    private final PasswordHandler passwordHandler;

    /**
     * @param rootCAAlias      the alias for the root CA that should be used
     * @param pkcs11ConfigPath the path of the PKCS#11 configuration file
     * @param pkcs11Pin        the pin that should be used for logging in to the HSM
     */
    public P11PKIConfiguration(@NonNull String rootCAAlias, String pkcs11ConfigPath, String pkcs11Pin) {
        super(rootCAAlias);
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(pkcs11ConfigPath);
        AuthProvider authProvider = (AuthProvider) p;
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
        this.passwordHandler = new PasswordHandler(this.pkcs11Pin);
    }

    /**
     * @param rootCAAlias      the alias for the root CA that should be used
     * @param pkcs11ConfigPath the path of the PKCS#11 configuration file
     * @param pkcs11Pin        the pin that should be used for logging in to the HSM
     */
    public P11PKIConfiguration(@NonNull String rootCAAlias, String pkcs11ConfigPath, char[] pkcs11Pin) {
        super(rootCAAlias);
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(pkcs11ConfigPath);
        AuthProvider authProvider = (AuthProvider) p;
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
            this.pkcs11Pin = pkcs11Pin;
        }
        this.passwordHandler = new PasswordHandler(this.pkcs11Pin);
    }

    /**
     * Login to the HSM
     */
    public void providerLogin() {
        if (loggedIn) {
            return;
        }
        try {
            provider.login(null, passwordHandler);
            loggedIn = true;
        } catch (LoginException e) {
            throw new PKIRuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Logout from the HSM
     */
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
