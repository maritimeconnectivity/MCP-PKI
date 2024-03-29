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

import lombok.AllArgsConstructor;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

/**
 * Class used to be able to login to an HSM using a password/PIN
 */
@AllArgsConstructor
public class PasswordHandler implements CallbackHandler {

    private final char[] password;

    @Override
    public void handle(Callback[] callbacks) {
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback passwordCallback) {
                passwordCallback.setPassword(password);
            }
        }
    }
}
