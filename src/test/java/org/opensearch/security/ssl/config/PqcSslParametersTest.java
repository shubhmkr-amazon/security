/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.ssl.config;

import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_ENFORCE_CLASSICAL_FALLBACK;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_GROUPS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_SIGNATURE_SCHEMES;
import static org.junit.Assert.assertThrows;

/**
 * PQC readiness tests for {@link SslParameters}: parsing of {@code enabled_groups} / {@code enabled_signature_schemes},
 * validation of unknown names, and the rolling-upgrade classical-fallback guard.
 */
public class PqcSslParametersTest {

    private static Settings.Builder httpEnabled() {
        return Settings.builder().put("plugins.security.ssl.http.enabled", true);
    }

    private static SslParameters load(final Settings settings) {
        return SslParameters.loader(CertType.HTTP, settings).load();
    }

    @Test
    public void hybridGroupsAndSchemesAreParsed() {
        final var params = load(
            httpEnabled().putList(SECURITY_SSL_HTTP_ENABLED_GROUPS, "X25519MLKEM768", "x25519", "secp256r1")
                .putList(SECURITY_SSL_HTTP_ENABLED_SIGNATURE_SCHEMES, "mldsa65", "ecdsa_secp256r1_sha256")
                .build()
        );
        assertThat(params.namedGroups(), is(java.util.List.of("X25519MLKEM768", "x25519", "secp256r1")));
        assertThat(params.signatureSchemes(), is(java.util.List.of("mldsa65", "ecdsa_secp256r1_sha256")));
    }

    @Test
    public void defaultsAreEmptyAndLoad() {
        final var params = load(httpEnabled().build());
        assertThat(params.namedGroups().isEmpty(), is(true));
        assertThat(params.signatureSchemes().isEmpty(), is(true));
    }

    @Test
    public void unknownGroupIsRejected() {
        final var ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> load(httpEnabled().putList(SECURITY_SSL_HTTP_ENABLED_GROUPS, "BOGUS_GROUP").build())
        );
        assertThat(ex.getMessage(), containsString("Unknown TLS group"));
        assertThat(ex.getMessage(), containsString("BOGUS_GROUP"));
    }

    @Test
    public void unknownSignatureSchemeIsRejected() {
        final var ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> load(httpEnabled().putList(SECURITY_SSL_HTTP_ENABLED_SIGNATURE_SCHEMES, "not_a_scheme").build())
        );
        assertThat(ex.getMessage(), containsString("Unknown signature scheme"));
    }

    @Test
    public void pqcOnlyGroupsWarnButLoadByDefault() {
        // No classical fallback, enforce flag not set -> warns, still loads.
        final var params = load(httpEnabled().putList(SECURITY_SSL_HTTP_ENABLED_GROUPS, "X25519MLKEM768").build());
        assertThat(params.namedGroups(), is(java.util.List.of("X25519MLKEM768")));
    }

    @Test
    public void pqcOnlyGroupsRejectedWhenEnforceEnabled() {
        final var ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> load(
                httpEnabled().put(SECURITY_SSL_ENFORCE_CLASSICAL_FALLBACK, true)
                    .putList(SECURITY_SSL_HTTP_ENABLED_GROUPS, "X25519MLKEM768")
                    .build()
            )
        );
        assertThat(ex.getMessage(), containsString("no classical fallback"));
    }

    @Test
    public void pqcOnlySignatureSchemesRejectedWhenEnforceEnabled() {
        final var ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> load(
                httpEnabled().put(SECURITY_SSL_ENFORCE_CLASSICAL_FALLBACK, true)
                    .putList(SECURITY_SSL_HTTP_ENABLED_SIGNATURE_SCHEMES, "mldsa65")
                    .build()
            )
        );
        assertThat(ex.getMessage(), containsString("no classical fallback"));
    }
}
