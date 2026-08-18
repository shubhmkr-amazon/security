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

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.SSLContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.util.SSLConfigConstants;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslProvider;

import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_SSL_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_SSL_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.CLIENT_AUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED_GROUPS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED_SIGNATURE_SCHEMES;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENFORCE_CERT_RELOAD_DN_VERIFICATION;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENTAUTH_MODE_DEFAULT;

public class SslParameters {

    private final SslProvider provider;

    private final ClientAuth clientAuth;

    private final List<String> protocols;

    private final List<String> ciphers;

    // PQC POC: TLS named groups (key-exchange groups) to enforce, e.g. "X25519MLKEM768". Empty = provider default.
    private final List<String> namedGroups;

    // PQC: TLS signature schemes to enforce, e.g. "mldsa65" (for ML-DSA cert authentication). Empty = default.
    private final List<String> signatureSchemes;

    private final boolean validateCertDNsOnReload;

    private SslParameters(
        SslProvider provider,
        final ClientAuth clientAuth,
        List<String> protocols,
        List<String> ciphers,
        List<String> namedGroups,
        List<String> signatureSchemes,
        boolean validateCertDNsOnReload
    ) {
        this.provider = provider;
        this.ciphers = ciphers;
        this.namedGroups = namedGroups;
        this.signatureSchemes = signatureSchemes;
        this.protocols = protocols;
        this.clientAuth = clientAuth;
        this.validateCertDNsOnReload = validateCertDNsOnReload;
    }

    public ClientAuth clientAuth() {
        return clientAuth;
    }

    public SslProvider provider() {
        return provider;
    }

    public List<String> allowedCiphers() {
        return ciphers;
    }

    public List<String> namedGroups() {
        return namedGroups;
    }

    public List<String> signatureSchemes() {
        return signatureSchemes;
    }

    public List<String> allowedProtocols() {
        return protocols;
    }

    public boolean shouldValidateNewCertDNs() {
        return validateCertDNsOnReload;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SslParameters that = (SslParameters) o;
        return provider == that.provider && Objects.equals(ciphers, that.ciphers) && Objects.equals(protocols, that.protocols);
    }

    @Override
    public int hashCode() {
        return Objects.hash(provider, ciphers, protocols);
    }

    public static Loader loader(final CertType certType, final Settings settings) {
        return new Loader(certType, settings);
    }

    public static final class Loader {
        private final static Logger LOGGER = LogManager.getLogger(SslParameters.class);

        private final CertType certType;
        private final Settings sslConfigSettings;
        private final boolean enforceClassicalFallback;

        public Loader(final CertType certType, final Settings settings) {
            this.certType = certType;
            this.sslConfigSettings = settings.getByPrefix(certType.sslSettingPrefix());
            this.enforceClassicalFallback = settings.getAsBoolean(
                SSLConfigConstants.SECURITY_SSL_ENFORCE_CLASSICAL_FALLBACK,
                false
            );
        }

        private SslProvider provider() {
            return SslProvider.JDK;
        }

        private boolean validateCertDNsOnReload(final Settings settings) {
            return settings.getAsBoolean(ENFORCE_CERT_RELOAD_DN_VERIFICATION, true);
        }

        private List<String> protocols(final Settings settings) {
            final var allowedProtocols = settings.getAsList(ENABLED_PROTOCOLS, List.of(ALLOWED_SSL_PROTOCOLS));
            return jdkProtocols(allowedProtocols);
        }

        private List<String> jdkProtocols(final List<String> allowedSslProtocols) {
            try {
                final var supportedProtocols = SSLContext.getDefault().getDefaultSSLParameters().getProtocols();
                LOGGER.debug("JVM supports the following {} protocols {}", supportedProtocols.length, supportedProtocols);
                return Stream.of(supportedProtocols).filter(allowedSslProtocols::contains).collect(Collectors.toList());
            } catch (final NoSuchAlgorithmException e) {
                throw new OpenSearchException("Unable to determine supported protocols", e);
            }
        }

        private List<String> namedGroups(final Settings settings) {
            // PQC POC: no filtering against JVM defaults — the group is provided by the BCJSSE provider,
            // not SunJSSE, so we pass the configured names straight through to the SSLEngine.
            return settings.getAsList(ENABLED_GROUPS, java.util.Collections.emptyList());
        }

        private List<String> signatureSchemes(final Settings settings) {
            // PQC: pass configured signature schemes (e.g. "mldsa65") through to the SSLEngine unchanged.
            return settings.getAsList(ENABLED_SIGNATURE_SCHEMES, java.util.Collections.emptyList());
        }

        private List<String> ciphers(final Settings settings) {
            final var allowed = settings.getAsList(ENABLED_CIPHERS, List.of(ALLOWED_SSL_CIPHERS));
            final Stream<String> allowedCiphers;
            try {
                final var supportedCiphers = SSLContext.getDefault().getDefaultSSLParameters().getCipherSuites();
                LOGGER.debug("JVM supports the following {} ciphers {}", supportedCiphers.length, supportedCiphers);
                allowedCiphers = Stream.of(supportedCiphers).filter(allowed::contains);
            } catch (final NoSuchAlgorithmException e) {
                throw new OpenSearchException("Unable to determine ciphers protocols", e);
            }
            return allowedCiphers.sorted(String::compareTo).collect(Collectors.toList());
        }

        public SslParameters load() {
            ClientAuth clientAuth;
            if (certType == CertType.TRANSPORT || certType == CertType.TRANSPORT_CLIENT) {
                clientAuth = SECURITY_SSL_TRANSPORT_CLIENTAUTH_MODE_DEFAULT;
            } else {
                clientAuth = ClientAuth.valueOf(
                    sslConfigSettings.get(CLIENT_AUTH_MODE, ClientAuth.OPTIONAL.name()).toUpperCase(Locale.ROOT)
                );
            }

            final var provider = provider();
            final var sslParameters = new SslParameters(
                provider,
                clientAuth,
                protocols(sslConfigSettings),
                ciphers(sslConfigSettings),
                namedGroups(sslConfigSettings),
                signatureSchemes(sslConfigSettings),
                validateCertDNsOnReload(sslConfigSettings)
            );
            if (sslParameters.allowedProtocols().isEmpty()) {
                throw new OpenSearchSecurityException("No ssl protocols for " + certType.id() + " layer");
            }
            if (sslParameters.allowedCiphers().isEmpty()) {
                throw new OpenSearchSecurityException("No valid cipher suites for " + certType.id() + " layer");
            }
            validatePqcParameters(sslParameters.namedGroups(), sslParameters.signatureSchemes());
            return sslParameters;
        }

        /**
         * PQC readiness guards for a layer's TLS key-exchange groups and signature schemes:
         * <ol>
         *   <li><b>Validation</b> — reject unknown group/scheme names up-front with a clear error, instead of
         *       letting the provider silently drop them (which yields a confusing handshake failure at runtime).</li>
         *   <li><b>Rolling-upgrade guard</b> — a PQC-only list (no classical fallback) cannot interoperate with
         *       peers/clients that lack PQC, so it can strand a node during a rolling upgrade. Warn loudly by
         *       default; hard-fail when {@code plugins.security.ssl.enforce_classical_fallback: true}.</li>
         * </ol>
         */
        private void validatePqcParameters(final List<String> groups, final List<String> signatureSchemes) {
            validateKnownNames(groups, "TLS group", SSLConfigConstants.KNOWN_CLASSICAL_GROUPS, SSLConfigConstants.KNOWN_PQC_GROUPS);
            validateKnownNames(
                signatureSchemes,
                "signature scheme",
                SSLConfigConstants.KNOWN_CLASSICAL_SIGNATURE_SCHEMES,
                SSLConfigConstants.KNOWN_PQC_SIGNATURE_SCHEMES
            );
            guardClassicalFallback(groups, "key-exchange groups", SSLConfigConstants.KNOWN_CLASSICAL_GROUPS);
            guardClassicalFallback(signatureSchemes, "signature schemes", SSLConfigConstants.KNOWN_CLASSICAL_SIGNATURE_SCHEMES);
        }

        private void validateKnownNames(
            final List<String> configured,
            final String kind,
            final java.util.Set<String> classical,
            final java.util.Set<String> pqc
        ) {
            if (configured == null) {
                return;
            }
            for (final String name : configured) {
                final String key = name.toLowerCase(Locale.ROOT);
                if (!classical.contains(key) && !pqc.contains(key)) {
                    throw new OpenSearchSecurityException(
                        "Unknown "
                            + kind
                            + " ["
                            + name
                            + "] configured for the "
                            + certType.id()
                            + " layer. Known values: "
                            + classical
                            + " (classical) and "
                            + pqc
                            + " (post-quantum)."
                    );
                }
            }
        }

        private void guardClassicalFallback(final List<String> configured, final String kind, final java.util.Set<String> classical) {
            if (configured == null || configured.isEmpty()) {
                return; // provider default => classical present, safe
            }
            final boolean hasClassical = configured.stream().map(s -> s.toLowerCase(Locale.ROOT)).anyMatch(classical::contains);
            if (!hasClassical) {
                final String message = "The "
                    + certType.id()
                    + " layer is configured with post-quantum-only "
                    + kind
                    + " "
                    + configured
                    + " and no classical fallback. Peers or clients without post-quantum support will FAIL to connect; "
                    + "this can strand a node during a rolling upgrade. Add a classical entry (e.g. x25519/secp256r1 for "
                    + "groups, ecdsa_secp256r1_sha256 for signature schemes) unless PQC-only is intended.";
                if (enforceClassicalFallback) {
                    throw new OpenSearchSecurityException(
                        message + " (rejected because " + SSLConfigConstants.SECURITY_SSL_ENFORCE_CLASSICAL_FALLBACK + "=true)"
                    );
                }
                LOGGER.warn(message);
            }
        }
    }
}
