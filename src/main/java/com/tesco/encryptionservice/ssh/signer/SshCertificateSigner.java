package com.tesco.encryptionservice.ssh.signer;

import com.tesco.encryptionservice.ssh.certificate.SshCertificate;
import com.tesco.encryptionservice.ssh.parser.decode.OpenSSHPublicKeyDecoder;
import lombok.SneakyThrows;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import static java.util.Map.of;

public class SshCertificateSigner {

    /**
     * RSA Keys (old SHA-1)
     * <p>
     * https://tools.ietf.org/html/rfc4253#section-6.6
     * <pre>
     *    Signing and verifying using this key format is performed according to
     *    the RSASSA-PKCS1-v1_5 scheme in [RFC3447] using the SHA-1 hash.
     *
     *    The resulting signature is encoded as follows:
     *
     *       string    "ssh-rsa"
     *       string    rsa_signature_blob
     *
     *    The value for 'rsa_signature_blob' is encoded as a string containing
     *    s (which is an integer, without lengths or padding, unsigned, and in
     *    network byte order).
     * </pre>
     * <p>
     * RSA Keys with SHA-2 256 and 512 (new in OpenSSH 7.2)
     * <p>
     * https://tools.ietf.org/html/rfc8332#section-3
     * <pre>
     *    Signing and verifying using these algorithms is performed according
     *    to the RSASSA-PKCS1-v1_5 scheme in [RFC8017] using SHA-2 [SHS] as
     *    hash.
     *
     *    For the algorithm "rsa-sha2-256", the hash used is SHA-256.
     *    For the algorithm "rsa-sha2-512", the hash used is SHA-512.
     *
     *    The resulting signature is encoded as follows:
     *
     *    string   "rsa-sha2-256" / "rsa-sha2-512"
     *    string    rsa_signature_blob
     * </pre>
     * <p>
     * Elliptic Curve
     * <p>
     * https://tools.ietf.org/html/rfc5656#section-6.2.1
     * <pre>
     * 6.2.1.  Elliptic Curve Digital Signature Algorithm
     *
     *    The Elliptic Curve Digital Signature Algorithm (ECDSA) is specified
     *    for use with the SSH ECC public key algorithm.
     *
     *    The hashing algorithm defined by this family of method names is the
     *    SHA2 family of hashing algorithms [FIPS-180-3].  The algorithm from
     *    the SHA2 family that will be used is chosen based on the size of the
     *    named curve specified in the public key:
     *
     *                     +----------------+----------------+
     *                     |   Curve Size   | Hash Algorithm |
     *                     +----------------+----------------+
     *                     |    b <= 256    |     SHA-256    |
     *                     |                |                |
     *                     | 256 < b <= 384 |     SHA-384    |
     *                     |                |                |
     *                     |     384 < b    |     SHA-512    |
     *                     +----------------+----------------+
     * </pre>
     */

    public static final Map<String, String> SUPPORTED_CA_SIGNING_ALGORITHMS = of(
            "ecdsa-sha2-nistp256", "SHA256withECDSA",
            "ecdsa-sha2-nistp384", "SHA384withECDSA",
            "ecdsa-sha2-nistp521", "SHA512withECDSA",
            "rsa-sha2-512", "SHA512withRSA",
            "rsa-sha2-256", "SHA256withRSA",
            "ssh-rsa", "SHA1WithRSA"
    );
    private static final String DEFAULT_SIGNING_ALGORITHM = "rsa-sha2-256";

    public static <T extends PublicKey> SshCertificate<T> sign(SshCertificate<T> certificate, KeyPair signingKeyPair) {
        return sign(certificate, signingKeyPair.getPublic(), signingKeyPair.getPrivate());
    }

    @SneakyThrows
    @SuppressWarnings("UnusedReturnValue")
    public static <T extends PublicKey> SshCertificate<T> sign(SshCertificate<T> certificate, PublicKey signingPublicKey, PrivateKey signingPrivateKey) {
        String algorithm;
        if (signingPublicKey instanceof RSAPublicKey) {
            algorithm = DEFAULT_SIGNING_ALGORITHM;
        } else if (signingPublicKey instanceof ECPublicKey) {
            algorithm = "ecdsa-sha2-" + OpenSSHPublicKeyDecoder.lookupCurveName((ECPublicKey) signingPublicKey);
        } else {
            throw new IllegalArgumentException("Unsupported signing key type \"" + signingPublicKey.getClass().getSimpleName() + "\" expected RSAPublicKey or ECPublicKey");
        }
        return sign(certificate, signingPublicKey, signingPrivateKey, algorithm);
    }

    @SneakyThrows
    @SuppressWarnings("UnusedReturnValue")
    public static <T extends PublicKey> SshCertificate<T> sign(SshCertificate<T> certificate, PublicKey signingPublicKey, PrivateKey signingPrivateKey, String algorithm) {
        certificate.signatureKey(signingPublicKey);
        byte[] bytesToSign = certificate.sshCertificateAlgorithm().encoder().encodeSignedBytes(certificate);

        if (!SUPPORTED_CA_SIGNING_ALGORITHMS.containsKey(algorithm)) {
            throw new IllegalArgumentException("Unsupported signing algorithm \"" + algorithm + "\" expected one of " + SUPPORTED_CA_SIGNING_ALGORITHMS.keySet());
        }

        Signature signer = Signature.getInstance(SUPPORTED_CA_SIGNING_ALGORITHMS.get(algorithm));
        signer.initSign(signingPrivateKey);
        signer.update(bytesToSign);

        certificate.signatureAlgorithm(algorithm);
        certificate.signature(certificate.sshCertificateAlgorithm().encoder().encodeSignature(algorithm, signer.sign()));

        if (verify(certificate)) {
            return certificate;
        } else {
            throw new IllegalArgumentException("unable to validate certificate signature");
        }
    }

    @SneakyThrows
    public static <T extends PublicKey> boolean verify(SshCertificate<T> certificate) {
        return verify(certificate, certificate.signatureKey());
    }

    @SneakyThrows
    public static <T extends PublicKey> boolean verify(SshCertificate<T> certificate, PublicKey signingPublicKey) {
        byte[] signedBytes = certificate.sshCertificateAlgorithm().encoder().encodeSignedBytes(certificate);
        byte[] signature = certificate.signature();

        Signature verifier = Signature.getInstance(SUPPORTED_CA_SIGNING_ALGORITHMS.get(certificate.signatureAlgorithm()));
        verifier.initVerify(signingPublicKey);
        verifier.update(signedBytes);

        return verifier.verify(certificate.sshCertificateAlgorithm().decoder().decodeSignature(certificate.signatureAlgorithm(), signature));
    }
}
