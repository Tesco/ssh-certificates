package com.tesco.encryptionservice.ssh.certificate;

import com.tesco.encryptionservice.ssh.parser.algorithms.SshCertificateAlgorithm;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Objects;

/**
 * ECDSA certificate format:
 * <p>
 * <pre>
 * string    "ecdsa-sha2-nistp256-cert-v01@openssh.com"
 *           | "ecdsa-sha2-nistp384-cert-v01@openssh.com"
 *           | "ecdsa-sha2-nistp521-cert-v01@openssh.com"
 * string    nonce
 * string    curve
 * string    public_key
 * uint64    serial
 * uint32    type
 * string    key id
 * string    valid principals
 * uint64    valid after
 * uint64    valid before
 * string    critical options
 * string    extensions
 * string    reserved
 * string    signature key
 * string    signatureAlgorithm
 * string    signature
 * </pre>
 * </p>
 */
@Data
@Accessors(fluent = true)
@EqualsAndHashCode(callSuper = true)
public class EcdsaSshCertificate extends SshCertificate<ECPublicKey> {

    /**
     * https://www.openssh.com/specs.html
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
     * <p>
     * https://www.openssh.com/specs.html
     * https://tools.ietf.org/html/rfc5656#section-10.1
     * <pre>
     * 10.1.  Required Curves
     *
     *    Every SSH ECC implementation MUST support the named curves below.
     *    These curves are defined in [SEC2]; the NIST curves were originally
     *    defined in [NIST-CURVES].  These curves SHOULD always be enabled
     *    unless specifically disabled by local security policy.
     *
     *               +----------+-----------+---------------------+
     *               |   NIST*  |    SEC    |         OID         |
     *               +----------+-----------+---------------------+
     *               | nistp256 | secp256r1 | 1.2.840.10045.3.1.7 |
     *               |          |           |                     |
     *               | nistp384 | secp384r1 |     1.3.132.0.34    |
     *               |          |           |                     |
     *               | nistp521 | secp521r1 |     1.3.132.0.35    |
     *               +----------+-----------+---------------------+
     *
     *       *  For these three REQUIRED curves, the elliptic curve domain
     *          parameter identifier is the string in the first column of the
     *          table, the NIST name of the curve.  (See Section 6.1.)
     *
     * 10.2.  Recommended Curves
     *
     *    It is RECOMMENDED that SSH ECC implementations also support the
     *    following curves.  These curves are defined in [SEC2].
     *
     *               +----------+-----------+---------------------+
     *               |   NIST   |    SEC    |         OID*        |
     *               +----------+-----------+---------------------+
     *               | nistk163 | sect163k1 |     1.3.132.0.1     |
     *               |          |           |                     |
     *               | nistp192 | secp192r1 | 1.2.840.10045.3.1.1 |
     *               |          |           |                     |
     *               | nistp224 | secp224r1 |     1.3.132.0.33    |
     *               |          |           |                     |
     *               | nistk233 | sect233k1 |     1.3.132.0.26    |
     *               |          |           |                     |
     *               | nistb233 | sect233r1 |     1.3.132.0.27    |
     *               |          |           |                     |
     *               | nistk283 | sect283k1 |     1.3.132.0.16    |
     *               |          |           |                     |
     *               | nistk409 | sect409k1 |     1.3.132.0.36    |
     *               |          |           |                     |
     *               | nistb409 | sect409r1 |     1.3.132.0.37    |
     *               |          |           |                     |
     *               | nistt571 | sect571k1 |     1.3.132.0.38    |
     *               +----------+-----------+---------------------+
     *
     *       *  For these RECOMMENDED curves, the elliptic curve domain
     *          parameter identifier is the string in the third column of the
     *          table, the ASCII representation of the OID of the curve.  (See
     *          Section 6.1.)
     * </pre>
     */

    public static final LinkedHashMap<String, String> SUPPORTED_EC_CURVES = new LinkedHashMap<>();

    static {
        // required curves (referenced by name)
        SUPPORTED_EC_CURVES.put("nistp256", "secp256r1");
        SUPPORTED_EC_CURVES.put("1.2.840.10045.3.1.7", "secp256r1");
        SUPPORTED_EC_CURVES.put("nistp384", "secp384r1");
        SUPPORTED_EC_CURVES.put("1.3.132.0.34", "secp384r1");
        SUPPORTED_EC_CURVES.put("nistp521", "secp521r1");
        SUPPORTED_EC_CURVES.put("1.3.132.0.35", "secp521r1");
        // recommended curves (referenced by OID)
        SUPPORTED_EC_CURVES.put("1.3.132.0.1", "sect163k1");
        SUPPORTED_EC_CURVES.put("nistk163", "sect163k1");
        SUPPORTED_EC_CURVES.put("1.2.840.10045.3.1.1", "secp192r1");
        SUPPORTED_EC_CURVES.put("nistp192", "secp192r1");
        SUPPORTED_EC_CURVES.put("1.3.132.0.33", "secp224r1");
        SUPPORTED_EC_CURVES.put("nistp224", "secp224r1");
        SUPPORTED_EC_CURVES.put("1.3.132.0.26", "sect233k1");
        SUPPORTED_EC_CURVES.put("nistk233", "sect233k1");
        SUPPORTED_EC_CURVES.put("1.3.132.0.27", "sect233r1");
        SUPPORTED_EC_CURVES.put("nistb233", "sect233r1");
        SUPPORTED_EC_CURVES.put("1.3.132.0.16", "sect283k1");
        SUPPORTED_EC_CURVES.put("nistk283", "sect283k1");
        SUPPORTED_EC_CURVES.put("1.3.132.0.36", "sect409k1");
        SUPPORTED_EC_CURVES.put("nistk409", "sect409k1");
        SUPPORTED_EC_CURVES.put("1.3.132.0.37", "sect409r1");
        SUPPORTED_EC_CURVES.put("nistb409", "sect409r1");
        SUPPORTED_EC_CURVES.put("1.3.132.0.38", "sect571k1");
        SUPPORTED_EC_CURVES.put("nistt571", "sect571k1");
    }

    private byte[] nonce;
    private String curve;
    private ECPublicKey publicKey;

    public EcdsaSshCertificate(SshCertificateAlgorithm<ECPublicKey> certificateAlgorithm) {
        sshCertificateAlgorithm = certificateAlgorithm;
    }

    public StringBuilder compare(EcdsaSshCertificate that) {
        StringBuilder matchErrors = super.compare(that);
        boolean nonceMatches = Arrays.equals(nonce, that.nonce);
        if (!nonceMatches) {
            matchErrors
                    .append("\n")
                    .append("nonce does not match, found: ")
                    .append(Arrays.toString(that.nonce))
                    .append(" expected: ")
                    .append(Arrays.toString(nonce));
        }
        boolean curveMatches = Objects.equals(curve, that.curve);
        if (!curveMatches) {
            matchErrors
                    .append("\n")
                    .append("curve does not match, found: ")
                    .append(that.curve)
                    .append(" expected: ")
                    .append(curve);
        }
        boolean publicKeyMatches = Objects.equals(publicKey, that.publicKey);
        if (!publicKeyMatches) {
            matchErrors
                    .append("\n")
                    .append("publicKey does not match, found: ")
                    .append(that.publicKey)
                    .append(" expected: ")
                    .append(publicKey);
        }
        return matchErrors;
    }
}
