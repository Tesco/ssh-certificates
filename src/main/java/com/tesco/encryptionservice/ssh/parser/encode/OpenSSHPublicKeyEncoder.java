package com.tesco.encryptionservice.ssh.parser.encode;

import lombok.SneakyThrows;
import sun.security.util.ECUtil;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static com.tesco.encryptionservice.ssh.parser.decode.OpenSSHPublicKeyDecoder.lookupCurveName;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;

public class OpenSSHPublicKeyEncoder {

    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();

    /**
     * https://www.openssh.com/specs.html
     * <p>
     * https://tools.ietf.org/html/rfc4253#section-6.6
     * <pre>
     *    Certificates and public keys are encoded as follows:
     *
     *       string    certificate or public key format identifier
     *       byte[n]   key/certificate data
     * </pre>
     * <p>
     * RSA Keys (old SHA-1)
     * <p>
     * https://tools.ietf.org/html/rfc4253#section-6.6
     * <pre>
     *    The "ssh-rsa" key format has the following specific encoding:
     *
     *       string    "ssh-rsa"
     *       mpint     e
     *       mpint     n
     *
     *    Here the 'e' and 'n' parameters form the signature key blob.
     * </pre>
     * <p>
     * RSA Keys with SHA-2 256 and 512 (new in OpenSSH 7.2)
     * <p>
     * https://tools.ietf.org/html/rfc8332#section-3
     * <pre>
     *    Since RSA keys are not dependent on the choice of hash function, the
     *    new public key algorithms reuse the "ssh-rsa" public key format as
     *    defined in [RFC4253]:
     *
     *    string    "ssh-rsa"
     *    mpint     e
     *    mpint     n
     *
     *    All aspects of the "ssh-rsa" format are kept, including the encoded
     *    string "ssh-rsa".  This allows existing RSA keys to be used with the
     *    new public key algorithms, without requiring re-encoding or affecting
     *    already trusted key fingerprints.
     * </pre>
     * <p>
     * Elliptic Curve
     * <p>
     * https://tools.ietf.org/html/rfc5656#section-3.1
     * <pre>
     * 3.1.  Key Format
     *
     *    The "ecdsa-sha2-*" key formats all have the following encoding:
     *
     *       string   "ecdsa-sha2-[identifier]"
     *       byte[n]  ecc_key_blob
     *
     *    The ecc_key_blob value has the following specific encoding:
     *
     *       string   [identifier]
     *       string   Q
     *
     *    The string [identifier] is the identifier of the elliptic curve
     *    domain parameters.  The format of this string is specified in
     *    Section 6.1.  Information on the REQUIRED and RECOMMENDED sets of
     *    elliptic curve domain parameters for use with this algorithm can be
     *    found in Section 10.
     *
     *    Q is the public key encoded from an elliptic curve point into an
     *    octet string as defined in Section 2.3.3 of [SEC1]; point compression
     *    MAY be used.
     *
     *    The algorithm for ECC key generation can be found in Section 3.2 of
     *    [SEC1].  Given some elliptic curve domain parameters, an ECC key pair
     *    can be generated containing a private key (an integer d), and a
     *    public key (an elliptic curve point Q).
     * </pre>
     * <p>
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

    @SneakyThrows
    public static void encodePublicKey(PublicKey publicKey, String comment, File publicKeyFile) {
        Files.writeString(publicKeyFile.toPath(), encodePublicKey(publicKey, comment), Charset.defaultCharset(), CREATE, TRUNCATE_EXISTING);
    }

    public static String encodePublicKey(PublicKey publicKey, String comment) {
        return encodeFormat(publicKey) +
                " " +
                BASE64_ENCODER.encodeToString(encodePublicKey(publicKey)) +
                " " +
                comment;
    }

    @SneakyThrows
    public static byte[] encodePublicKey(PublicKey publicKey) {
        ByteOutputStream byteOutputStream = ByteOutputStream.getInstance();
        byteOutputStream.writeString(encodeFormat(publicKey));
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            byteOutputStream.writeBigInteger(rsaPublicKey.getPublicExponent());
            byteOutputStream.writeBigInteger(rsaPublicKey.getModulus());
        } else if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            byteOutputStream.writeString(lookupCurveName((ECPublicKey) publicKey));
            byteOutputStream.writeBytes(ECUtil.encodePoint(ecPublicKey.getW(), ecPublicKey.getParams().getCurve()));
        } else {
            throw new IllegalArgumentException("Unsupported public key type \"" + publicKey.getClass().getSimpleName() + "\" only RSAPublicKey and ECPublicKey supported");
        }
        return byteOutputStream.toByteArray();
    }

    @SneakyThrows
    public static String encodeFormat(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey) {
            return "ssh-rsa";
        } else if (publicKey instanceof ECPublicKey) {
            return "ecdsa-sha2-" + lookupCurveName((ECPublicKey) publicKey);
        } else {
            throw new IllegalArgumentException("Unsupported public key type \"" + publicKey.getClass().getSimpleName() + "\" only RSAPublicKey and ECPublicKey supported");
        }
    }
}
