package com.tesco.encryptionservice.ssh.certificate;

import com.tesco.encryptionservice.ssh.parser.algorithms.SshRsaCertV01;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.SneakyThrows;
import lombok.experimental.Accessors;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * RSA certificate format:
 * <p>
 * <pre>
 * string    "ssh-rsa-cert-v01@openssh.com"
 * string    nonce
 * mpint     e
 * mpint     n
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
public class RsaSshCertificate extends SshCertificate<RSAPublicKey> {

    private byte[] nonce;
    private BigInteger e;
    private BigInteger n;

    public RsaSshCertificate() {
        sshCertificateAlgorithm = new SshRsaCertV01();
    }

    @SneakyThrows
    public RSAPublicKey publicKey() {
        KeyFactory keyPairGenerator = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyPairGenerator.generatePublic(new RSAPublicKeySpec(n, e));
    }

    public StringBuilder compare(RsaSshCertificate that) {
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
        boolean exponentMatches = Objects.equals(e, that.e);
        if (!exponentMatches) {
            matchErrors
                    .append("\n")
                    .append("exponent does not match, found: ")
                    .append(that.e)
                    .append(" expected: ")
                    .append(e);
        }
        boolean modulusMatches = Objects.equals(n, that.n);
        if (!modulusMatches) {
            matchErrors
                    .append("\n")
                    .append("modulus does not match, found: ")
                    .append(that.n)
                    .append(" expected: ")
                    .append(n);
        }
        return matchErrors;
    }
}
