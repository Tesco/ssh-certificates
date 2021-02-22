package com.tesco.encryptionservice.ssh.certificate;

import com.tesco.encryptionservice.ssh.parser.algorithms.SshCertificateAlgorithm;
import lombok.Data;
import lombok.experimental.Accessors;

import java.math.BigInteger;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Objects;

/**
 * Common certificate format:
 * <p>
 * <pre>
 * string    algorithm
 * ... <fields to specific type> ...
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
public abstract class SshCertificate<T extends PublicKey> {

    protected SshCertificateAlgorithm<T> sshCertificateAlgorithm;

    protected BigInteger serial;
    protected SshCertificateType type;
    protected String keyId;
    protected LinkedHashSet<String> validPrincipals = new LinkedHashSet<>();
    protected Instant validAfter;
    protected Instant validBefore;
    protected LinkedHashMap<String, String> criticalOptions = new LinkedHashMap<>();
    protected LinkedHashMap<String, String> extensions = new LinkedHashMap<>();
    protected String reserved = "";
    protected PublicKey signatureKey;
    protected String signatureAlgorithm;
    protected byte[] signature;

    public SshCertificate<T> addPrincipal(String principal) {
        validPrincipals.add(principal);
        return this;
    }

    public SshCertificate<T> addCriticalOption(String key, String value) {
        criticalOptions.put(key, value);
        return this;
    }

    public SshCertificate<T> addCriticalOption(SshCriticalOption sshCriticalOption, String value) {
        criticalOptions.put(sshCriticalOption.getKey(), value);
        return this;
    }

    public SshCertificate<T> addExtension(String key, String value) {
        extensions.put(key, value);
        return this;
    }

    public SshCertificate<T> addExtension(SshPermission sshPermission, String value) {
        extensions.put(sshPermission.getKey(), value);
        return this;
    }

    public abstract T publicKey();

    public StringBuilder compare(SshCertificate<T> that) {
        StringBuilder matchErrors = new StringBuilder();
        boolean sshCertificateAlgorithmMatches = sshCertificateAlgorithm == that.sshCertificateAlgorithm;
        if (!sshCertificateAlgorithmMatches) {
            matchErrors
                    .append("\n")
                    .append("sshCertificateAlgorithm does not match, found: ")
                    .append(that.sshCertificateAlgorithm)
                    .append(" expected: ")
                    .append(sshCertificateAlgorithm);
        }
        boolean serialMatches = serial.longValue() == that.serial.longValue();
        if (!serialMatches) {
            matchErrors
                    .append("\n")
                    .append("serial does not match, found: ")
                    .append(that.serial)
                    .append(" expected: ")
                    .append(serial);
        }
        boolean typeMatches = type == that.type;
        if (!typeMatches) {
            matchErrors
                    .append("\n")
                    .append("type does not match, found: ")
                    .append(that.type)
                    .append(" expected: ")
                    .append(type);
        }
        boolean keyIdMatches = Objects.equals(keyId, that.keyId);
        if (!keyIdMatches) {
            matchErrors
                    .append("\n")
                    .append("keyId does not match, found: ")
                    .append(that.keyId)
                    .append(" expected: ")
                    .append(keyId);
        }
        boolean validPrincipalsMatches = Objects.equals(validPrincipals, that.validPrincipals);
        if (!validPrincipalsMatches) {
            matchErrors
                    .append("\n")
                    .append("validPrincipals does not match, found: ")
                    .append(that.validPrincipals)
                    .append(" expected: ")
                    .append(validPrincipals);
        }
        boolean validAfterMatches = Objects.equals(validAfter, that.validAfter);
        if (!validAfterMatches) {
            matchErrors
                    .append("\n")
                    .append("validAfter does not match, found: ")
                    .append(that.validAfter)
                    .append(" expected: ")
                    .append(validAfter);
        }
        boolean validBeforeMatches = Objects.equals(validBefore, that.validBefore);
        if (!validBeforeMatches) {
            matchErrors
                    .append("\n")
                    .append("validBefore does not match, found: ")
                    .append(that.validBefore)
                    .append(" expected: ")
                    .append(validBefore);
        }
        boolean criticalOptionsMatches = Objects.equals(criticalOptions, that.criticalOptions);
        if (!criticalOptionsMatches) {
            matchErrors
                    .append("\n")
                    .append("criticalOptions does not match, found: ")
                    .append(that.criticalOptions)
                    .append(" expected: ")
                    .append(criticalOptions);
        }
        boolean extensionsMatches = Objects.equals(extensions, that.extensions);
        if (!extensionsMatches) {
            matchErrors
                    .append("\n")
                    .append("extensions does not match, found: ")
                    .append(that.extensions)
                    .append(" expected: ")
                    .append(extensions);
        }
        boolean reservedMatches = Objects.equals(reserved, that.reserved);
        if (!reservedMatches) {
            matchErrors
                    .append("\n")
                    .append("reserved does not match, found: ")
                    .append(that.reserved)
                    .append(" expected: ")
                    .append(reserved);
        }
        boolean signatureKeyMatches = Objects.equals(signatureKey, that.signatureKey);
        if (!signatureKeyMatches) {
            matchErrors
                    .append("\n")
                    .append("signatureKey does not match, found: ")
                    .append(that.signatureKey)
                    .append(" expected: ")
                    .append(signatureKey);
        }
        boolean signatureAlgorithmMatches = Objects.equals(signatureAlgorithm, that.signatureAlgorithm);
        if (!signatureAlgorithmMatches) {
            matchErrors
                    .append("\n")
                    .append("signatureAlgorithm does not match, found: ")
                    .append(that.signatureAlgorithm)
                    .append(" expected: ")
                    .append(signatureAlgorithm);
        }
        boolean signatureMatches = Arrays.equals(signature, that.signature);
        if (!signatureMatches) {
            matchErrors
                    .append("\n")
                    .append("signature does not match, found:\n  ")
                    .append(Arrays.toString(that.signature))
                    .append("\nexpected:\n  ")
                    .append(Arrays.toString(signature));
        }
        return matchErrors;
    }
}