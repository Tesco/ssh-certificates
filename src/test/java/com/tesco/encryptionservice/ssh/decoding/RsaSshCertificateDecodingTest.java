package com.tesco.encryptionservice.ssh.decoding;

import com.tesco.encryptionservice.ssh.certificate.RsaSshCertificate;
import com.tesco.encryptionservice.ssh.certificate.SshCertificateType;
import com.tesco.encryptionservice.ssh.parser.algorithms.SshCertificateAlgorithm;
import com.tesco.encryptionservice.ssh.parser.algorithms.SshRsaCertV01;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Random;
import java.util.UUID;

import static com.tesco.encryptionservice.ssh.signer.SshCertificateSigner.SUPPORTED_CA_SIGNING_ALGORITHMS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsEmptyCollection.empty;
import static org.hamcrest.collection.IsIterableContainingInOrder.contains;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static org.hamcrest.collection.IsMapWithSize.anEmptyMap;
import static org.hamcrest.core.AllOf.allOf;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.hamcrest.number.OrderingComparison.lessThan;

@Tag("UnitTest")
public class RsaSshCertificateDecodingTest extends AbstractDecodingTest {

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showDecodeRsaSshCertificateForUser(String keyLength) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair signingKeyPair = getKeyPair("RSA", caPublicKey, caPrivateKey);
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair leafKeyPair = getKeyPair("RSA", leafPublicKey, leafPrivateKey);
        // and - a leaf certificate
        SshCertificateAlgorithm<RSAPublicKey> sshCertificateAlgorithm = new SshRsaCertV01();
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();
        exec(
                "ssh-keygen",
                "-z", serialNumber,
                "-s", caPrivateKey.getAbsolutePath(),
                "-t", "rsa-sha2-256",
                "-I", keyId,
                "-n", "principle:one,principle:two",
                "-V", "-1d:+5d",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // when
        RsaSshCertificate rsaSshCertificate = (RsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate);

        // then
        assertThat("nonce", rsaSshCertificate.nonce().length, equalTo(32));
        assertThat("n", rsaSshCertificate.n(), is(((RSAPublicKey) leafKeyPair.getPublic()).getModulus()));
        assertThat("e", rsaSshCertificate.e(), is(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent()));
        assertThat("serial", rsaSshCertificate.serial().toString(), equalTo(serialNumber));
        assertThat("type", rsaSshCertificate.type(), equalTo(SshCertificateType.SSH_CERT_TYPE_USER));
        assertThat("keyId", rsaSshCertificate.keyId(), equalTo(keyId));
        assertThat("validPrincipals", rsaSshCertificate.validPrincipals(), contains(
                "principle:one",
                "principle:two"
        ));
        assertThat("validAfter", rsaSshCertificate.validAfter().toEpochMilli(), allOf(
                greaterThan(Instant.now().minus(Duration.ofDays(1)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().minus(Duration.ofDays(1)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("validBefore", rsaSshCertificate.validBefore().toEpochMilli(), allOf(
                greaterThan(Instant.now().plus(Duration.ofDays(5)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().plus(Duration.ofDays(5)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("criticalOptions", rsaSshCertificate.criticalOptions(), anEmptyMap());
        assertThat("extensions", rsaSshCertificate.extensions(), allOf(
                hasEntry("permit-X11-forwarding", ""),
                hasEntry("permit-agent-forwarding", ""),
                hasEntry("permit-port-forwarding", ""),
                hasEntry("permit-user-rc", "")
        ));
        assertThat("reserved", rsaSshCertificate.reserved(), equalTo(""));
        assertThat("signatureKey", rsaSshCertificate.signatureKey(), equalTo(signingKeyPair.getPublic()));
        assertThat("signatureAlgorithm", rsaSshCertificate.signatureAlgorithm(), equalTo("rsa-sha2-256"));

        Signature signer = Signature.getInstance(SUPPORTED_CA_SIGNING_ALGORITHMS.get(rsaSshCertificate.signatureAlgorithm()));
        signer.initSign(signingKeyPair.getPrivate());
        signer.update(sshCertificateAlgorithm.encoder().encodeSignedBytes(rsaSshCertificate));
        assertThat("signature", rsaSshCertificate.signature(), equalTo(sshCertificateAlgorithm.encoder().encodeSignature("rsa-sha2-256", signer.sign())));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}, signing algorithm - {1}")
    @CsvSource({
            "2048,ssh-rsa",
            "2048,rsa-sha2-256",
            "2048,rsa-sha2-256",
            "3072,ssh-rsa",
            "3072,rsa-sha2-256",
            "3072,rsa-sha2-256",
            "4096,ssh-rsa",
            "4096,rsa-sha2-256",
            "4096,rsa-sha2-256",
    })
    public void showDecodeRsaSshCertificateForUserWithDifferentSigningAlgorithms(String keyLength, String signingAlgorithm) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair signingKeyPair = getKeyPair("RSA", caPublicKey, caPrivateKey);
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair leafKeyPair = getKeyPair("RSA", leafPublicKey, leafPrivateKey);
        // and - a leaf certificate
        SshCertificateAlgorithm<RSAPublicKey> sshCertificateAlgorithm = new SshRsaCertV01();
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();
        exec(
                "ssh-keygen",
                "-z", serialNumber,
                "-s", caPrivateKey.getAbsolutePath(),
                "-t", signingAlgorithm,
                "-I", keyId,
                "-n", "principle:one,principle:two",
                "-V", "-1d:+5d",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // when
        RsaSshCertificate rsaSshCertificate = (RsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate);

        // then
        assertThat("nonce", rsaSshCertificate.nonce().length, equalTo(32));
        assertThat("n", rsaSshCertificate.n(), is(((RSAPublicKey) leafKeyPair.getPublic()).getModulus()));
        assertThat("e", rsaSshCertificate.e(), is(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent()));
        assertThat("serial", rsaSshCertificate.serial().toString(), equalTo(serialNumber));
        assertThat("type", rsaSshCertificate.type(), equalTo(SshCertificateType.SSH_CERT_TYPE_USER));
        assertThat("keyId", rsaSshCertificate.keyId(), equalTo(keyId));
        assertThat("validPrincipals", rsaSshCertificate.validPrincipals(), contains(
                "principle:one",
                "principle:two"
        ));
        assertThat("validAfter", rsaSshCertificate.validAfter().toEpochMilli(), allOf(
                greaterThan(Instant.now().minus(Duration.ofDays(1)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().minus(Duration.ofDays(1)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("validBefore", rsaSshCertificate.validBefore().toEpochMilli(), allOf(
                greaterThan(Instant.now().plus(Duration.ofDays(5)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().plus(Duration.ofDays(5)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("criticalOptions", rsaSshCertificate.criticalOptions(), anEmptyMap());
        assertThat("extensions", rsaSshCertificate.extensions(), allOf(
                hasEntry("permit-X11-forwarding", ""),
                hasEntry("permit-agent-forwarding", ""),
                hasEntry("permit-port-forwarding", ""),
                hasEntry("permit-user-rc", "")
        ));
        assertThat("reserved", rsaSshCertificate.reserved(), equalTo(""));
        assertThat("signatureKey", rsaSshCertificate.signatureKey(), equalTo(signingKeyPair.getPublic()));
        assertThat("signatureAlgorithm", rsaSshCertificate.signatureAlgorithm(), equalTo(signingAlgorithm));

        Signature signer = Signature.getInstance(SUPPORTED_CA_SIGNING_ALGORITHMS.get(rsaSshCertificate.signatureAlgorithm()));
        signer.initSign(signingKeyPair.getPrivate());
        signer.update(sshCertificateAlgorithm.encoder().encodeSignedBytes(rsaSshCertificate));
        assertThat("signature", rsaSshCertificate.signature(), equalTo(sshCertificateAlgorithm.encoder().encodeSignature(signingAlgorithm, signer.sign())));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showDecodeRsaSshCertificateForUserWithNoPermissions(String keyLength) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair signingKeyPair = getKeyPair("RSA", caPublicKey, caPrivateKey);
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair leafKeyPair = getKeyPair("RSA", leafPublicKey, leafPrivateKey);
        // and - a leaf certificate
        SshCertificateAlgorithm<RSAPublicKey> sshCertificateAlgorithm = new SshRsaCertV01();
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();
        exec(
                "ssh-keygen",
                "-z", serialNumber,
                "-s", caPrivateKey.getAbsolutePath(),
                "-t", "rsa-sha2-256",
                "-I", keyId,
                "-n", "principle:one,principle:two",
                "-V", "-1d:+5d",
                "-O", "clear",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // when
        RsaSshCertificate rsaSshCertificate = (RsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate);

        // then
        assertThat("nonce", rsaSshCertificate.nonce().length, equalTo(32));
        assertThat("n", rsaSshCertificate.n(), is(((RSAPublicKey) leafKeyPair.getPublic()).getModulus()));
        assertThat("e", rsaSshCertificate.e(), is(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent()));
        assertThat("serial", rsaSshCertificate.serial().toString(), equalTo(serialNumber));
        assertThat("type", rsaSshCertificate.type(), equalTo(SshCertificateType.SSH_CERT_TYPE_USER));
        assertThat("keyId", rsaSshCertificate.keyId(), equalTo(keyId));
        assertThat("validPrincipals", rsaSshCertificate.validPrincipals(), contains(
                "principle:one",
                "principle:two"
        ));
        assertThat("validAfter", rsaSshCertificate.validAfter().toEpochMilli(), allOf(
                greaterThan(Instant.now().minus(Duration.ofDays(1)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().minus(Duration.ofDays(1)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("validBefore", rsaSshCertificate.validBefore().toEpochMilli(), allOf(
                greaterThan(Instant.now().plus(Duration.ofDays(5)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().plus(Duration.ofDays(5)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("criticalOptions", rsaSshCertificate.criticalOptions(), anEmptyMap());
        assertThat("extensions", rsaSshCertificate.extensions(), anEmptyMap());
        assertThat("reserved", rsaSshCertificate.reserved(), equalTo(""));
        assertThat("signatureKey", rsaSshCertificate.signatureKey(), equalTo(signingKeyPair.getPublic()));
        assertThat("signatureAlgorithm", rsaSshCertificate.signatureAlgorithm(), equalTo("rsa-sha2-256"));

        Signature signer = Signature.getInstance(SUPPORTED_CA_SIGNING_ALGORITHMS.get(rsaSshCertificate.signatureAlgorithm()));
        signer.initSign(signingKeyPair.getPrivate());
        signer.update(sshCertificateAlgorithm.encoder().encodeSignedBytes(rsaSshCertificate));
        assertThat("signature", rsaSshCertificate.signature(), equalTo(sshCertificateAlgorithm.encoder().encodeSignature("rsa-sha2-256", signer.sign())));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showDecodeRsaSshCertificateForUserWithCustomPermissions(String keyLength) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair signingKeyPair = getKeyPair("RSA", caPublicKey, caPrivateKey);
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair leafKeyPair = getKeyPair("RSA", leafPublicKey, leafPrivateKey);
        // and - a leaf certificate
        SshCertificateAlgorithm<RSAPublicKey> sshCertificateAlgorithm = new SshRsaCertV01();
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();
        exec(
                "ssh-keygen",
                "-z", serialNumber,
                "-s", caPrivateKey.getAbsolutePath(),
                "-t", "rsa-sha2-256",
                "-I", keyId,
                "-n", "principle:one,principle:two",
                "-V", "-1d:+5d",
                "-O", "no-x11-forwarding",
                "-O", "force-command=\"ls -lrt\"",
                "-O", "critical:critical_option_example@example.com=some_option_value",
                "-O", "extension:extension_example@example.com=some_extension_value",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // when
        RsaSshCertificate rsaSshCertificate = (RsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate);

        // then
        assertThat("nonce", rsaSshCertificate.nonce().length, equalTo(32));
        assertThat("n", rsaSshCertificate.n(), is(((RSAPublicKey) leafKeyPair.getPublic()).getModulus()));
        assertThat("e", rsaSshCertificate.e(), is(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent()));
        assertThat("serial", rsaSshCertificate.serial().toString(), equalTo(serialNumber));
        assertThat("type", rsaSshCertificate.type(), equalTo(SshCertificateType.SSH_CERT_TYPE_USER));
        assertThat("keyId", rsaSshCertificate.keyId(), equalTo(keyId));
        assertThat("validPrincipals", rsaSshCertificate.validPrincipals(), contains(
                "principle:one",
                "principle:two"
        ));
        assertThat("validAfter", rsaSshCertificate.validAfter().toEpochMilli(), allOf(
                greaterThan(Instant.now().minus(Duration.ofDays(1)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().minus(Duration.ofDays(1)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("validBefore", rsaSshCertificate.validBefore().toEpochMilli(), allOf(
                greaterThan(Instant.now().plus(Duration.ofDays(5)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().plus(Duration.ofDays(5)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("criticalOptions", rsaSshCertificate.criticalOptions(), allOf(
                hasEntry("force-command", "\"ls -lrt\""),
                hasEntry("critical_option_example@example.com", "some_option_value")
        ));
        assertThat("extensions", rsaSshCertificate.extensions(), allOf(
                hasEntry("permit-agent-forwarding", ""),
                hasEntry("permit-port-forwarding", ""),
                hasEntry("permit-pty", ""),
                hasEntry("permit-user-rc", ""),
                hasEntry("extension_example@example.com", "some_extension_value")
        ));
        assertThat("reserved", rsaSshCertificate.reserved(), equalTo(""));
        assertThat("signatureKey", rsaSshCertificate.signatureKey(), equalTo(signingKeyPair.getPublic()));
        assertThat("signatureAlgorithm", rsaSshCertificate.signatureAlgorithm(), equalTo("rsa-sha2-256"));

        Signature signer = Signature.getInstance(SUPPORTED_CA_SIGNING_ALGORITHMS.get(rsaSshCertificate.signatureAlgorithm()));
        signer.initSign(signingKeyPair.getPrivate());
        signer.update(sshCertificateAlgorithm.encoder().encodeSignedBytes(rsaSshCertificate));
        assertThat("signature", rsaSshCertificate.signature(), equalTo(sshCertificateAlgorithm.encoder().encodeSignature("rsa-sha2-256", signer.sign())));
    }


    @SneakyThrows
    @ParameterizedTest(name = "curve - {0}, key length - {1}")
    @CsvSource({
            "nistp256,2048",
            "nistp256,3072",
            "nistp256,4096",
            "nistp384,2048",
            "nistp384,3072",
            "nistp384,4096",
            "nistp521,2048",
            "nistp521,3072",
            "nistp521,4096",
    })
    public void showDecodeRSASshCertificateForUserWithECSigningKey(String curve, String keyLength) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "ecdsa", "-b", curve.replace("nistp", ""), "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair signingKeyPair = getKeyPair("EC", caPublicKey, caPrivateKey);
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair leafKeyPair = getKeyPair("RSA", leafPublicKey, leafPrivateKey);
        // and - a leaf certificate
        SshCertificateAlgorithm<RSAPublicKey> sshCertificateAlgorithm = new SshRsaCertV01();
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();
        exec(
                "ssh-keygen",
                "-z", serialNumber,
                "-s", caPrivateKey.getAbsolutePath(),
                "-t", "ecdsa-sha2-" + curve.toLowerCase(),
                "-I", keyId,
                "-n", "principle:one,principle:two",
                "-V", "-1d:+5d",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // when
        RsaSshCertificate rsaSshCertificate = (RsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate);

        // then
        assertThat("nonce", rsaSshCertificate.nonce().length, equalTo(32));
        assertThat("n", rsaSshCertificate.n(), is(((RSAPublicKey) leafKeyPair.getPublic()).getModulus()));
        assertThat("e", rsaSshCertificate.e(), is(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent()));
        assertThat("serial", rsaSshCertificate.serial().toString(), equalTo(serialNumber));
        assertThat("type", rsaSshCertificate.type(), equalTo(SshCertificateType.SSH_CERT_TYPE_USER));
        assertThat("keyId", rsaSshCertificate.keyId(), equalTo(keyId));
        assertThat("validPrincipals", rsaSshCertificate.validPrincipals(), contains(
                "principle:one",
                "principle:two"
        ));
        assertThat("validAfter", rsaSshCertificate.validAfter().toEpochMilli(), allOf(
                greaterThan(Instant.now().minus(Duration.ofDays(1)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().minus(Duration.ofDays(1)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("validBefore", rsaSshCertificate.validBefore().toEpochMilli(), allOf(
                greaterThan(Instant.now().plus(Duration.ofDays(5)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().plus(Duration.ofDays(5)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("criticalOptions", rsaSshCertificate.criticalOptions(), anEmptyMap());
        assertThat("extensions", rsaSshCertificate.extensions(), allOf(
                hasEntry("permit-X11-forwarding", ""),
                hasEntry("permit-agent-forwarding", ""),
                hasEntry("permit-port-forwarding", ""),
                hasEntry("permit-user-rc", "")
        ));
        assertThat("reserved", rsaSshCertificate.reserved(), equalTo(""));
        assertThat("signatureKey", rsaSshCertificate.signatureKey(), equalTo(signingKeyPair.getPublic()));
        assertThat("signatureAlgorithm", rsaSshCertificate.signatureAlgorithm(), equalTo("ecdsa-sha2-" + curve.toLowerCase()));
        assertThat("signature", rsaSshCertificate.signature().length, greaterThan(50));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showDecodeRsaSshCertificateForHost(String keyLength) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair signingKeyPair = getKeyPair("RSA", caPublicKey, caPrivateKey);
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair leafKeyPair = getKeyPair("RSA", leafPublicKey, leafPrivateKey);
        // and - a leaf certificate
        SshCertificateAlgorithm<RSAPublicKey> sshCertificateAlgorithm = new SshRsaCertV01();
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();
        exec(
                "ssh-keygen",
                "-z", serialNumber,
                "-s", caPrivateKey.getAbsolutePath(),
                "-t", "rsa-sha2-256",
                "-I", keyId,
                "-Z", "host.name", "-h",
                "-V", "-1d:+5d",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // when
        RsaSshCertificate rsaSshCertificate = (RsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate);

        // then
        assertThat("nonce", rsaSshCertificate.nonce().length, equalTo(32));
        assertThat("n", rsaSshCertificate.n(), is(((RSAPublicKey) leafKeyPair.getPublic()).getModulus()));
        assertThat("e", rsaSshCertificate.e(), is(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent()));
        assertThat("serial", rsaSshCertificate.serial().toString(), equalTo(serialNumber));
        assertThat("type", rsaSshCertificate.type(), equalTo(SshCertificateType.SSH_CERT_TYPE_HOST));
        assertThat("keyId", rsaSshCertificate.keyId(), equalTo(keyId));
        assertThat("validPrincipals", rsaSshCertificate.validPrincipals(), empty());
        assertThat("validAfter", rsaSshCertificate.validAfter().toEpochMilli(), allOf(
                greaterThan(Instant.now().minus(Duration.ofDays(1)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().minus(Duration.ofDays(1)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("validBefore", rsaSshCertificate.validBefore().toEpochMilli(), allOf(
                greaterThan(Instant.now().plus(Duration.ofDays(5)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().plus(Duration.ofDays(5)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("criticalOptions", rsaSshCertificate.criticalOptions(), anEmptyMap());
        assertThat("extensions", rsaSshCertificate.extensions(), anEmptyMap());
        assertThat("reserved", rsaSshCertificate.reserved(), equalTo(""));
        assertThat("signatureKey", rsaSshCertificate.signatureKey(), equalTo(signingKeyPair.getPublic()));
        assertThat("signatureAlgorithm", rsaSshCertificate.signatureAlgorithm(), equalTo("rsa-sha2-256"));

        Signature signer = Signature.getInstance(SUPPORTED_CA_SIGNING_ALGORITHMS.get(rsaSshCertificate.signatureAlgorithm()));
        signer.initSign(signingKeyPair.getPrivate());
        signer.update(sshCertificateAlgorithm.encoder().encodeSignedBytes(rsaSshCertificate));
        assertThat("signature", rsaSshCertificate.signature(), equalTo(sshCertificateAlgorithm.encoder().encodeSignature("rsa-sha2-256", signer.sign())));
    }
}
