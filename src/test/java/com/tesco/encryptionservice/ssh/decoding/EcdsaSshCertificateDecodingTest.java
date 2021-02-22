package com.tesco.encryptionservice.ssh.decoding;

import com.tesco.encryptionservice.ssh.certificate.EcdsaSshCertificate;
import com.tesco.encryptionservice.ssh.certificate.SshCertificateType;
import com.tesco.encryptionservice.ssh.parser.algorithms.SshCertificateAlgorithm;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
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
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.hamcrest.number.OrderingComparison.lessThan;

@SuppressWarnings("unchecked")
@Tag("UnitTest")
public class EcdsaSshCertificateDecodingTest extends AbstractDecodingTest {

    @SneakyThrows
    @ParameterizedTest(name = "curve - {0}")
    @CsvSource({
            "nistp256",
            "nistp384",
            "nistp521",
    })
    public void showDecodeECSshCertificateForUser(String curve) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "ecdsa", "-b", curve.replace("nistp", ""), "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair signingKeyPair = getKeyPair("EC", caPublicKey, caPrivateKey);
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "ecdsa", "-b", curve.replace("nistp", ""), "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair leafKeyPair = getKeyPair("EC", leafPublicKey, leafPrivateKey);
        // and - a leaf certificate
        SshCertificateAlgorithm<ECPublicKey> sshCertificateAlgorithm = (SshCertificateAlgorithm<ECPublicKey>) SshCertificateAlgorithm.get("ecdsa-sha2-" + curve + "-cert-v01@openssh.com");
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();
        exec(
                "ssh-keygen",
                "-z", serialNumber,
                "-s", caPrivateKey.getAbsolutePath(),
                "-t", "ecdsa-sha2-" + curve,
                "-I", keyId,
                "-n", "principle:one,principle:two",
                "-V", "-1d:+5d",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // when
        EcdsaSshCertificate ecdsaCertificate = (EcdsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate);

        // then
        assertThat("nonce", ecdsaCertificate.nonce().length, equalTo(32));
        assertThat("curve", ecdsaCertificate.curve(), equalTo(curve.toLowerCase()));
        assertThat("publicKey", ecdsaCertificate.publicKey(), equalTo(leafKeyPair.getPublic()));
        assertThat("serial", ecdsaCertificate.serial().toString(), equalTo(serialNumber));
        assertThat("type", ecdsaCertificate.type(), equalTo(SshCertificateType.SSH_CERT_TYPE_USER));
        assertThat("keyId", ecdsaCertificate.keyId(), equalTo(keyId));
        assertThat("validPrincipals", ecdsaCertificate.validPrincipals(), contains(
                "principle:one",
                "principle:two"
        ));
        assertThat("validAfter", ecdsaCertificate.validAfter().toEpochMilli(), allOf(
                greaterThan(Instant.now().minus(Duration.ofDays(1)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().minus(Duration.ofDays(1)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("validBefore", ecdsaCertificate.validBefore().toEpochMilli(), allOf(
                greaterThan(Instant.now().plus(Duration.ofDays(5)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().plus(Duration.ofDays(5)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("criticalOptions", ecdsaCertificate.criticalOptions(), anEmptyMap());
        assertThat("extensions", ecdsaCertificate.extensions(), allOf(
                hasEntry("permit-X11-forwarding", ""),
                hasEntry("permit-agent-forwarding", ""),
                hasEntry("permit-port-forwarding", ""),
                hasEntry("permit-user-rc", "")
        ));
        assertThat("reserved", ecdsaCertificate.reserved(), equalTo(""));
        assertThat("signatureKey", ecdsaCertificate.signatureKey(), equalTo(signingKeyPair.getPublic()));
        assertThat("signatureAlgorithm", ecdsaCertificate.signatureAlgorithm(), equalTo("ecdsa-sha2-" + curve.toLowerCase()));
        assertThat("signature", ecdsaCertificate.signature().length, greaterThan(50));
    }

    @SneakyThrows
    @ParameterizedTest(name = "curve - {0}")
    @CsvSource({
            "nistp256",
            "nistp384",
            "nistp521",
    })
    public void showDecodeECSshCertificateForHost(String curve) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "ecdsa", "-b", curve.replace("nistp", ""), "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair signingKeyPair = getKeyPair("EC", caPublicKey, caPrivateKey);
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "ecdsa", "-b", curve.replace("nistp", ""), "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair leafKeyPair = getKeyPair("EC", leafPublicKey, leafPrivateKey);
        // and - a leaf certificate
        SshCertificateAlgorithm<ECPublicKey> sshCertificateAlgorithm = (SshCertificateAlgorithm<ECPublicKey>) SshCertificateAlgorithm.get("ecdsa-sha2-" + curve + "-cert-v01@openssh.com");
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();
        exec(
                "ssh-keygen",
                "-z", serialNumber,
                "-s", caPrivateKey.getAbsolutePath(),
                "-t", "ecdsa-sha2-" + curve,
                "-I", keyId,
                "-Z", "host.name",
                "-h",
                "-V", "-1d:+5d",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // when
        EcdsaSshCertificate ecdsaCertificate = (EcdsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate);

        // then
        assertThat("nonce", ecdsaCertificate.nonce().length, equalTo(32));
        assertThat("curve", ecdsaCertificate.curve(), equalTo(curve.toLowerCase()));
        assertThat("publicKey", ecdsaCertificate.publicKey(), equalTo(leafKeyPair.getPublic()));
        assertThat("serial", ecdsaCertificate.serial().toString(), equalTo(serialNumber));
        assertThat("type", ecdsaCertificate.type(), equalTo(SshCertificateType.SSH_CERT_TYPE_HOST));
        assertThat("keyId", ecdsaCertificate.keyId(), equalTo(keyId));
        assertThat("validPrincipals", ecdsaCertificate.validPrincipals(), empty());
        assertThat("validAfter", ecdsaCertificate.validAfter().toEpochMilli(), allOf(
                greaterThan(Instant.now().minus(Duration.ofDays(1)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().minus(Duration.ofDays(1)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("validBefore", ecdsaCertificate.validBefore().toEpochMilli(), allOf(
                greaterThan(Instant.now().plus(Duration.ofDays(5)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().plus(Duration.ofDays(5)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("criticalOptions", ecdsaCertificate.criticalOptions(), anEmptyMap());
        assertThat("extensions", ecdsaCertificate.extensions(), anEmptyMap());
        assertThat("reserved", ecdsaCertificate.reserved(), equalTo(""));
        assertThat("signatureKey", ecdsaCertificate.signatureKey(), equalTo(signingKeyPair.getPublic()));
        assertThat("signatureAlgorithm", ecdsaCertificate.signatureAlgorithm(), equalTo("ecdsa-sha2-" + curve.toLowerCase()));
        assertThat("signature", ecdsaCertificate.signature().length, greaterThan(50));
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
    public void showDecodeECSshCertificateForUserWithRSASigningKey(String curve, String keyLength) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair signingKeyPair = getKeyPair("RSA", caPublicKey, caPrivateKey);
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "ecdsa", "-b", curve.replace("nistp", ""), "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair leafKeyPair = getKeyPair("EC", leafPublicKey, leafPrivateKey);
        // and - a leaf certificate
        SshCertificateAlgorithm<ECPublicKey> sshCertificateAlgorithm = (SshCertificateAlgorithm<ECPublicKey>) SshCertificateAlgorithm.get("ecdsa-sha2-" + curve + "-cert-v01@openssh.com");
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
        EcdsaSshCertificate ecdsaCertificate = (EcdsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate);

        // then
        assertThat("nonce", ecdsaCertificate.nonce().length, equalTo(32));
        assertThat("curve", ecdsaCertificate.curve(), equalTo(curve.toLowerCase()));
        assertThat("publicKey", ecdsaCertificate.publicKey(), equalTo(leafKeyPair.getPublic()));
        assertThat("serial", ecdsaCertificate.serial().toString(), equalTo(serialNumber));
        assertThat("type", ecdsaCertificate.type(), equalTo(SshCertificateType.SSH_CERT_TYPE_USER));
        assertThat("keyId", ecdsaCertificate.keyId(), equalTo(keyId));
        assertThat("validPrincipals", ecdsaCertificate.validPrincipals(), contains(
                "principle:one",
                "principle:two"
        ));
        assertThat("validAfter", ecdsaCertificate.validAfter().toEpochMilli(), allOf(
                greaterThan(Instant.now().minus(Duration.ofDays(1)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().minus(Duration.ofDays(1)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("validBefore", ecdsaCertificate.validBefore().toEpochMilli(), allOf(
                greaterThan(Instant.now().plus(Duration.ofDays(5)).minus(Duration.ofMinutes(1)).toEpochMilli()),
                lessThan(Instant.now().plus(Duration.ofDays(5)).plus(Duration.ofMinutes(1)).toEpochMilli())
        ));
        assertThat("criticalOptions", ecdsaCertificate.criticalOptions(), anEmptyMap());
        assertThat("extensions", ecdsaCertificate.extensions(), allOf(
                hasEntry("permit-X11-forwarding", ""),
                hasEntry("permit-agent-forwarding", ""),
                hasEntry("permit-port-forwarding", ""),
                hasEntry("permit-user-rc", "")
        ));
        assertThat("reserved", ecdsaCertificate.reserved(), equalTo(""));
        assertThat("signatureKey", ecdsaCertificate.signatureKey(), equalTo(signingKeyPair.getPublic()));
        assertThat("signatureAlgorithm", ecdsaCertificate.signatureAlgorithm(), equalTo("rsa-sha2-256"));

        Signature signer = Signature.getInstance(SUPPORTED_CA_SIGNING_ALGORITHMS.get(ecdsaCertificate.signatureAlgorithm()));
        signer.initSign(signingKeyPair.getPrivate());
        signer.update(sshCertificateAlgorithm.encoder().encodeSignedBytes(ecdsaCertificate));
        assertThat("signature", ecdsaCertificate.signature(), equalTo(sshCertificateAlgorithm.encoder().encodeSignature("rsa-sha2-256", signer.sign())));
    }
}
