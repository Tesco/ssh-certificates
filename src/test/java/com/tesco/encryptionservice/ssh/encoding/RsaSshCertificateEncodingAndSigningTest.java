package com.tesco.encryptionservice.ssh.encoding;

import com.tesco.encryptionservice.ssh.certificate.RsaSshCertificate;
import com.tesco.encryptionservice.ssh.certificate.SshCertificate;
import com.tesco.encryptionservice.ssh.certificate.SshCertificateType;
import com.tesco.encryptionservice.ssh.parser.algorithms.SshCertificateAlgorithm;
import com.tesco.encryptionservice.ssh.parser.algorithms.SshRsaCertV01;
import com.tesco.encryptionservice.ssh.signer.SshCertificateSigner;
import lombok.SneakyThrows;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

import static com.tesco.encryptionservice.ssh.certificate.EcdsaSshCertificate.SUPPORTED_EC_CURVES;
import static com.tesco.encryptionservice.ssh.certificate.SshCriticalOption.FORCE_COMMAND;
import static com.tesco.encryptionservice.ssh.certificate.SshPermission.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.StringContains.containsString;

@Tag("UnitTest")
public class RsaSshCertificateEncodingAndSigningTest extends AbstractCertificateEncodingAndSigningTest {

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showDecodeAndEncodeToOriginalValue(String keyLength) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "");
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "");
        exec("ssh-keygen", "-c", "-C", "user@host", "-f", leafPrivateKey.getAbsolutePath());
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
        String leafCertificateFileContents = Files.readString(leafCertificate.toPath(), Charset.defaultCharset()).trim();
        SshCertificate<RSAPublicKey> decodedCertificate = sshCertificateAlgorithm.decoder().decode(leafCertificateFileContents);
        String reEncodedCertificate = sshCertificateAlgorithm.encoder().encodeToString(decodedCertificate, "user@host");

        // then
        assertThat(reEncodedCertificate, equalTo(leafCertificateFileContents));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showEncodeAndSignRsaSshCertificateForUser(String keyLength) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair signingKeyPair = getKeyPair("RSA", caPublicKey, caPrivateKey);
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair leafKeyPair = getKeyPair("RSA", leafPublicKey, leafPrivateKey);
        // Note: must change comment after reading file as this forces the format into OpenSSH format i.e. not PKCS8
        exec("ssh-keygen", "-c", "-C", "user@host", "-f", leafPrivateKey.getAbsolutePath());
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
                "-V", "20100101123000:20110101123000",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // and
        RsaSshCertificate rsaSshCertificate =
                (RsaSshCertificate) new RsaSshCertificate()
                        .nonce(((RsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate)).nonce())
                        .e(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent())
                        .n(((RSAPublicKey) leafKeyPair.getPublic()).getModulus())
                        .serial(new BigInteger(serialNumber))
                        .type(SshCertificateType.SSH_CERT_TYPE_USER)
                        .keyId(keyId)
                        .addPrincipal("principle:one")
                        .addPrincipal("principle:two")
                        .validAfter(Instant.parse("2010-01-01T12:30:00Z"))
                        .validBefore(Instant.parse("2011-01-01T12:30:00Z"))
                        .addExtension(PERMIT_X11_FORWARDING, "")
                        .addExtension(PERMIT_AGENT_FORWARDING, "")
                        .addExtension(PERMIT_PORT_FORWARDING, "")
                        .addExtension(PERMIT_PTY, "")
                        .addExtension(PERMIT_USER_RC, "")
                        .reserved("");
        SshCertificateSigner.sign(rsaSshCertificate, signingKeyPair);

        // when
        String encodeCertificate = sshCertificateAlgorithm.encoder().encodeToString(rsaSshCertificate, "user@host");

        // then
        assertThat(encodeCertificate, equalTo(Files.readString(leafCertificate.toPath(), Charset.defaultCharset()).trim()));
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
        // Note: must change comment after reading file as this forces the format into OpenSSH format i.e. not PKCS8
        exec("ssh-keygen", "-c", "-C", "user@host", "-f", leafPrivateKey.getAbsolutePath());
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
                "-V", "20100101123000:20110101123000",
                "-O", "clear",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // and
        RsaSshCertificate rsaSshCertificate =
                (RsaSshCertificate) new RsaSshCertificate()
                        .nonce(((RsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate)).nonce())
                        .e(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent())
                        .n(((RSAPublicKey) leafKeyPair.getPublic()).getModulus())
                        .serial(new BigInteger(serialNumber))
                        .type(SshCertificateType.SSH_CERT_TYPE_USER)
                        .keyId(keyId)
                        .addPrincipal("principle:one")
                        .addPrincipal("principle:two")
                        .validAfter(Instant.parse("2010-01-01T12:30:00Z"))
                        .validBefore(Instant.parse("2011-01-01T12:30:00Z"))
                        .reserved("");
        SshCertificateSigner.sign(rsaSshCertificate, signingKeyPair);

        // when
        String encodeCertificate = sshCertificateAlgorithm.encoder().encodeToString(rsaSshCertificate, "user@host");

        // then
        assertThat(encodeCertificate, equalTo(Files.readString(leafCertificate.toPath(), Charset.defaultCharset()).trim()));
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
        // Note: must change comment after reading file as this forces the format into OpenSSH format i.e. not PKCS8
        exec("ssh-keygen", "-c", "-C", "user@host", "-f", leafPrivateKey.getAbsolutePath());
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
                "-V", "20100101123000:20110101123000",
                "-O", "no-x11-forwarding",
                "-O", "force-command=\"ls -lrt\"",
                "-O", "critical:critical_option_example@example.com=some_option_value",
                "-O", "extension:extension_example@example.com=some_extension_value",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // and
        RsaSshCertificate rsaSshCertificate =
                (RsaSshCertificate) new RsaSshCertificate()
                        .nonce(((RsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate)).nonce())
                        .e(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent())
                        .n(((RSAPublicKey) leafKeyPair.getPublic()).getModulus())
                        .serial(new BigInteger(serialNumber))
                        .type(SshCertificateType.SSH_CERT_TYPE_USER)
                        .keyId(keyId)
                        .addPrincipal("principle:one")
                        .addPrincipal("principle:two")
                        .validAfter(Instant.parse("2010-01-01T12:30:00Z"))
                        .validBefore(Instant.parse("2011-01-01T12:30:00Z"))
                        .addCriticalOption(FORCE_COMMAND, "\"ls -lrt\"")
                        .addCriticalOption("critical_option_example@example.com", "some_option_value")
                        .addExtension(PERMIT_AGENT_FORWARDING, "")
                        .addExtension(PERMIT_PORT_FORWARDING, "")
                        .addExtension(PERMIT_PTY, "")
                        .addExtension(PERMIT_USER_RC, "")
                        .addExtension("extension_example@example.com", "some_extension_value")
                        .reserved("");
        SshCertificateSigner.sign(rsaSshCertificate, signingKeyPair);

        // when
        String encodeCertificate = sshCertificateAlgorithm.encoder().encodeToString(rsaSshCertificate, "user@host");

        // then
        assertThat(encodeCertificate, equalTo(Files.readString(leafCertificate.toPath(), Charset.defaultCharset()).trim()));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showEncodeAndSignRsaSshCertificateForHost(String keyLength) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair signingKeyPair = getKeyPair("RSA", caPublicKey, caPrivateKey);
        // and - a leaf key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", leafPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        KeyPair leafKeyPair = getKeyPair("RSA", leafPublicKey, leafPrivateKey);
        // Note: must change comment after reading file as this forces the format into OpenSSH format i.e. not PKCS8
        exec("ssh-keygen", "-c", "-C", "user@host", "-f", leafPrivateKey.getAbsolutePath());
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
                "-V", "20100101123000:20110101123000",
                leafPrivateKey.getAbsolutePath() + ".pub"
        );

        // and
        RsaSshCertificate rsaSshCertificate =
                (RsaSshCertificate) new RsaSshCertificate()
                        .nonce(((RsaSshCertificate) sshCertificateAlgorithm.decoder().decode(leafCertificate)).nonce())
                        .e(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent())
                        .n(((RSAPublicKey) leafKeyPair.getPublic()).getModulus())
                        .serial(new BigInteger(serialNumber))
                        .type(SshCertificateType.SSH_CERT_TYPE_HOST)
                        .keyId(keyId)
                        .validAfter(Instant.parse("2010-01-01T12:30:00Z"))
                        .validBefore(Instant.parse("2011-01-01T12:30:00Z"))
                        .reserved("");
        SshCertificateSigner.sign(rsaSshCertificate, signingKeyPair);

        // when
        String encodeCertificate = sshCertificateAlgorithm.encoder().encodeToString(rsaSshCertificate, "user@host");

        // then
        String leafCertificateFileContents = Files.readString(leafCertificate.toPath(), Charset.defaultCharset()).trim();
        assertThat(encodeCertificate, equalTo(leafCertificateFileContents));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showEncodeECSshCertificateForUserParsableBySshKeyGen(int keyLength) {
        // given - an RSA key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keyLength);
        // and - a CA key pair
        KeyPair signingKeyPair = keyPairGenerator.generateKeyPair();
        // and - a leaf key pair
        KeyPair leafKeyPair = keyPairGenerator.generateKeyPair();
        // and - some certificate properties
        SshCertificateAlgorithm<RSAPublicKey> sshCertificateAlgorithm = new SshRsaCertV01();
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();

        // when
        RsaSshCertificate rsaSshCertificate =
                (RsaSshCertificate) new RsaSshCertificate()
                        .nonce(keyId.getBytes())
                        .e(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent())
                        .n(((RSAPublicKey) leafKeyPair.getPublic()).getModulus())
                        .serial(new BigInteger(serialNumber))
                        .type(SshCertificateType.SSH_CERT_TYPE_USER)
                        .keyId(keyId)
                        .addPrincipal("principle_one")
                        .addPrincipal("principle_two")
                        .validAfter(Instant.parse("2010-01-01T12:30:00Z"))
                        .validBefore(Instant.parse("2011-01-01T12:30:00Z"))
                        .addExtension(PERMIT_X11_FORWARDING, "")
                        .addExtension(PERMIT_AGENT_FORWARDING, "")
                        .addExtension(PERMIT_PORT_FORWARDING, "")
                        .addExtension(PERMIT_PTY, "")
                        .addExtension(PERMIT_USER_RC, "")
                        .reserved("");
        SshCertificateSigner.sign(rsaSshCertificate, signingKeyPair);
        sshCertificateAlgorithm.encoder().encodeToFile(rsaSshCertificate, "user@host", leafCertificate);

        // then
        String processOutput = execAndCaptureOutput(
                "ssh-keygen",
                "-L",
                "-f", leafCertificate.getAbsolutePath()
        );
        Map<String, String> parsedValue = parseKeyGenOutput(processOutput);

        // then
        assertThat(parsedValue.get("Type"), equalTo(sshCertificateAlgorithm.algorithmName() + " user certificate"));
        assertThat(parsedValue.get("PublicKey"), equalTo("RSA-CERT SHA256:" + BASE64_ENCODER_NO_PADDING.encodeToString(DigestUtils.sha256(sshCertificateAlgorithm.encoder().encodeSignatureKey(rsaSshCertificate.publicKey())))));
        assertThat(parsedValue.get("SigningKey"), containsString("RSA SHA256:" + BASE64_ENCODER_NO_PADDING.encodeToString(DigestUtils.sha256(sshCertificateAlgorithm.encoder().encodeSignatureKey(rsaSshCertificate.signatureKey())))));
        assertThat(parsedValue.get("KeyID"), equalTo("\"" + keyId + "\""));
        assertThat(parsedValue.get("Serial"), equalTo(serialNumber));
        assertThat(parsedValue.get("Valid"), equalTo("from 2010-01-01T12:30:00 to 2011-01-01T12:30:00"));
        assertThat(parsedValue.get("Principals"), equalTo("principle_one principle_two"));
        assertThat(parsedValue.get("CriticalOptions"), equalTo("(none)"));
        assertThat(parsedValue.get("Extensions"), equalTo("permit-X11-forwarding permit-agent-forwarding permit-port-forwarding permit-pty"));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}, signing algorithm - {1}")
    @CsvSource({
            "2048,ssh-rsa",
            "2048,rsa-sha2-256",
            "2048,rsa-sha2-512",
            "3072,ssh-rsa",
            "3072,rsa-sha2-256",
            "3072,rsa-sha2-512",
            "4096,ssh-rsa",
            "4096,rsa-sha2-256",
            "4096,rsa-sha2-512",
    })
    public void showEncodeECSshCertificateForUserParsableBySshKeyGen(int keyLength, String signingAlgorithm) {
        // given - an RSA key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keyLength);
        // and - a CA key pair
        KeyPair signingKeyPair = keyPairGenerator.generateKeyPair();
        // and - a leaf key pair
        KeyPair leafKeyPair = keyPairGenerator.generateKeyPair();
        // and - some certificate properties
        SshCertificateAlgorithm<RSAPublicKey> sshCertificateAlgorithm = new SshRsaCertV01();
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();

        // when
        RsaSshCertificate rsaSshCertificate =
                (RsaSshCertificate) new RsaSshCertificate()
                        .nonce(keyId.getBytes())
                        .e(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent())
                        .n(((RSAPublicKey) leafKeyPair.getPublic()).getModulus())
                        .serial(new BigInteger(serialNumber))
                        .type(SshCertificateType.SSH_CERT_TYPE_USER)
                        .keyId(keyId)
                        .addPrincipal("principle_one")
                        .addPrincipal("principle_two")
                        .validAfter(Instant.parse("2010-01-01T12:30:00Z"))
                        .validBefore(Instant.parse("2011-01-01T12:30:00Z"))
                        .addExtension(PERMIT_X11_FORWARDING, "")
                        .addExtension(PERMIT_AGENT_FORWARDING, "")
                        .addExtension(PERMIT_PORT_FORWARDING, "")
                        .addExtension(PERMIT_PTY, "")
                        .addExtension(PERMIT_USER_RC, "")
                        .reserved("");
        SshCertificateSigner.sign(rsaSshCertificate, signingKeyPair.getPublic(), signingKeyPair.getPrivate(), signingAlgorithm);
        sshCertificateAlgorithm.encoder().encodeToFile(rsaSshCertificate, "user@host", leafCertificate);

        // then
        String processOutput = execAndCaptureOutput(
                "ssh-keygen",
                "-L",
                "-f", leafCertificate.getAbsolutePath()
        );
        Map<String, String> parsedValue = parseKeyGenOutput(processOutput);

        // then
        assertThat(parsedValue.get("Type"), equalTo(sshCertificateAlgorithm.algorithmName() + " user certificate"));
        assertThat(parsedValue.get("PublicKey"), equalTo("RSA-CERT SHA256:" + BASE64_ENCODER_NO_PADDING.encodeToString(DigestUtils.sha256(sshCertificateAlgorithm.encoder().encodeSignatureKey(rsaSshCertificate.publicKey())))));
        assertThat(parsedValue.get("SigningKey"), containsString("RSA SHA256:" + BASE64_ENCODER_NO_PADDING.encodeToString(DigestUtils.sha256(sshCertificateAlgorithm.encoder().encodeSignatureKey(rsaSshCertificate.signatureKey())))));
        assertThat(parsedValue.get("KeyID"), equalTo("\"" + keyId + "\""));
        assertThat(parsedValue.get("Serial"), equalTo(serialNumber));
        assertThat(parsedValue.get("Valid"), equalTo("from 2010-01-01T12:30:00 to 2011-01-01T12:30:00"));
        assertThat(parsedValue.get("Principals"), equalTo("principle_one principle_two"));
        assertThat(parsedValue.get("CriticalOptions"), equalTo("(none)"));
        assertThat(parsedValue.get("Extensions"), equalTo("permit-X11-forwarding permit-agent-forwarding permit-port-forwarding permit-pty"));
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
    public void showEncodeECSshCertificateForUserWithRSASignatureParsableBySshKeyGen(String curve, int keyLength) {
        // given - a CA key pair
        KeyPairGenerator ecKeyPairGenerator = KeyPairGenerator.getInstance("EC");
        ecKeyPairGenerator.initialize(new ECGenParameterSpec(SUPPORTED_EC_CURVES.get(curve)));
        KeyPair signingKeyPair = ecKeyPairGenerator.generateKeyPair();
        // and - a leaf key pair
        KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
        rsaKeyPairGenerator.initialize(keyLength);
        KeyPair leafKeyPair = rsaKeyPairGenerator.generateKeyPair();
        // and - some certificate properties
        SshCertificateAlgorithm<RSAPublicKey> sshCertificateAlgorithm = new SshRsaCertV01();
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();

        // when
        RsaSshCertificate rsaSshCertificate =
                (RsaSshCertificate) new RsaSshCertificate()
                        .nonce(keyId.getBytes())
                        .e(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent())
                        .n(((RSAPublicKey) leafKeyPair.getPublic()).getModulus())
                        .serial(new BigInteger(serialNumber))
                        .type(SshCertificateType.SSH_CERT_TYPE_USER)
                        .keyId(keyId)
                        .addPrincipal("principle_one")
                        .addPrincipal("principle_two")
                        .validAfter(Instant.parse("2010-01-01T12:30:00Z"))
                        .validBefore(Instant.parse("2011-01-01T12:30:00Z"))
                        .addExtension(PERMIT_X11_FORWARDING, "")
                        .addExtension(PERMIT_AGENT_FORWARDING, "")
                        .addExtension(PERMIT_PORT_FORWARDING, "")
                        .addExtension(PERMIT_PTY, "")
                        .addExtension(PERMIT_USER_RC, "")
                        .reserved("");
        SshCertificateSigner.sign(rsaSshCertificate, signingKeyPair);
        sshCertificateAlgorithm.encoder().encodeToFile(rsaSshCertificate, "user@host", leafCertificate);

        // then
        String processOutput = execAndCaptureOutput(
                "ssh-keygen",
                "-L",
                "-f", leafCertificate.getAbsolutePath()
        );
        Map<String, String> parsedValue = parseKeyGenOutput(processOutput);

        // then
        assertThat(parsedValue.get("Type"), equalTo(sshCertificateAlgorithm.algorithmName() + " user certificate"));
        assertThat(parsedValue.get("PublicKey"), equalTo("RSA-CERT SHA256:" + BASE64_ENCODER_NO_PADDING.encodeToString(DigestUtils.sha256(sshCertificateAlgorithm.encoder().encodeSignatureKey(rsaSshCertificate.publicKey())))));
        assertThat(parsedValue.get("SigningKey"), containsString("ECDSA SHA256:" + BASE64_ENCODER_NO_PADDING.encodeToString(DigestUtils.sha256(sshCertificateAlgorithm.encoder().encodeSignatureKey(rsaSshCertificate.signatureKey())))));
        assertThat(parsedValue.get("KeyID"), equalTo("\"" + keyId + "\""));
        assertThat(parsedValue.get("Serial"), equalTo(serialNumber));
        assertThat(parsedValue.get("Valid"), equalTo("from 2010-01-01T12:30:00 to 2011-01-01T12:30:00"));
        assertThat(parsedValue.get("Principals"), equalTo("principle_one principle_two"));
        assertThat(parsedValue.get("CriticalOptions"), equalTo("(none)"));
        assertThat(parsedValue.get("Extensions"), equalTo("permit-X11-forwarding permit-agent-forwarding permit-port-forwarding permit-pty"));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showEncodeECSshCertificateForHostParsableBySshKeyGen(int keyLength) {
        // given - an RSA key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keyLength);
        // and - a CA key pair
        KeyPair signingKeyPair = keyPairGenerator.generateKeyPair();
        // and - a leaf key pair
        KeyPair leafKeyPair = keyPairGenerator.generateKeyPair();
        // and - some certificate properties
        SshCertificateAlgorithm<RSAPublicKey> sshCertificateAlgorithm = new SshRsaCertV01();
        String serialNumber = new BigInteger(63, new Random()).toString();
        String keyId = UUID.randomUUID().toString();

        // when
        RsaSshCertificate rsaSshCertificate =
                (RsaSshCertificate) new RsaSshCertificate()
                        .nonce(keyId.getBytes())
                        .e(((RSAPublicKey) leafKeyPair.getPublic()).getPublicExponent())
                        .n(((RSAPublicKey) leafKeyPair.getPublic()).getModulus())
                        .serial(new BigInteger(serialNumber))
                        .type(SshCertificateType.SSH_CERT_TYPE_HOST)
                        .keyId(keyId)
                        .validAfter(Instant.parse("2010-01-01T12:30:00Z"))
                        .validBefore(Instant.parse("2011-01-01T12:30:00Z"))
                        .reserved("");
        SshCertificateSigner.sign(rsaSshCertificate, signingKeyPair);
        sshCertificateAlgorithm.encoder().encodeToFile(rsaSshCertificate, "user@host", leafCertificate);

        // then
        String processOutput = execAndCaptureOutput(
                "ssh-keygen",
                "-L",
                "-f", leafCertificate.getAbsolutePath()
        );
        Map<String, String> parsedValue = parseKeyGenOutput(processOutput);

        // then
        assertThat(parsedValue.get("Type"), equalTo(sshCertificateAlgorithm.algorithmName() + " host certificate"));
        assertThat(parsedValue.get("PublicKey"), equalTo("RSA-CERT SHA256:" + BASE64_ENCODER_NO_PADDING.encodeToString(DigestUtils.sha256(sshCertificateAlgorithm.encoder().encodeSignatureKey(rsaSshCertificate.publicKey())))));
        assertThat(parsedValue.get("SigningKey"), containsString("RSA SHA256:" + BASE64_ENCODER_NO_PADDING.encodeToString(DigestUtils.sha256(sshCertificateAlgorithm.encoder().encodeSignatureKey(rsaSshCertificate.signatureKey())))));
        assertThat(parsedValue.get("KeyID"), equalTo("\"" + keyId + "\""));
        assertThat(parsedValue.get("Serial"), equalTo(serialNumber));
        assertThat(parsedValue.get("Valid"), equalTo("from 2010-01-01T12:30:00 to 2011-01-01T12:30:00"));
        assertThat(parsedValue.get("Principals"), equalTo("(none)"));
        assertThat(parsedValue.get("CriticalOptions"), equalTo("(none)"));
        assertThat(parsedValue.get("Extensions"), equalTo("(none)"));
    }
}
