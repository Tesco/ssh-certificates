package com.tesco.encryptionservice.ssh.encoding;

import com.tesco.encryptionservice.ssh.decoding.AbstractDecodingTest;
import com.tesco.encryptionservice.ssh.parser.decode.OpenSSHPublicKeyDecoder;
import com.tesco.encryptionservice.ssh.parser.encode.OpenSSHPublicKeyEncoder;
import lombok.SneakyThrows;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;

import static com.tesco.encryptionservice.ssh.certificate.EcdsaSshCertificate.SUPPORTED_EC_CURVES;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class OpenSSHPublicKeyEncoderTest extends AbstractDecodingTest {

    @SneakyThrows
    @ParameterizedTest(name = "curve - {0}")
    @CsvSource({
            "nistp256",
            "nistp384",
            "nistp521",
    })
    public void showDecodeAndEncodeECPublicKeys(String curve) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "ecdsa", "-b", curve.replace("nistp", ""), "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        ECPublicKey publicKey = (ECPublicKey) OpenSSHPublicKeyDecoder.decodePublicKey(caPublicKey.getAbsoluteFile());
        exec("ssh-keygen", "-c", "-C", "user@host", "-f", caPrivateKey.getAbsolutePath());

        // when
        String encodedPublicKey = OpenSSHPublicKeyEncoder.encodePublicKey(publicKey, "user@host");

        // then
        String caPublicKeyFileContents = Files.readString(caPublicKey.toPath(), Charset.defaultCharset()).trim();
        assertThat(encodedPublicKey, equalTo(caPublicKeyFileContents));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showDecodeAndEncodeRSAPublicKeys(String keyLength) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");
        RSAPublicKey publicKey = (RSAPublicKey) OpenSSHPublicKeyDecoder.decodePublicKey(caPublicKey.getAbsoluteFile());
        exec("ssh-keygen", "-c", "-C", "user@host", "-f", caPrivateKey.getAbsolutePath());

        // when
        String encodedPublicKey = OpenSSHPublicKeyEncoder.encodePublicKey(publicKey, "user@host");

        // then
        String caPublicKeyFileContents = Files.readString(caPublicKey.toPath(), Charset.defaultCharset()).trim();
        assertThat(encodedPublicKey, equalTo(caPublicKeyFileContents));
    }

    @SneakyThrows
    @ParameterizedTest(name = "curve - {0}")
    @CsvSource({
            "nistp256",
            "nistp384",
            "nistp521",
    })
    public void showEncodeAndDecodeECPublicKeys(String curve) {
        // given - an EC key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec(SUPPORTED_EC_CURVES.get(curve)));
        // and - a CA key pair
        KeyPair caKeyPair = keyPairGenerator.generateKeyPair();

        // when
        String encodedPublicKey = OpenSSHPublicKeyEncoder.encodePublicKey(caKeyPair.getPublic(), "user@host");
        ECPublicKey decodedPublicKey = (ECPublicKey) OpenSSHPublicKeyDecoder.decodePublicKey(encodedPublicKey);

        // then
        assertThat(decodedPublicKey, equalTo(caKeyPair.getPublic()));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showEncodeAndDecodeRSAPublicKeys(int keyLength) {
        // given - an RSA key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keyLength);
        // and - a CA key pair
        KeyPair caKeyPair = keyPairGenerator.generateKeyPair();

        // when
        String encodedPublicKey = OpenSSHPublicKeyEncoder.encodePublicKey(caKeyPair.getPublic(), "user@host");
        RSAPublicKey decodedPublicKey = (RSAPublicKey) OpenSSHPublicKeyDecoder.decodePublicKey(encodedPublicKey);

        // then
        assertThat(decodedPublicKey, equalTo(caKeyPair.getPublic()));
    }
}
