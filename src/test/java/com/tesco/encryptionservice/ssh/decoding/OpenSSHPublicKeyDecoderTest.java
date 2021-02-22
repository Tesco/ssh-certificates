package com.tesco.encryptionservice.ssh.decoding;

import com.tesco.encryptionservice.ssh.parser.decode.OpenSSHPublicKeyDecoder;
import lombok.SneakyThrows;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static com.tesco.encryptionservice.ssh.parser.decode.OpenSSHPublicKeyDecoder.lookupCurveName;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class OpenSSHPublicKeyDecoderTest extends AbstractDecodingTest {

    @SneakyThrows
    @ParameterizedTest(name = "curve - {0}")
    @CsvSource({
            "nistp256",
            "nistp384",
            "nistp521",
    })
    public void showDecodeECPublicKeys(String curve) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "ecdsa", "-b", curve.replace("nistp", ""), "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");

        // when
        ECPublicKey publicKey = (ECPublicKey) OpenSSHPublicKeyDecoder.decodePublicKey(caPublicKey.getAbsoluteFile());

        // then
        assertThat(publicKey.getAlgorithm(), equalTo("EC"));
        assertThat(publicKey.getFormat(), equalTo("X.509"));
        assertThat(lookupCurveName(publicKey), equalTo(curve));
    }

    @SneakyThrows
    @ParameterizedTest(name = "key length - {0}")
    @CsvSource({
            "2048",
            "3072",
            "4096",
    })
    public void showDecodeRSAPublicKeys(String keyLength) {
        // given - a CA key pair
        exec("ssh-keygen", "-t", "rsa", "-b", keyLength, "-f", caPrivateKey.getAbsolutePath(), "-q", "-N", "", "-m", "PKCS8");

        // when
        RSAPublicKey publicKey = (RSAPublicKey) OpenSSHPublicKeyDecoder.decodePublicKey(caPublicKey.getAbsoluteFile());

        // then
        assertThat(publicKey.getAlgorithm(), equalTo("RSA"));
        assertThat(publicKey.getFormat(), equalTo("X.509"));
    }
}
