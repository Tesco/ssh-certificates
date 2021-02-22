package com.tesco.encryptionservice.ssh.parser.decode;

import lombok.SneakyThrows;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class PKCS8PrivateKeyDecoder {

    @SneakyThrows
    public static PrivateKey parsePCKS8PrivateKey(String algorithm, File privateKeyFile) {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        String key = Files.readString(privateKeyFile.toPath(), Charset.defaultCharset());
        String publicKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----END OPENSSH PRIVATE KEY-----", "");

        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(publicKeyPEM)));
    }

}
