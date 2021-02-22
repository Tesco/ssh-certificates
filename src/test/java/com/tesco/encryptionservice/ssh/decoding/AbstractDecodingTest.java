package com.tesco.encryptionservice.ssh.decoding;

import com.tesco.encryptionservice.ssh.parser.decode.OpenSSHPublicKeyDecoder;
import com.tesco.encryptionservice.ssh.parser.decode.PKCS8PrivateKeyDecoder;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.stream.Collectors;

@Tag("UnitTest")
public class AbstractDecodingTest {

    protected File caPrivateKey;
    protected File caPublicKey;
    protected File leafPrivateKey;
    protected File leafPublicKey;
    protected File leafCertificate;

    @BeforeEach
    @SuppressWarnings("ResultOfMethodCallIgnored")
    public void createNewTmpFile() throws IOException {
        caPrivateKey = File.createTempFile("ca_key_pair", "");
        caPublicKey = new File(caPrivateKey.getAbsoluteFile() + ".pub");
        leafPrivateKey = File.createTempFile("leaf_key_pair", "");
        leafPublicKey = new File(leafPrivateKey.getAbsoluteFile() + ".pub");
        leafCertificate = new File(leafPrivateKey.getAbsoluteFile() + "-cert.pub");
        caPrivateKey.delete();
        leafPrivateKey.delete();
    }

    @SneakyThrows
    public void exec(String... command) {
        ProcessBuilder builder = new ProcessBuilder();
        System.out.println("running: " + Arrays.stream(command).map(argument -> argument.isBlank() ? "''" : argument).collect(Collectors.joining(" ")));
        builder.command(command);
        builder.inheritIO();
        Process process = builder.start();
        process.waitFor();
    }

    protected void logFileContents() throws IOException {
        System.out.println("\ncaPrivateKey:\n" + String.join("\n", IOUtils.readLines(new FileInputStream(caPrivateKey), StandardCharsets.UTF_8)));
        System.out.println("\ncaPublicKey:\n" + String.join("\n", IOUtils.readLines(new FileInputStream(caPublicKey), StandardCharsets.UTF_8)));
        System.out.println("\nleafPrivateKey:\n" + String.join("\n", IOUtils.readLines(new FileInputStream(leafPrivateKey), StandardCharsets.UTF_8)));
        System.out.println("\nleafPublicKey:\n" + String.join("\n", IOUtils.readLines(new FileInputStream(leafPublicKey), StandardCharsets.UTF_8)));
        System.out.println("\nleafCertificate:\n" + String.join("\n", IOUtils.readLines(new FileInputStream(leafCertificate), StandardCharsets.UTF_8)));
    }

    @SneakyThrows
    public KeyPair getKeyPair(String algorithm, File publicKeyFile, File privateKeyFile) {
        return new KeyPair(
                OpenSSHPublicKeyDecoder.decodePublicKey(publicKeyFile),
                PKCS8PrivateKeyDecoder.parsePCKS8PrivateKey(algorithm, privateKeyFile)
        );
    }
}
