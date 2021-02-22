package com.tesco.encryptionservice.ssh.encoding;

import com.tesco.encryptionservice.ssh.parser.decode.OpenSSHPublicKeyDecoder;
import com.tesco.encryptionservice.ssh.parser.decode.PKCS8PrivateKeyDecoder;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.*;
import java.util.stream.Collectors;

@Tag("UnitTest")
public class AbstractCertificateEncodingAndSigningTest {

    protected static final Base64.Encoder BASE64_ENCODER_NO_PADDING = Base64.getEncoder().withoutPadding();

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

    @SneakyThrows
    public String execAndCaptureOutput(String... command) {
        ProcessBuilder builder = new ProcessBuilder();
        System.out.println("running: " + Arrays.stream(command).map(argument -> argument.isBlank() ? "''" : argument).collect(Collectors.joining(" ")));
        builder.command(command);
        Process process = builder.start();
        process.waitFor();
        String errorOutput = IOUtils.toString(process.getErrorStream(), StandardCharsets.UTF_8);
        if (errorOutput != null && !errorOutput.isEmpty()) {
            System.err.println("command stderr:\n" + errorOutput);
        }
        return IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
    }

    protected void logFileContents() throws IOException {
        System.out.println("\ncaPrivateKey:\n" + String.join("\n", IOUtils.readLines(new FileInputStream(caPrivateKey), StandardCharsets.UTF_8)));
        System.out.println("\ncaPublicKey:\n" + String.join("\n", IOUtils.readLines(new FileInputStream(caPublicKey), StandardCharsets.UTF_8)));
        System.out.println("\nleafPrivateKey:\n" + String.join("\n", IOUtils.readLines(new FileInputStream(leafPrivateKey), StandardCharsets.UTF_8)));
        System.out.println("\nleafPublicKey:\n" + String.join("\n", IOUtils.readLines(new FileInputStream(leafPublicKey), StandardCharsets.UTF_8)));
        System.out.println("\nleafCertificate:\n" + String.join("\n", IOUtils.readLines(new FileInputStream(leafCertificate), StandardCharsets.UTF_8)) + "\n\n");
    }

    @SneakyThrows
    public KeyPair getKeyPair(String algorithm, File publicKeyFile, File privateKeyFile) {
        return new KeyPair(
                OpenSSHPublicKeyDecoder.decodePublicKey(publicKeyFile),
                PKCS8PrivateKeyDecoder.parsePCKS8PrivateKey(algorithm, privateKeyFile)
        );
    }

    protected Map<String, String> parseKeyGenOutput(String processOutput) {
        List<String> lines = Arrays.stream(processOutput.split("\n")).map(String::trim).collect(Collectors.toList());
        Map<String, String> parsedValue = new HashMap<>();
        for (int i = 0, linesSize = lines.size(); i < linesSize; i++) {
            String line = lines.get(i);
            if (line.startsWith("Type:")) {
                parsedValue.put("Type", StringUtils.substringAfter(line, ":").trim());
            }
            if (line.startsWith("Public key:")) {
                parsedValue.put("PublicKey", StringUtils.substringAfter(line, ":").trim());
            }
            if (line.startsWith("Signing CA:")) {
                parsedValue.put("SigningKey", StringUtils.substringAfter(line, ":").trim());
            }
            if (line.startsWith("Key ID:")) {
                parsedValue.put("KeyID", StringUtils.substringAfter(line, ":").trim());
            }
            if (line.startsWith("Serial:")) {
                parsedValue.put("Serial", StringUtils.substringAfter(line, ":").trim());
            }
            if (line.startsWith("Valid:")) {
                parsedValue.put("Valid", StringUtils.substringAfter(line, ":").trim());
            }
            if (line.startsWith("Principals:")) {
                StringBuilder list = new StringBuilder(StringUtils.substringAfter(line, ":"));
                for (int j = i + 1; j < linesSize - 1 && !lines.get(j).contains(":"); j++, i++) {
                    list.append(lines.get(j)).append(" ");
                }
                parsedValue.put("Principals", list.toString().trim());
            }
            if (line.startsWith("Critical Options:")) {
                StringBuilder list = new StringBuilder(StringUtils.substringAfter(line, ":"));
                for (int j = i + 1; j < linesSize - 1 && !lines.get(j).contains(":"); j++, i++) {
                    list.append(lines.get(j)).append(" ");
                }
                parsedValue.put("CriticalOptions", list.toString().trim());
            }
            if (line.startsWith("Extensions:")) {
                StringBuilder list = new StringBuilder(StringUtils.substringAfter(line, ":"));
                for (int j = i + 1; j < linesSize - 1 && !lines.get(j).contains(":"); j++, i++) {
                    list.append(lines.get(j)).append(" ");
                }
                parsedValue.put("Extensions", list.toString().trim());
            }
        }
        return parsedValue;
    }
}
