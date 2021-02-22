package com.tesco.encryptionservice.ssh.parser.algorithms;

import com.tesco.encryptionservice.ssh.certificate.SshCertificate;
import com.tesco.encryptionservice.ssh.parser.decode.SshCertificateDecoder;
import com.tesco.encryptionservice.ssh.parser.encode.SshCertificateEncoder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.List;

@Data
@Accessors(fluent = true)
@EqualsAndHashCode(callSuper = false)
public class EcdsaSshCertificateAlgorithm extends SshCertificateAlgorithm<ECPublicKey> {

    List<String> supportedCurves;

    public EcdsaSshCertificateAlgorithm(String algorithmName, SshCertificateEncoder<ECPublicKey> encoder, SshCertificateDecoder<? extends SshCertificate<ECPublicKey>> decoder, String... supportedCurves) {
        super(algorithmName, encoder, decoder);
        this.supportedCurves = Arrays.asList(supportedCurves);
    }

}
