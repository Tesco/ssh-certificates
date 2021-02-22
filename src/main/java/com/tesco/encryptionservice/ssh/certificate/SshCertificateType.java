package com.tesco.encryptionservice.ssh.certificate;

import lombok.SneakyThrows;

import static java.lang.String.format;

public enum SshCertificateType {

    SSH_CERT_TYPE_USER(1),
    SSH_CERT_TYPE_HOST(2);

    private final int type;

    SshCertificateType(int type) {
        this.type = type;
    }

    @SneakyThrows
    public static SshCertificateType getType(int type) {
        if (type == 1) {
            return SSH_CERT_TYPE_USER;
        } else if (type == 2) {
            return SSH_CERT_TYPE_HOST;
        } else {
            throw new IllegalArgumentException(format("Unrecognised type %d, should be 1 or 2", type));
        }
    }

    public int getType() {
        return type;
    }

}
