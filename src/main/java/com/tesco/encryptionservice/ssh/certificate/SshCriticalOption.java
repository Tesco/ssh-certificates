package com.tesco.encryptionservice.ssh.certificate;

public enum SshCriticalOption {
    // forces the execution of command instead of any shell or command specified by the user when the certificate is used for authentication
    FORCE_COMMAND("force-command");

    private final String key;

    SshCriticalOption(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }
}
