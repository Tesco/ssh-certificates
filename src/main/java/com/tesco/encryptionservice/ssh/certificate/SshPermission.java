package com.tesco.encryptionservice.ssh.certificate;

public enum SshPermission {
    // allow local ssh-agent to handle authorisation requests for any ssh connections done inside an existing ssh connection (i.e. transitive ssh connections) when the certificate is used for authentication
    PERMIT_AGENT_FORWARDING("permit-agent-forwarding"),
    // allow encrypted tunnelling of application ports from the client machine to the server machine, or vice versa when the certificate is used for authentication
    PERMIT_PORT_FORWARDING("permit-port-forwarding"),
    // allow run commands in ~/.ssh/rc or ~/.ssh2/rc or /etc/sshrc to be executed before the shell or remote command request on an incoming connection when the certificate is used for authentication
    PERMIT_USER_RC("permit-user-rc"),
    // allow use of a pseudoterminal for ssh connections when the certificate is used for authentication
    PERMIT_PTY("permit-pty"),
    // allow encrypted remote GUI via X Windows when the certificate is used for authentication
    PERMIT_X11_FORWARDING("permit-X11-forwarding");

    private final String key;

    SshPermission(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }
}
