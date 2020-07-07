package net.tcpshield.tcpshield.velocity;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.proxy.ProxyServer;

import java.util.logging.Logger;

@Plugin(id = "tcpshield",
        name = "TCPShield",
        description = "TCPShield IP parsing capabilities for Velocity"
)
public class TCPShieldVelocity {

    private static TCPShieldVelocity instance;

    public static TCPShieldVelocity getInstance() {
        return instance;
    }

    private final ProxyServer server;
    private final Logger logger;

    @Inject
    public TCPShieldVelocity(ProxyServer server, Logger logger) {
        this.server = server;
        this.logger = logger;
        instance = this;
    }

    @Subscribe
    public void onProxyInitialization(ProxyInitializeEvent event) {
        this.server.getEventManager().register(this, new VelocityHandshakePacketHandler());
    }

    public ProxyServer getServer() {
        return this.server;
    }

    public Logger getLogger() {
        return this.logger;
    }
}