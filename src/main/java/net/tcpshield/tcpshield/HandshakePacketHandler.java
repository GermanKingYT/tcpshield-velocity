package net.tcpshield.tcpshield;

import net.tcpshield.tcpshield.abstraction.IPacket;
import net.tcpshield.tcpshield.abstraction.IPlayer;
import net.tcpshield.tcpshield.exception.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;

public class HandshakePacketHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(HandshakePacketHandler.class);

    private final SignatureVerifier signatureVerifier;

    public HandshakePacketHandler() {
        try {
            this.signatureVerifier = new SignatureVerifier();
        } catch (Exception e) {
            throw new TCPShieldInitializationException(e);
        }
    }

    public boolean onHandshake(IPacket packet, IPlayer player) {
        String rawPayload = packet.getRawPayload();

        try {
            String extraData = null;

            // fix for e.g. incoming FML tagged packets
            String cleanedPayload;
            int nullIndex = rawPayload.indexOf('\0');
            if (nullIndex != -1) { // FML tagged
                cleanedPayload = rawPayload.substring(0, nullIndex);
                extraData = rawPayload.substring(nullIndex);
            } else { // standard
                cleanedPayload = rawPayload;
            }

            String[] payload = cleanedPayload.split("///", 4);
            if (payload.length != 4)
                throw new MalformedPayloadException("payload.length != 4. Raw payload = \"" + rawPayload + "\"");

            String hostname = payload[0];
            String ipData = payload[1];
            int timestamp;
            try {
                timestamp = Integer.parseInt(payload[2]);
            } catch (NumberFormatException e) {
                throw new MalformedPayloadException(e);
            }
            String signature = payload[3];

            String[] hostnameParts = ipData.split(":");
            String host = hostnameParts[0];
            int port = Integer.parseInt(hostnameParts[1]);

            String reconstructedPayload = hostname + "///" + host + ":" + port + "///" + timestamp;

            if (!signatureVerifier.verify(reconstructedPayload, signature))
                throw new SigningVerificationFailureException();

            InetSocketAddress newIP = new InetSocketAddress(host, port);
            player.setIP(newIP);

            if (extraData != null) hostname = hostname + extraData;

            packet.modifyOriginalPacket(hostname);
            return true;
        } catch (SigningVerificationFailureException e) {
            handleSigningVerificationFailure(player, rawPayload);
        } catch (ConnectionNotProxiedException e) {
            handleNotProxiedConnection(player, rawPayload);
        } catch (IPModificationFailureException e) {
            LOGGER.warn(String.format("%s[%s/%s]'s IP failed to be modified. Raw payload = \"%s\"", player.getName(), player.getUUID(), player.getIP(), rawPayload));
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private void handleSigningVerificationFailure(IPlayer player, String rawPayload) {
        LOGGER.warn(String.format("%s[%s/%s] provided valid handshake information, but signing check failed. Raw payload = \"%s\"", player.getName(), player.getUUID(), player.getIP(), rawPayload));

        player.disconnect();
    }

    private void handleNotProxiedConnection(IPlayer player, String rawPayload) {
        LOGGER.warn(String.format("%s[%s/%s] was disconnected because no proxy info was received and only-allow-proxy-connections is enabled. Raw payload = \"%s\"", player.getName(), player.getUUID(), player.getIP(), rawPayload));

        player.disconnect();
    }
}
