package de.cubeside.connection;

import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class GlobalPlayer {
    private final GlobalClient client;
    private final UUID uuid;
    private final String name;
    private final HashSet<GlobalPlayerOnServer> servers;
    private GlobalPlayerOnServer lastJoined;

    public GlobalPlayer(GlobalClient client, UUID uuid, String name, GlobalServer server, long joinTime) {
        this.client = client;
        this.uuid = uuid;
        this.name = name;
        this.servers = new HashSet<>();
        this.lastJoined = new GlobalPlayerOnServer(this, server, joinTime);
        this.servers.add(lastJoined);
    }

    /**
     * Get the most recently joined server this player is on
     *
     * @return the most recently joined server this player is on
     */
    public GlobalServer getCurrentServer() {
        return lastJoined == null ? null : lastJoined.getServer();
    }

    /**
     * Get all servers server this player is on, ordered by the last join. The most recently joined server is the first in the list.
     *
     * @return a list of all servers this player is on
     */
    public List<GlobalServer> getCurrentServers() {
        return servers.stream().map((s) -> s.getServer()).collect(Collectors.toList());
    }

    /**
     * The current name of this player
     *
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * The UUID of this player
     *
     * @return the uuid
     */
    public UUID getUniqueId() {
        return uuid;
    }

    /**
     * Sends some data to this player. The message will be sent to all servers this player is on.
     * The channel name should use the format <i>plugin.subchannel</i>. This has the same effect as
     * calling {@link #sendData(String, byte[], boolean, boolean)} with sendToUnrestricted false and
     * sendToRestricted false.
     *
     * @param channel
     *            the channel to use. may not be null
     * @param data
     *            the data to send. may not be null
     */
    public void sendData(String channel, byte[] data) {
        sendData(channel, data, false, false);
    }

    /**
     * Sends some data to this player. The message will be sent to all servers this player is on.
     * The channel name should use the format <i>plugin.subchannel</i>.
     *
     * @param channel
     *            the channel to use. may not be null
     * @param data
     *            the data to send. may not be null
     * @param sendToUnrestricted
     *            send this message also to unrestricted servers where this player is not online.
     * @param sendToRestricted
     *            send this message to restricted servers too. If the player is online on some server
     *            the message is always sent there, even if this parameter is false.
     */
    public void sendData(String channel, byte[] data, boolean sendToUnrestricted, boolean sendToRestricted) {
        client.sendData(channel, uuid, null, data, sendToUnrestricted, sendToRestricted);
    }

    public boolean isOnAnyServer() {
        return !servers.isEmpty();
    }

    public boolean isOnServer(GlobalServer server) {
        for (GlobalPlayerOnServer pos : servers) {
            if (pos.getServer() == server) {
                return true;
            }
        }
        return false;
    }

    protected void addServer(GlobalServer server, long joinTime) {
        GlobalPlayerOnServer pos = new GlobalPlayerOnServer(this, server, joinTime);
        servers.add(pos);
        if (lastJoined == null || lastJoined.getJoinTime() < joinTime) {
            lastJoined = pos;
        }
    }

    protected void removeServer(GlobalServer server) {
        for (GlobalPlayerOnServer pos : servers) {
            if (pos.getServer() == server) {
                servers.remove(pos);
                if (lastJoined == pos) {
                    lastJoined = null;
                    for (GlobalPlayerOnServer pos2 : servers) {
                        if (lastJoined == null || lastJoined.getJoinTime() < pos2.getJoinTime()) {
                            lastJoined = pos2;
                        }
                    }
                }
                break;
            }
        }
    }

    public long getJoinTime(GlobalServer s) {
        for (GlobalPlayerOnServer onServer : servers) {
            if (onServer.getServer() == s) {
                return onServer.getJoinTime();
            }
        }
        return -1;
    }

    @Override
    public String toString() {
        return "GlobalPlayer{uuid=" + uuid + ";name=" + name + "}";
    }
}
