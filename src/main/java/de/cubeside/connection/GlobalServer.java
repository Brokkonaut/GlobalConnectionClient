package de.cubeside.connection;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.UUID;

public class GlobalServer {
    private final GlobalClient client;
    private final String name;
    private final HashMap<UUID, GlobalPlayer> players;
    private final Collection<GlobalPlayer> unmodifiablePlayers;

    public GlobalServer(GlobalClient client, String name) {
        this.client = client;
        this.name = name;
        this.players = new HashMap<>();
        this.unmodifiablePlayers = Collections.unmodifiableCollection(this.players.values());
    }

    public String getName() {
        return name;
    }

    public Collection<GlobalPlayer> getPlayers() {
        return unmodifiablePlayers;
    }

    /**
     * Sends some data to this server.
     * The channel name should use the format <i>plugin.subchannel</i>.
     *
     * @param channel
     *            the channel to use. may not be null
     * @param data
     *            the data to send. may not be null
     */
    public void sendData(String channel, byte[] data) {
        client.sendData(channel, null, name, data);
    }

    protected void addPlayer(GlobalPlayer player) {
        players.put(player.getUniqueId(), player);
    }

    protected void removePlayer(UUID player) {
        players.remove(player);
    }

    @Override
    public String toString() {
        return "GlobalServer{name=" + name + "}";
    }
}
