package de.cubeside.connection;

import java.util.Collection;
import java.util.UUID;

public interface ConnectionAPI {
    /**
     * Get a collection of all servers
     *
     * @return a collection of all servers
     */
    public Collection<GlobalServer> getServers();

    /**
     * Get a server by name
     *
     * @param name
     *            the name of the server
     * @return the server with that name or null if not found
     */
    public GlobalServer getServer(String name);

    /**
     * Get a collection of all players
     *
     * @return a collection of all players
     */
    public Collection<GlobalPlayer> getPlayers();

    /**
     * Get a player by UUID
     *
     * @param uuid
     *            the players UUID
     * @return the player or null if not found
     */
    public GlobalPlayer getPlayer(UUID uuid);

    /**
     * Get a player by name
     *
     * @param name
     *            the name of the player
     * @return the player or null if not found
     */
    public GlobalPlayer getPlayer(String name);

    /**
     * Sends some data to all servers.
     * The channel name should use the format <i>plugin.subchannel</i>.
     *
     * @param channel
     *            the channel to use. may not be null
     * @param data
     *            the data to send. may not be null
     */
    public void sendData(String channel, byte[] data);
}
