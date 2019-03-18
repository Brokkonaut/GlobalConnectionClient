package de.cubeside.connection;

public class GlobalPlayerOnServer {
    private final GlobalPlayer player;
    private final GlobalServer server;
    private final long joinTime;

    public GlobalPlayerOnServer(GlobalPlayer player, GlobalServer server, long joinTime) {
        this.player = player;
        this.server = server;
        this.joinTime = joinTime;
    }

    public GlobalPlayer getPlayer() {
        return player;
    }

    public GlobalServer getServer() {
        return server;
    }

    public long getJoinTime() {
        return joinTime;
    }
}
