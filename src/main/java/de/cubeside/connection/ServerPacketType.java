package de.cubeside.connection;

public enum ServerPacketType {
    PING,
    PONG,
    PLAYER_ONLINE,
    PLAYER_OFFLINE,
    SERVER_ONLINE,
    SERVER_OFFLINE,
    DATA;

    static final ServerPacketType[] values = values();

    public static ServerPacketType valueOf(int ordinal) {
        return values[ordinal];
    }
}
