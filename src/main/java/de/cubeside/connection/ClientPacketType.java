package de.cubeside.connection;

public enum ClientPacketType {
    PING,
    PONG,
    PLAYER_ONLINE,
    PLAYER_OFFLINE,
    SERVER_OFFLINE,
    DATA;

    static final ClientPacketType[] values = values();

    public static ClientPacketType valueOf(int ordinal) {
        return values[ordinal];
    }
}
