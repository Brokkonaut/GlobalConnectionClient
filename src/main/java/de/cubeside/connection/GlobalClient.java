package de.cubeside.connection;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Objects;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public abstract class GlobalClient implements ConnectionAPI {
    private final Logger logger;

    private String host;
    private int port;
    private String account;
    private String password;
    private volatile boolean running;

    private PingThread pingThread;
    private ClientThread connection;
    private DataOutputStream dos;

    private final HashMap<String, GlobalServer> servers;
    private final HashMap<UUID, GlobalPlayer> players;
    private final Collection<GlobalServer> unmodifiableServers;
    private final Collection<GlobalPlayer> unmodifiablePlayers;

    protected GlobalClient(Logger logger) {
        this.logger = logger != null ? logger : Logger.getLogger("GlobalClient");
        this.servers = new HashMap<>();
        unmodifiableServers = Collections.unmodifiableCollection(servers.values());
        this.players = new HashMap<>();
        unmodifiablePlayers = Collections.unmodifiableCollection(players.values());
        this.running = true;

        pingThread = new PingThread();
        pingThread.setName("GlobalConnectionPing");
        pingThread.setDaemon(true);
        pingThread.start();
    }

    protected synchronized void setServer(String host, int port, String account, String password) {
        if (this.connection != null) {
            this.connection.shutdown();
            this.connection = null;
            this.dos = null;
        }
        this.account = null;
        this.clearServersAndPlayers();
        this.host = host;
        this.port = port;
        this.account = account;
        this.password = password;
        setServerOnline(this.account);

        this.connection = new ClientThread();
        this.connection.setName("GlobalConnectionClient");
        this.connection.setDaemon(true);
        this.connection.start();
    }

    private class PingThread extends Thread {
        private volatile boolean running = true;

        @Override
        public void run() {
            while (running) {
                sendPing();
                try {
                    Thread.sleep(10000);
                } catch (InterruptedException e) {
                    interrupt();
                }
            }
        }

        public void shutdown() {
            running = false;
            this.interrupt();
        }
    }

    private class ClientThread extends Thread {
        private volatile boolean threadRunning;
        private Socket socket;
        private DataInputStream dis;
        private DataOutputStream localDos;

        @Override
        public void run() {
            threadRunning = true;
            while (running && threadRunning) {
                try {
                    if (socket == null) {
                        dis = null;

                        byte[] randomNumberClient = new byte[32];
                        new SecureRandom().nextBytes(randomNumberClient);

                        socket = new Socket(host, port);
                        DataInputStream dis = new DataInputStream(socket.getInputStream());
                        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                        dos.write(randomNumberClient);

                        byte[] randomNumberServer = new byte[32];
                        dis.readFully(randomNumberServer);
                        dos.writeUTF(account);

                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        digest.update(password.getBytes(StandardCharsets.UTF_8));
                        digest.update(randomNumberServer);
                        digest.update(randomNumberClient);
                        byte[] encodedhash = digest.digest();
                        dos.write(encodedhash);

                        byte result = dis.readByte();
                        if (result == 1) {
                            logger.severe("Login failed!");
                            try {
                                socket.close();
                            } catch (IOException e) {
                                // ignored
                            }
                            dis = null;
                            dos = null;
                            socket = null;
                            try {
                                Thread.sleep(60000);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                            continue;
                        }

                        // switch to encoded connection
                        byte[] secret;
                        digest.reset();
                        digest.update(randomNumberServer);
                        digest.update(password.getBytes(StandardCharsets.UTF_8));
                        digest.update(randomNumberClient);
                        secret = digest.digest();

                        byte[] in = new byte[32];
                        dis.readFully(in);
                        byte[] keyInBytes = new byte[16];
                        byte[] keyOutBytes = new byte[16];
                        for (int i = 0; i < 16; i++) {
                            keyInBytes[i] = (byte) (secret[i] ^ in[i]);
                        }
                        for (int i = 0; i < 16; i++) {
                            keyOutBytes[i] = (byte) (secret[i + 16] ^ in[i + 16]);
                        }

                        SecretKey kpOut = new SecretKeySpec(keyOutBytes, "AES");
                        SecretKey kpIn = new SecretKeySpec(keyInBytes, "AES");

                        DataOutputStream finalDos;
                        try {
                            Cipher cipherAESout = Cipher.getInstance("AES/CFB8/NoPadding");
                            cipherAESout.init(Cipher.ENCRYPT_MODE, kpOut, new IvParameterSpec(new byte[] { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 }));

                            finalDos = new DataOutputStream(new CipherOutputStream(socket.getOutputStream(), cipherAESout));

                            Cipher cipherAESin = Cipher.getInstance("AES/CFB8/NoPadding");
                            cipherAESin.init(Cipher.DECRYPT_MODE, kpIn, new IvParameterSpec(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }));

                            ClientThread.this.dis = new DataInputStream(new CipherInputStream(socket.getInputStream(), cipherAESin));
                        } catch (GeneralSecurityException e) {
                            throw new Error(e);// impossible?
                        }
                        runInMainThread(new Runnable() {
                            @Override
                            public void run() {
                                if (connection == ClientThread.this) {
                                    localDos = finalDos;
                                    sendClientsFromThisServer(finalDos);
                                }
                            }
                        });
                        logger.info("Connection established!");
                    } else {
                        ServerPacketType packet = ServerPacketType.valueOf(dis.readByte());
                        switch (packet) {
                            case PING: {
                                sendPong(this);
                                break;
                            }
                            case PONG: {
                                break;
                            }
                            case SERVER_ONLINE: {
                                String server = dis.readUTF();
                                runInMainThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        if (connection == ClientThread.this) {
                                            setServerOnline(server);
                                        }
                                    }
                                });
                                break;
                            }
                            case SERVER_OFFLINE: {
                                String server = dis.readUTF();
                                runInMainThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        if (connection == ClientThread.this) {
                                            setServerOffine(server);
                                        }
                                    }
                                });
                                break;
                            }
                            case PLAYER_ONLINE: {

                                String server = dis.readUTF();
                                long mostSigBits = dis.readLong();
                                long leastSigBits = dis.readLong();
                                UUID uuid = new UUID(mostSigBits, leastSigBits);
                                String name = dis.readUTF();
                                long joinTime = dis.readLong();

                                runInMainThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        if (connection == ClientThread.this) {
                                            setPlayerOnline(server, uuid, name, joinTime);
                                        }
                                    }
                                });
                                break;
                            }
                            case PLAYER_OFFLINE:

                            {
                                String server = dis.readUTF();
                                long mostSigBits = dis.readLong();
                                long leastSigBits = dis.readLong();
                                UUID uuid = new UUID(mostSigBits, leastSigBits);
                                runInMainThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        if (connection == ClientThread.this) {
                                            setPlayerOffline(server, uuid);
                                        }
                                    }
                                });
                                break;
                            }
                            case DATA: {
                                String server = dis.readUTF();
                                String channel = dis.readUTF();
                                int flags = dis.readByte();
                                UUID targetUuid = null;
                                if ((flags & 0x01) != 0) {
                                    long mostSigBits = dis.readLong();
                                    long leastSigBits = dis.readLong();
                                    targetUuid = new UUID(mostSigBits, leastSigBits);
                                }
                                String targetServer = null;
                                if ((flags & 0x02) != 0) {
                                    targetServer = dis.readUTF();
                                }
                                int dataSize = dis.readInt();
                                if (dataSize > 10_000_000 || dataSize < 0) {
                                    // 10 mb
                                    throw new IOException("Oversized data packet received from '" + account + "' from " + socket.getInetAddress().getHostAddress() + " (" + dataSize + " bytes).");
                                }
                                byte[] data = new byte[dataSize];
                                dis.readFully(data);
                                final UUID finalTargetUuid = targetUuid;
                                final String finalTargetServer = targetServer;
                                runInMainThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        if (connection == ClientThread.this) {
                                            GlobalServer source = getServer(server);
                                            GlobalPlayer targetPlayer = finalTargetUuid == null ? null : getPlayer(finalTargetUuid);
                                            GlobalServer targetServer = finalTargetServer == null ? null : getServer(finalTargetServer);

                                            processData(source, channel, targetPlayer, targetServer, data);
                                        }
                                    }
                                });
                                break;
                            }
                        }
                    }

                } catch (IOException e) {
                    if (e instanceof ConnectException) {
                        logger.severe("Could not connect to the server!");
                        // wait some time before retry
                        try {
                            Thread.sleep(10000);
                        } catch (InterruptedException e2) {
                            Thread.currentThread().interrupt();
                        }
                    } else if ((running && threadRunning) || !(e instanceof SocketException)) {
                        if ("Connection reset".equals(e.getMessage()) || (e instanceof EOFException)) {
                            logger.warning("Lost connection to the server!");
                        } else {
                            logger.log(Level.SEVERE, "Exception while reading from the server", e);
                        }
                        // wait some time before retry
                        try {
                            Thread.sleep(5000);
                        } catch (InterruptedException e2) {
                            Thread.currentThread().interrupt();
                        }
                    }
                    if (socket != null) {
                        try {
                            socket.close();
                        } catch (IOException e1) {
                            // ignore
                        }
                        socket = null;
                    }
                    dis = null;
                    localDos = null;
                    runInMainThread(new Runnable() {
                        @Override
                        public void run() {
                            if (connection == ClientThread.this) {
                                clearServersAndPlayers();
                            }
                        }
                    });
                } catch (NoSuchAlgorithmException e) {
                    throw new Error(e); // impossible
                }
            }
        }

        public void shutdown() {
            logger.log(Level.INFO, "Closing connection!");
            threadRunning = false;
            Socket localSocket = socket;
            if (localSocket != null) {
                synchronized (GlobalClient.this) {
                    DataOutputStream dos = this.localDos;
                    if (dos != null) {
                        try {
                            dos.writeByte(ClientPacketType.SERVER_OFFLINE.ordinal());
                        } catch (Exception e) {
                            logger.log(Level.SEVERE, "Exception sending server offline!", e);
                        }
                    }
                }
                try {
                    localSocket.close();
                } catch (IOException e) {
                    // ignored
                }
            }
            interrupt();
        }
    }

    protected synchronized void sendClientsFromThisServer(DataOutputStream dos) {
        this.dos = dos;
        for (GlobalServer s : servers.values()) {
            if (s.getName().equals(account)) {
                for (GlobalPlayer p : s.getPlayers()) {
                    sendPlayerOnline(p.getUniqueId(), p.getName(), p.getJoinTime(s));
                }
            }
        }
    }

    protected synchronized void clearServersAndPlayers() {
        dos = null;
        for (GlobalServer s : new ArrayList<>(servers.values())) {
            if (account == null || !account.equals(s.getName())) {
                setServerOffine(s.getName());
            }
        }
    }

    protected synchronized void sendPing() {
        DataOutputStream dos = this.dos;
        if (dos != null) {
            try {
                dos.writeByte(ClientPacketType.PING.ordinal());
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Exception sending ping!", e);
            }
        }
    }

    protected synchronized void sendPong(ClientThread client) {
        DataOutputStream dos = client.localDos;
        if (dos != null) {
            try {
                dos.writeByte(ClientPacketType.PONG.ordinal());
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Exception sending pong!", e);
            }
        }
    }

    protected void processData(GlobalServer source, String channel, GlobalPlayer targetPlayer, GlobalServer targetServer, byte[] data) {
        logger.info("Data from " + source + " in Channel " + channel + " to " + targetPlayer + "; " + targetServer + " Data: " + bytesToHexString(data));
    }

    public static String bytesToHexString(byte[] bytes) {
        StringBuffer hexString = new StringBuffer(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xff & bytes[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    protected synchronized void setPlayerOffline(String server, UUID uuid) {
        if (!servers.containsKey(server)) {
            throw new IllegalArgumentException("Server " + server + " is not online.");
        }
        GlobalServer globalServer = servers.get(server);
        GlobalPlayer player = players.get(uuid);
        boolean leftTheNetwork = false;
        if (player == null) {
            throw new IllegalArgumentException("Player " + uuid + " is not online.");
        } else if (!player.isOnServer(globalServer)) {
            throw new IllegalArgumentException("Player " + uuid + " is not on server " + server + ".");
        }
        player.removeServer(globalServer);
        if (!player.isOnAnyServer()) {
            players.remove(uuid);
            leftTheNetwork = true;
        }

        globalServer.removePlayer(uuid);
        onPlayerDisconnected(globalServer, player, leftTheNetwork);
    }

    protected synchronized void setPlayerOnline(String server, UUID uuid, String name, long joinTime) {
        if (!servers.containsKey(server)) {
            throw new IllegalArgumentException("Server " + server + " is not online.");
        }
        GlobalServer globalServer = servers.get(server);
        GlobalPlayer player = players.get(uuid);
        boolean joinedTheNetwork = false;
        if (player == null) {
            player = new GlobalPlayer(this, uuid, name, globalServer, joinTime);
            players.put(uuid, player);
            joinedTheNetwork = true;
        } else if (player.isOnServer(globalServer)) {
            throw new IllegalArgumentException("Player " + uuid + " is already on server " + server + ".");
        } else {
            player.addServer(globalServer, joinTime);
        }
        globalServer.addPlayer(player);
        onPlayerJoined(globalServer, player, joinedTheNetwork);
    }

    protected abstract void onPlayerJoined(GlobalServer server, GlobalPlayer player, boolean joinedTheNetwork);

    protected abstract void onPlayerDisconnected(GlobalServer server, GlobalPlayer player, boolean leftTheNetwork);

    protected abstract void onServerDisconnected(GlobalServer server);

    protected abstract void onServerConnected(GlobalServer server);

    protected synchronized void setServerOffine(String server) {
        if (!servers.containsKey(server)) {
            throw new IllegalArgumentException("Server " + server + " is not online.");
        }
        GlobalServer offline = servers.get(server);
        for (GlobalPlayer player : new ArrayList<>(offline.getPlayers())) {
            player.removeServer(offline);
            boolean leftTheNetwork = false;
            if (!player.isOnAnyServer()) {
                players.remove(player.getUniqueId());
                leftTheNetwork = true;
            }
            onPlayerDisconnected(offline, player, leftTheNetwork);
        }
        servers.remove(server);
        onServerDisconnected(offline);
    }

    protected synchronized void setServerOnline(String server) {
        if (servers.containsKey(server)) {
            throw new IllegalArgumentException("Server " + server + " is already online.");
        }
        GlobalServer joined = new GlobalServer(this, server);
        servers.put(server, joined);
        onServerConnected(joined);
    }

    protected synchronized void onPlayerOnline(UUID uuid, String name, long joinTime) {
        Objects.requireNonNull(uuid, "uuid");
        Objects.requireNonNull(name, "name");
        setPlayerOnline(account, uuid, name, joinTime);

        sendPlayerOnline(uuid, name, joinTime);
    }

    private void sendPlayerOnline(UUID uuid, String name, long joinTime) {
        DataOutputStream dos = this.dos;
        if (dos != null) {
            try {
                dos.writeByte(ClientPacketType.PLAYER_ONLINE.ordinal());
                dos.writeLong(uuid.getMostSignificantBits());
                dos.writeLong(uuid.getLeastSignificantBits());
                dos.writeUTF(name);
                dos.writeLong(joinTime);
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Exception sending player online!", e);
            }
        }
    }

    protected synchronized void onPlayerOffline(UUID uuid) {
        Objects.requireNonNull(uuid, "uuid");
        setPlayerOffline(account, uuid);

        DataOutputStream dos = this.dos;
        if (dos != null) {
            try {
                dos.writeByte(ClientPacketType.PLAYER_OFFLINE.ordinal());
                dos.writeLong(uuid.getMostSignificantBits());
                dos.writeLong(uuid.getLeastSignificantBits());
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Exception sending player offline!", e);
            }
        }
    }

    @Override
    public void sendData(String channel, byte[] data) {
        sendData(channel, data, false);
    }

    @Override
    public void sendData(String channel, byte[] data, boolean sendToRestricted) {
        sendData(channel, null, null, data, false, sendToRestricted);
    }

    protected synchronized void sendData(String channel, UUID targetUuid, String targetServer, byte[] data, boolean sendToAll, boolean sendToRestricted) {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(data, "data");
        byte[] dataClone = data.clone();
        DataOutputStream dos = this.dos;
        if (dos != null) {
            try {
                dos.writeByte(ClientPacketType.DATA.ordinal());
                dos.writeUTF(channel);
                int flags = (targetUuid != null ? 1 : 0) + (targetServer != null ? 2 : 0) + (sendToRestricted ? 4 : 0) + (sendToAll ? 8 : 0);
                dos.writeByte(flags);
                if (targetUuid != null) {
                    dos.writeLong(targetUuid.getMostSignificantBits());
                    dos.writeLong(targetUuid.getLeastSignificantBits());
                }
                if (targetServer != null) {
                    dos.writeUTF(targetServer);
                }
                dos.writeInt(data.length);
                dos.write(dataClone);
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Exception sending data!", e);
            }
        }
    }

    public void shutdown() {
        running = false;
        ClientThread localConnection = this.connection;
        if (localConnection != null) {
            localConnection.shutdown();
        }
        PingThread pingThread = this.pingThread;
        if (pingThread != null) {
            pingThread.shutdown();
            pingThread = null;
        }
    }

    protected abstract void runInMainThread(Runnable r);

    @Override
    public Collection<GlobalServer> getServers() {
        return unmodifiableServers;
    }

    @Override
    public GlobalServer getServer(String name) {
        return servers.get(name);
    }

    @Override
    public GlobalServer getThisServer() {
        return servers.get(account);
    }

    @Override
    public Collection<GlobalPlayer> getPlayers() {
        return unmodifiablePlayers;
    }

    @Override
    public GlobalPlayer getPlayer(UUID uuid) {
        return players.get(uuid);
    }

    @Override
    public GlobalPlayer getPlayer(String name) {
        for (GlobalPlayer p : players.values()) {
            if (p.getName().equalsIgnoreCase(name)) {
                return p;
            }
        }
        return null;
    }
}
