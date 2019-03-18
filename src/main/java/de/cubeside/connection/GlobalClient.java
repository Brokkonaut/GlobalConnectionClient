package de.cubeside.connection;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
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
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public abstract class GlobalClient implements ConnectionAPI {
    private final String host;
    private final int port;
    private final String account;
    private final String password;
    private volatile boolean running;

    private final ClientThread connection;

    private final HashMap<String, GlobalServer> servers;
    private final HashMap<UUID, GlobalPlayer> players;
    private final Collection<GlobalServer> unmodifiableServers;
    private final Collection<GlobalPlayer> unmodifiablePlayers;

    protected GlobalClient(String host, int port, String account, String password, boolean startThread) {
        this.host = host;
        this.port = port;
        this.account = account;
        this.password = password;
        this.running = true;
        this.servers = new HashMap<>();
        unmodifiableServers = Collections.unmodifiableCollection(servers.values());
        this.players = new HashMap<>();
        unmodifiablePlayers = Collections.unmodifiableCollection(players.values());

        setServerOnline(account);
        this.connection = new ClientThread();
        this.connection.setName("GlobalConnectionClient");
        this.connection.setDaemon(true);
        if (startThread) {
            this.connection.start();
        }
    }

    protected void startThread() {
        this.connection.start();
    }

    private class ClientThread extends Thread {
        private Socket socket;
        private DataInputStream dis;
        private DataOutputStream dos;

        @Override
        public void run() {
            while (running) {
                try {
                    if (socket == null) {
                        dis = null;
                        dos = null;

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
                            System.out.println("Login failed!");
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
                        byte[] seedOut;
                        byte[] seedIn;
                        digest.reset();
                        digest.update(randomNumberServer);
                        digest.update(password.getBytes(StandardCharsets.UTF_8));
                        digest.update(randomNumberClient);
                        seedIn = digest.digest();
                        digest.reset();
                        digest.update(randomNumberClient);
                        digest.update(randomNumberServer);
                        digest.update(password.getBytes(StandardCharsets.UTF_8));
                        seedOut = digest.digest();
                        SecretKey kpOut = generateSecretKey(new SecureRandom(seedOut));
                        SecretKey kpIn = generateSecretKey(new SecureRandom(seedIn));

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
                                ClientThread.this.dos = finalDos;
                                sendClientsFromThisServer();
                            }
                        });
                        System.out.println("Connection established!");
                    } else {
                        ServerPacketType packet = ServerPacketType.valueOf(dis.readByte());
                        switch (packet) {
                            case PING: {
                                sendPong();
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
                                        setServerOnline(server);
                                    }
                                });
                                break;
                            }
                            case SERVER_OFFLINE: {
                                String server = dis.readUTF();
                                runInMainThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        setServerOffine(server);
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
                                        setPlayerOnline(server, uuid, name, joinTime);
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
                                        setPlayerOffline(server, uuid);
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
                                        GlobalServer source = getServer(server);
                                        GlobalPlayer targetPlayer = finalTargetUuid == null ? null : getPlayer(finalTargetUuid);
                                        GlobalServer targetServer = finalTargetServer == null ? null : getServer(finalTargetServer);

                                        processData(source, channel, targetPlayer, targetServer, data);
                                    }
                                });
                                break;
                            }
                        }
                    }

                } catch (IOException e) {
                    if (e instanceof ConnectException) {
                        System.out.println("Could not connect to the server!");
                        try {
                            Thread.sleep(10000);
                        } catch (InterruptedException e2) {
                            Thread.currentThread().interrupt();
                        }
                    } else if (running || !(e instanceof SocketException)) {
                        if ("Connection reset".equals(e.getMessage()) || (e instanceof EOFException)) {
                            System.out.println("Lost connection to the server!");
                        } else {
                            System.out.println(e.getMessage());
                            e.printStackTrace();
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
                    runInMainThread(new Runnable() {
                        @Override
                        public void run() {
                            dos = null;
                            clearServersAndPlayers();
                        }
                    });
                } catch (NoSuchAlgorithmException e) {
                    throw new Error(e); // impossible
                }
            }
        }

        protected synchronized void sendClientsFromThisServer() {
            for (GlobalServer s : servers.values()) {
                if (s.getName().equals(account)) {
                    for (GlobalPlayer p : s.getPlayers()) {
                        sendPlayerOnline(p.getUniqueId(), p.getName(), p.getJoinTime(s));
                    }
                }
            }
        }

        protected synchronized void clearServersAndPlayers() {
            for (GlobalServer s : new ArrayList<>(servers.values())) {
                if (!s.getName().equals(account)) {
                    setServerOffine(s.getName());
                }
            }
        }

        private synchronized void sendPong() {
            DataOutputStream dos = this.dos;
            if (dos != null) {
                try {
                    dos.writeByte(ClientPacketType.PONG.ordinal());
                } catch (Exception e) {
                    System.out.println("Exception sending pong!" + e);
                }
            }
        }

        public void shutdown() {
            Socket localSocket = socket;
            if (localSocket != null) {
                synchronized (this) {
                    DataOutputStream dos = this.dos;
                    if (dos != null) {
                        try {
                            dos.writeByte(ClientPacketType.SERVER_OFFLINE.ordinal());
                        } catch (Exception e) {
                            System.out.println("Exception sending server offline!" + e);
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

        private SecretKey generateSecretKey(SecureRandom random) {
            KeyGenerator keygeneratorAES;
            try {
                keygeneratorAES = KeyGenerator.getInstance("AES");
            } catch (NoSuchAlgorithmException e) {
                throw new Error("No AES?", e);
            }
            keygeneratorAES.init(128, random);
            return keygeneratorAES.generateKey();
        }

    }

    protected void processData(GlobalServer source, String channel, GlobalPlayer targetPlayer, GlobalServer targetServer, byte[] data) {
        System.out.println("Data from " + source + " in Channel " + channel + " to " + targetPlayer + "; " + targetServer + " Data: " + bytesToHexString(data));
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
        if (player == null) {
            throw new IllegalArgumentException("PLayer " + uuid + " is not online.");
        } else if (!player.isOnServer(globalServer)) {
            throw new IllegalArgumentException("Player " + uuid + " is not on server " + server + ".");
        } else {
            player.removeServer(globalServer);
            if (!player.isOnAnyServer()) {
                players.remove(uuid);
            }
        }
        globalServer.removePlayer(uuid);
    }

    protected synchronized void setPlayerOnline(String server, UUID uuid, String name, long joinTime) {
        if (!servers.containsKey(server)) {
            throw new IllegalArgumentException("Server " + server + " is not online.");
        }
        GlobalServer globalServer = servers.get(server);
        GlobalPlayer player = players.get(uuid);
        if (player == null) {
            player = new GlobalPlayer(this, uuid, name, globalServer, joinTime);
            players.put(uuid, player);
        } else if (player.isOnServer(globalServer)) {
            throw new IllegalArgumentException("Player " + uuid + " is already on server " + server + ".");
        } else {
            player.addServer(globalServer, joinTime);
        }
        globalServer.addPlayer(player);
    }

    protected synchronized void setServerOffine(String server) {
        if (!servers.containsKey(server)) {
            throw new IllegalArgumentException("Server " + server + " is not online.");
        }
        GlobalServer offline = servers.remove(server);
        for (GlobalPlayer player : new ArrayList<>(offline.getPlayers())) {
            player.removeServer(offline);
            if (!player.isOnAnyServer()) {
                players.remove(player.getUniqueId());
            }
        }
    }

    protected synchronized void setServerOnline(String server) {
        if (servers.containsKey(server)) {
            throw new IllegalArgumentException("Server " + server + " is already online.");
        }
        servers.put(server, new GlobalServer(this, server));
    }

    protected synchronized void onPlayerOnline(UUID uuid, String name, long joinTime) {
        Objects.requireNonNull(uuid, "uuid");
        Objects.requireNonNull(name, "name");
        setPlayerOnline(account, uuid, name, joinTime);

        sendPlayerOnline(uuid, name, joinTime);
    }

    private void sendPlayerOnline(UUID uuid, String name, long joinTime) {
        DataOutputStream dos = this.connection.dos;
        if (dos != null) {
            try {
                dos.writeByte(ClientPacketType.PLAYER_ONLINE.ordinal());
                dos.writeLong(uuid.getMostSignificantBits());
                dos.writeLong(uuid.getLeastSignificantBits());
                dos.writeUTF(name);
                dos.writeLong(joinTime);
            } catch (Exception e) {
                System.out.println("Exception sending player online!" + e);
            }
        }
    }

    protected synchronized void onPlayerOffline(UUID uuid) {
        Objects.requireNonNull(uuid, "uuid");
        setPlayerOffline(account, uuid);

        DataOutputStream dos = this.connection.dos;
        if (dos != null) {
            try {
                dos.writeByte(ClientPacketType.PLAYER_OFFLINE.ordinal());
                dos.writeLong(uuid.getMostSignificantBits());
                dos.writeLong(uuid.getLeastSignificantBits());
            } catch (Exception e) {
                System.out.println("Exception sending player offline!" + e);
            }
        }
    }

    @Override
    public void sendData(String channel, byte[] data) {
        sendData(channel, null, null, data);
    }

    protected synchronized void sendData(String channel, UUID targetUuid, String targetServer, byte[] data) {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(data, "data");
        byte[] dataClone = data.clone();
        DataOutputStream dos = this.connection.dos;
        if (dos != null) {
            try {
                dos.writeByte(ClientPacketType.DATA.ordinal());
                dos.writeUTF(channel);
                int flags = (targetUuid != null ? 1 : 0) + (targetServer != null ? 2 : 0);
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
                System.out.println("Exception sending data!" + e);
            }
        }
    }

    public void shutdown() {
        running = false;
        connection.shutdown();
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
            if (p.getName().equals(name)) {
                return p;
            }
        }
        return null;
    }

    public static void main(String[] args) throws IOException {
        // TextComponent tc = new TextComponent("lala");
        // tc.setClickEvent(new ClickEvent(Action.RUN_COMMAND, "blubb\"("));
        // String serialized = ComponentSerializer.toString(tc);
        // System.out.println(serialized);
        // System.out.println(ComponentSerializer.parse(serialized));
        // System.exit(0);
        GlobalClient client = new GlobalClient("localhost", 12345, "test", "testpassword", true) {
            @Override
            protected void runInMainThread(Runnable r) {
                r.run();
            }
        };
        System.out.println("Starting the client!");
        new BufferedReader(new InputStreamReader(System.in)).readLine();
        client.onPlayerOnline(UUID.randomUUID(), "Brokkonaut", System.currentTimeMillis());
        new BufferedReader(new InputStreamReader(System.in)).readLine();
        client.sendData("testchannel", "abc".getBytes());
        new BufferedReader(new InputStreamReader(System.in)).readLine();
        System.out.println("Stopping the client!");
        client.shutdown();
    }
}
