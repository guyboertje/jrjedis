package com.jrjedis;

import org.jruby.Ruby;
import org.jruby.RubyHash;
import org.jruby.runtime.builtin.IRubyObject;
import redis.clients.jedis.JedisBinaryPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.Protocol;

/**
 *
 * @author guy
 */
public class OptionsToPool {

    private static final int POOLSIZE = 32;
    private static final double TIMEOUT = 5.0;
//    private static final double CONNECTTIMEOUT = 5.0;

    public static JedisBinaryPool newPool(Ruby ruby, IRubyObject options) {
        return newPool(ruby, options, Protocol.DEFAULT_DATABASE);
    }

    public static JedisBinaryPool newPool(Ruby ruby, IRubyObject options, int db) {
        JedisPoolConfig poolConfig = new JedisPoolConfig();
        poolConfig.setMaxTotal(POOLSIZE);
        int timeout = (int)(1000.0 * TIMEOUT);

        if (options == null || !(options instanceof RubyHash)) {
           return new JedisBinaryPool(poolConfig, Protocol.DEFAULT_HOST, Protocol.DEFAULT_PORT,
                    timeout, null, db, null);
        }

        RubyHash hash = (RubyHash)options;
        if (hash.isEmpty()) {
            return new JedisBinaryPool(poolConfig, Protocol.DEFAULT_HOST, Protocol.DEFAULT_PORT,
                    timeout, null, db, null);
        }

        String host;
        int port;

//        int connectionTimeout;
        String password = null;
        String clientName = null;
        int poolSize;

        double tempTimeout;

        host = Utils.toStr(Utils.hashARef(ruby, hash, "host"), Protocol.DEFAULT_HOST);
        port = Utils.toInt(Utils.hashARef(ruby, hash, "port"), Protocol.DEFAULT_PORT);
        tempTimeout = Utils.toDouble(Utils.hashARef(ruby, hash, "read_timeout"), TIMEOUT);
        tempTimeout = Utils.toDouble(Utils.hashARef(ruby, hash, "timeout"), tempTimeout);
//        connectionTimeout = Utils.toInt(Utils.hashARef(ruby, hash, "connect_timeout"), CONNECTTIMEOUT);
        timeout = (int)(1000.0 * tempTimeout);
        poolSize = Utils.toInt(Utils.hashARef(ruby, hash, "pool_size"), POOLSIZE);

        poolConfig = new JedisPoolConfig();
        poolConfig.setMaxTotal(poolSize);

        IRubyObject val = Utils.hashARef(ruby, hash, "password");
        if (!val.isNil()) {
            password = val.toString();
        }

        val = Utils.hashARef(ruby, hash, "id");
        if (!val.isNil()) {
            clientName = val.toString();
        }

        // jedis master has a constructor that includes a connectionTimeout
        return new JedisBinaryPool(poolConfig, host, port, timeout, password, db, clientName); //jedis 2.7.2 has this constructor
   }

}

//public JedisBinaryPool(final GenericObjectPoolConfig poolConfig, final String host, int port,
//      final int connectionTimeout, final int soTimeout, final String password, final int database,
//      final String clientName) {
//
//  }

//
//+  # @option options [Float] :timeout (5.0) timeout in seconds
//+  # @option options [Float] :connect_timeout (same as timeout) timeout for initial connect in seconds
//+  # @option options [String] :password Password to authenticate against server
//+  # @option options [Fixnum] :db (0) Database to select after initial connect
//+  # @option options [String] :id ID for the client connection, assigns name to current connection by sending `CLIENT SETNAME`

//    from ruby redis client
//    DEFAULTS = {
//      :url => lambda { ENV["REDIS_URL"] },
//      :scheme => "redis",
//      :host => "127.0.0.1",
//      :port => 6379,
//      :path => nil,
//      :timeout => 5.0,
//      :read_timeout => 5.0,
//      :connect_timeout => 5.0,
//      :password => nil,
//      :db => 0,
//      :driver => nil,
//      :id => nil,
//      :tcp_keepalive => 0,
//      :reconnect_attempts => 1,
//      :inherit_socket => false,
//      :pool_size => 128 //<-- added by JrJedis
//    }

