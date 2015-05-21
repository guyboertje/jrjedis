package com.jrjedis;

import org.jruby.Ruby;
import org.jruby.RubyHash;
import org.jruby.RubyNumeric;
import org.jruby.runtime.builtin.IRubyObject;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

/**
 *
 * @author guy
 */
public class OptionsToPool {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 6379;
    private static final int TIMEOUT = 5;
    private static final int POOLSIZE = 32;
//    private static final int CONNECTTIMEOUT = 5;

    public static JedisPool newPool(Ruby ruby, IRubyObject options) {
        JedisPoolConfig poolConfig = new JedisPoolConfig();
        poolConfig.setMaxTotal(POOLSIZE);

        if (options == null || !(options instanceof RubyHash)) {
            return new JedisPool(poolConfig, HOST);
        }
        RubyHash hash = (RubyHash) options;
        if (hash.isEmpty()) {
            return new JedisPool(poolConfig, HOST);
        }

        String host;
        int port;
        int timeout;
//        int connectionTimeout;
        String password = null;
        int db;
        String clientName = null;
        int poolSize;

        host = Utils.toStr(Utils.hashARef(ruby, hash, "host"), HOST);
        port = Utils.toInt(Utils.hashARef(ruby, hash, "port"), PORT);
        int rto = Utils.toInt(Utils.hashARef(ruby, hash, "read_timeout"), TIMEOUT);
        timeout = Utils.toInt(Utils.hashARef(ruby, hash, "timeout"), rto);
//        connectionTimeout = Utils.toInt(Utils.hashARef(ruby, hash, "connect_timeout"), CONNECTTIMEOUT);
        db = Utils.toInt(Utils.hashARef(ruby, hash, "db"), 0);
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
        return new JedisPool(poolConfig, host, port, timeout, password, db, clientName); //jedis 2.7.2 has this constructor
   }

}

//public JedisPool(final GenericObjectPoolConfig poolConfig, final String host, int port,
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

