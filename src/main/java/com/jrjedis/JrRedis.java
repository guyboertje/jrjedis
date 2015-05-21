package com.jrjedis;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

/**
 *
 * @author guy
 */
@JRubyClass(name = "JrJedis::Redis", parent = "Object")
public class JrRedis extends RubyObject {

    private static JedisPool pool;

    public static final ObjectAllocator JRREDIS_ALLOCATOR = new ObjectAllocator() {
        @Override
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new JrRedis(runtime, klass);
        }
    };

    @JRubyMethod(name = "new", required = 1, meta = true)
    public static JrRedis newInstance(IRubyObject self, IRubyObject arg) {
        JrRedis session = (JrRedis) ((RubyClass) self).allocate();
        session.callInit(arg, Block.NULL_BLOCK);
        return session;
    }

    @JRubyMethod(required = 1, visibility = Visibility.PRIVATE)
    public void initialize(ThreadContext context, IRubyObject options) {
        pool = OptionsToPool.newPool(context.runtime, options);
    }

    public JrRedis(final Ruby runtime, RubyClass rubyClass) {
        super(runtime, rubyClass);
    }

    /**
     * Ping the server
     *
     * @param context Ruby thread context
     * @return "PONG"
     */
    @JRubyMethod
    public IRubyObject ping(ThreadContext context) {
        try (Jedis jedis = pool.getResource()) {
            String reply = jedis.ping();
            return Utils.stringify(context.runtime, reply);
        }
    }

    @JRubyMethod(name = {"[]", "get"}, required = 1)
    public IRubyObject op_get(ThreadContext context, IRubyObject key) {
        try (Jedis jedis = pool.getResource()) {
            String reply = jedis.get(key.toString());
            return Utils.stringify(context.runtime, reply);
        }
    }
    @JRubyMethod(name = {"[]=", "set"}, required = 2)
    public IRubyObject op_set(ThreadContext context, IRubyObject key, IRubyObject value) {
        try (Jedis jedis = pool.getResource()) {
            String reply = jedis.set(key.toString(), value.toString());
            return Utils.boolify(context.runtime, reply);
        }
    }

    @JRubyMethod(name = {"[]=", "set"}, required = 3)
    public IRubyObject op_set_o(ThreadContext context, IRubyObject key, IRubyObject value, IRubyObject options) {
        String reply = "";
        RubyHash hash = (RubyHash)options;
        if (hash.isNil() || hash.isEmpty()) {
            try (Jedis jedis = pool.getResource()) {
                reply = jedis.set(key.toString(), value.toString());
                return Utils.boolify(context.runtime, reply);
            }
        }

        Ruby ruby = context.runtime;
        String expx = null;
        String nxxx = null;

        int time = Utils.toInt(Utils.hashARef(ruby, hash, "px"), -1);

        if (time != -1) {
            expx = "PX";
        }
        else {
            time = Utils.toInt(Utils.hashARef(ruby, hash, "ex"), -1);
        }
        if (time != -1) {
            expx = "EX";
        }
        nxxx = hash.containsKey(ruby.newSymbol("nx")) ? "NX" :
                    hash.containsKey(ruby.newSymbol("xx")) ? "XX" : null;

        try (Jedis jedis = pool.getResource()) {
            reply = jedis.set(key.toString(), value.toString(), nxxx, expx, time);
            return Utils.boolify(context.runtime, reply);
        }
    }


    
    // ----------------------------


}
