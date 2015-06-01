package com.jrjedis;

import java.util.HashMap;
import java.util.List;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.Block;
import org.jruby.runtime.Helpers;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import redis.clients.jedis.BinaryClient;
import redis.clients.jedis.BinaryJedis;
import redis.clients.jedis.BitOP;
import redis.clients.jedis.BitPosParams;
import redis.clients.jedis.JedisBinaryPool;
import redis.clients.jedis.SortingParams;
import redis.clients.jedis.Protocol;
import redis.clients.util.SafeEncoder;

/**
 *
 * @author guy
 */
@JRubyClass(name = "JrBinaryJedis::Redis", parent = "Object")
public class JrRedis extends RubyObject {

    private static JedisBinaryPool pool;
    private static HashMap<Integer, JedisBinaryPool> pools = new HashMap<>();

    private static byte[] DEFAULTPATTERN = {Protocol.ASTERISK_BYTE};

    private static final String OR = "or";
    private static final String XOR = "xor";
    private static final String NOT = "not";

    private RubyHash options;

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
    public void initialize(ThreadContext ctx, IRubyObject options) {
        this.options = (RubyHash) options;

        int db = Utils.toInt(Utils.hashARef(rt(ctx), this.options, "db"), Protocol.DEFAULT_DATABASE);
        pool = OptionsToPool.newPool(rt(ctx), this.options, db);
        pools.put(db, pool);
    }

    public JrRedis(final Ruby runtime, RubyClass rubyClass) {
        super(runtime, rubyClass);
    }

    @JRubyMethod
    public IRubyObject select(ThreadContext ctx, IRubyObject newdb) {
        Ruby ruby = rt(ctx);
        int db = Utils.toInt(newdb);
        int max = maxDB() - 1;
        if (db > max) {
            throw ruby.newArgumentError(
                    String.format("Database number given: %d is higher than Redis configuration of %d", db, max));
        }
        if (!pools.containsKey(db)) {
            pools.put(db,
                    OptionsToPool.newPool(ruby, this.options, db));
        }
        pool = pools.get(db);
        return Utils.stringify(ruby, "OK");
    }

    @JRubyMethod(required = 2)
    public IRubyObject config(ThreadContext ctx, IRubyObject action, IRubyObject arg) {
        Ruby ruby = rt(ctx);
        if (ruby.newSymbol("get").eql(action)) {
            return Utils.arrayStringify(ruby, configGet(Utils.toBytes(arg)));
        }
        return ctx.nil;
    }

    private List<byte[]> configGet(byte[] pattern) {
        try (BinaryJedis jedis = pool.getResource()) {
            return jedis.configGet(pattern);
        }
    }

    @JRubyMethod
    public IRubyObject dbsize(ThreadContext ctx) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx), jedis.dbSize());
        }
    }

    @JRubyMethod
    public IRubyObject info(ThreadContext ctx) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx), jedis.info());
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject info(ThreadContext ctx, IRubyObject section) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx), jedis.info(Utils.toStr(section)));
        }
    }

    @JRubyMethod
    public IRubyObject flushall(ThreadContext ctx) {
        try (BinaryJedis jedis = pool.getResource()) {
            String reply = jedis.flushAll();
            return Utils.stringify(rt(ctx), reply);
        }
    }

    @JRubyMethod
    public IRubyObject flushdb(ThreadContext ctx) {
        try (BinaryJedis jedis = pool.getResource()) {
            String reply = jedis.flushDB();
            return Utils.stringify(rt(ctx), reply);
        }
    }

    @JRubyMethod
    public IRubyObject ping(ThreadContext ctx) {
        try (BinaryJedis jedis = pool.getResource()) {
            String reply = jedis.ping();
            return Utils.stringify(rt(ctx), reply);
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject persist(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.persist(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject expire(ThreadContext ctx, IRubyObject key, IRubyObject seconds) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.expire(Utils.toBytes(key), Utils.toInt(seconds)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject expireat(ThreadContext ctx, IRubyObject key, IRubyObject unixtime) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.expireAt(Utils.toBytes(key), Utils.toLong(unixtime)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject ttl(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.ttl(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject pexpire(ThreadContext ctx, IRubyObject key, IRubyObject milliseconds) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.pexpire(Utils.toBytes(key), Utils.toLong(milliseconds)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject pexpireat(ThreadContext ctx, IRubyObject key, IRubyObject ms_unix_time) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.pexpireAt(Utils.toBytes(key), Utils.toLong(ms_unix_time)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject pttl(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.pttl(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject dump(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.dump(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 3)
    public IRubyObject restore(ThreadContext ctx, IRubyObject key, IRubyObject ttl, IRubyObject serializedValue) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.restore(Utils.toBytes(key), Utils.toInt(ttl), Utils.toBytes(serializedValue)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject migrate(ThreadContext ctx, IRubyObject key, IRubyObject options) {
        Ruby ruby = rt(ctx);

        RubyHash hash = (RubyHash) options;
        if (hash.isNil() || hash.isEmpty()) {
            throw ruby.newArgumentError("options must be supplied");
        }
        byte[] host = Utils.toBytes(Utils.hashARef(ruby, hash, "host"), null);
//        byte[] host = Utils.toBytes(Utils.hashARef(ruby, hash, "host"), "".getBytes());
        if (host == null) {
            throw ruby.newRuntimeError("host not specified");
        }

        int port = Utils.toInt(Utils.hashARef(ruby, hash, "port"), -1);
        if (port == -1) {
            throw ruby.newRuntimeError("port not specified");
        }

        int db = Utils.toInt(Utils.hashARef(ruby, hash, "db"), -1);
        int timeout = Utils.toInt(Utils.hashARef(ruby, hash, "timeout"), -1);

        try (BinaryJedis jedis = pool.getResource()) {
            if (db == -1) {
                db = jedis.getDB();
            }
            if (timeout == -1) {
                timeout = jedis.getClient().getSoTimeout();
            }

            return Utils.stringify(ruby,
                    jedis.migrate(
                            host, port, Utils.toBytes(key), db, timeout
                    ));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject del(ThreadContext ctx, IRubyObject key) {
        IRubyObject[] keys = Helpers.splatToArguments(key);
        return del(ctx, keys);
    }

    @JRubyMethod(rest = true)
    public IRubyObject del(ThreadContext ctx, IRubyObject[] keys) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.del(Utils.toArrayBytes(keys)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject exists(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.exists(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(optional = 1)
    public IRubyObject keys(ThreadContext ctx, IRubyObject[] args) {
        boolean not_given = args.length == 0 || args[0] == null || args[0].isNil();
        byte[] pat = not_given ? DEFAULTPATTERN : Utils.toBytes(args[0]);
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.arrayStringify(rt(ctx),
                    jedis.keys(pat));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject move(ThreadContext ctx, IRubyObject key, IRubyObject db) {
        try (BinaryJedis jedis = pool.getResource()) {
            long result = jedis.move(Utils.toBytes(key), Utils.toInt(db));
            System.out.println(result);
            return Utils.boolify(rt(ctx), result);
        }
    }

    @JRubyMethod(rest = true)
    public IRubyObject object(ThreadContext ctx, IRubyObject[] args) {
        if (args.length != 2) {
            return ctx.nil;
        }
        try (BinaryJedis jedis = pool.getResource()) {
            Ruby ruby = rt(ctx);
            RubySymbol method = (RubySymbol) args[0];

            if (method.eql(ruby.newSymbol("refcount"))) {
                return Utils.numify(rt(ctx),
                        jedis.objectRefcount(Utils.toBytes(args[1]))
                );
            }
            if (method.eql(ruby.newSymbol("encoding"))) {
                return Utils.stringify(rt(ctx),
                        jedis.objectEncoding(Utils.toBytes(args[1]))
                );
            }
            if (method.eql(ruby.newSymbol("idletime"))) {
                return Utils.numify(rt(ctx),
                        jedis.objectIdletime(Utils.toBytes(args[1]))
                );
            }
            return ctx.nil;
        }
    }

    @JRubyMethod
    public IRubyObject randomkey(ThreadContext ctx) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.randomBinaryKey());
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject rename(ThreadContext ctx, IRubyObject oldn, IRubyObject newn) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.rename(Utils.toBytes(oldn), Utils.toBytes(newn)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject renamenx(ThreadContext ctx, IRubyObject oldn, IRubyObject newn) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.renamenx(Utils.toBytes(oldn), Utils.toBytes(newn)));
        }
    }

    @JRubyMethod(name = "sort", required = 1)
    public IRubyObject op_sort(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            List<byte[]> results = jedis.sort(Utils.toBytes(key));
            return Utils.arrayStringify(rt(ctx), results);
        }
    }

    @JRubyMethod(name = "sort", required = 2)
    public IRubyObject op_sort_o(ThreadContext ctx, IRubyObject key, IRubyObject options) {
        Ruby ruby = rt(ctx);
        SortingParams sortParams = OptionsToSortingParameters.build(ruby, options);

        byte[] store = null;
        if (options instanceof RubyHash) {
            store = Utils.toBytes(Utils.hashARef(rt(ctx), (RubyHash) options, "store"));
        }
        boolean complexSort = sortParams.hasParams();
        boolean stash = store != null;

        try (BinaryJedis jedis = pool.getResource()) {
            if (complexSort && stash) {
                long result = jedis.sort(Utils.toBytes(key), sortParams, store);
                return Utils.numify(ruby, result);
            }
            if (complexSort && !stash) {
                List<byte[]> results = jedis.sort(Utils.toBytes(key), sortParams);
                return Utils.arrayStringify(ruby, results);
            }
            if (!complexSort && stash) {
                long result = jedis.sort(Utils.toBytes(key), store);
                return Utils.numify(ruby, result);
            }
            // must be !complexSort && !stash
            List<byte[]> results = jedis.sort(Utils.toBytes(key));
            return Utils.arrayStringify(ruby, results);
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject type(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.type(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject decr(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.decr(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject decrby(ThreadContext ctx, IRubyObject key, IRubyObject decrement) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.decrBy(Utils.toBytes(key), Utils.toLong(decrement)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject incr(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.incr(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject incrby(ThreadContext ctx, IRubyObject key, IRubyObject increment) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.incrBy(Utils.toBytes(key), Utils.toLong(increment)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject incrbyfloat(ThreadContext ctx, IRubyObject key, IRubyObject increment) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.incrByFloat(Utils.toBytes(key), Utils.toDouble(increment)));
        }
    }

    @JRubyMethod(name = {"[]=", "set"}, required = 2)
    public IRubyObject op_set(ThreadContext ctx, IRubyObject key, IRubyObject value) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.set(Utils.toBytes(key), Utils.toBytes(value)));
        }
    }

    @JRubyMethod(name = {"[]=", "set"}, required = 3)
    public IRubyObject op_set_o(ThreadContext ctx, IRubyObject key, IRubyObject value, IRubyObject options) {
        RubyHash hash = (RubyHash) options;
        if (hash.isNil() || hash.isEmpty()) {
            return op_set(ctx, key, value);
        }

        Ruby ruby = ctx.runtime;
        byte[] expx = null;
        byte[] nxxx = null;

        int time = Utils.toInt(Utils.hashARef(ruby, hash, "px"), -1);

        if (time != -1) {
            expx = "PX".getBytes();
        } else {
            time = Utils.toInt(Utils.hashARef(ruby, hash, "ex"), -1);
        }
        if (time != -1) {
            expx = "EX".getBytes();
        }
        nxxx = hash.containsKey(ruby.newSymbol("nx")) ? "NX".getBytes()
                : hash.containsKey(ruby.newSymbol("xx")) ? "XX".getBytes() : null;

        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.set(Utils.toBytes(key), Utils.toBytes(value), nxxx, expx, time));
        }
    }

    @JRubyMethod(required = 3)
    public IRubyObject setex(ThreadContext ctx, IRubyObject key, IRubyObject ttl, IRubyObject value) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.setex(Utils.toBytes(key), Utils.toInt(ttl), Utils.toBytes(value)));
        }
    }

    @JRubyMethod(required = 3)
    public IRubyObject psetex(ThreadContext ctx, IRubyObject key, IRubyObject ttl, IRubyObject value) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.psetex(Utils.toBytes(key), Utils.toLong(ttl), Utils.toBytes(value)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject setnx(ThreadContext ctx, IRubyObject key, IRubyObject value) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.setnx(Utils.toBytes(key), Utils.toBytes(value)));
        }
    }

    @JRubyMethod(rest = true)
    public IRubyObject mset(ThreadContext ctx, IRubyObject[] args) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.mset(Utils.toFlatArrayBytes(ctx, args)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject mapped_mset(ThreadContext ctx, IRubyObject hash) {
        if (!(hash instanceof RubyHash)) {
            return ctx.nil;
        }
        return mset(ctx, Utils.hashToArrayIRubyObject(ctx, (RubyHash) hash));
    }

    @JRubyMethod(rest = true)
    public IRubyObject msetnx(ThreadContext ctx, IRubyObject[] args) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.msetnx(Utils.toFlatArrayBytes(ctx, args)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject mapped_msetnx(ThreadContext ctx, IRubyObject hash) {
        if (!(hash instanceof RubyHash)) {
            return ctx.nil;
        }
        return msetnx(ctx, Utils.hashToArrayIRubyObject(ctx, (RubyHash) hash));
    }

    @JRubyMethod(name = {"[]", "get"}, required = 1)
    public IRubyObject op_get(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.get(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(rest = true)
    public IRubyObject mget(ThreadContext ctx, IRubyObject[] args, Block block) {
        try (BinaryJedis jedis = pool.getResource()) {
            RubyArray results = (RubyArray) Utils.arrayStringify(rt(ctx),
                    jedis.mget(Utils.toFlatArrayBytes(ctx, args)));

            if (block.isGiven()) {
                return block.yield(ctx, results);
            } else {
                return results;
            }
        }
    }

    @JRubyMethod(rest = true)
    public IRubyObject mapped_mget(ThreadContext ctx, IRubyObject[] args, Block block) {
        Ruby ruby = rt(ctx);
        RubyArray results = (RubyArray) mget(ctx, args, block);
        RubyHash out = RubyHash.newHash(ruby);
        for (int i = 0; i < args.length; i++) {
            IRubyObject key = args[i];
            IRubyObject val = results.entry(i);
            out.op_aset(ctx, key, val);
        }
        return out;
    }

    @JRubyMethod(required = 3)
    public IRubyObject setrange(ThreadContext ctx, IRubyObject key, IRubyObject offset, IRubyObject value) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.setrange(Utils.toBytes(key), Utils.toLong(offset), Utils.toBytes(value)));
        }
    }

    @JRubyMethod(required = 3)
    public IRubyObject getrange(ThreadContext ctx, IRubyObject key, IRubyObject start, IRubyObject stop) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.getrange(Utils.toBytes(key), Utils.toLong(start), Utils.toLong(stop)));
        }
    }

    @JRubyMethod(required = 3)
    public IRubyObject setbit(ThreadContext ctx, IRubyObject key, IRubyObject offset, IRubyObject value) {
        Ruby ruby = rt(ctx);
        try (BinaryJedis jedis = pool.getResource()) {
            int bitval = Utils.toInt(value);
            jedis.getClient().setbit(Utils.toBytes(key), Utils.toLong(offset),
                    (bitval == 0 ? Protocol.BYTES_FALSE : Protocol.BYTES_TRUE));
            return Utils.numify(ruby, jedis.getClient().getIntegerReply());
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject getbit(ThreadContext ctx, IRubyObject key, IRubyObject offset) {
        Ruby ruby = rt(ctx);
        try (BinaryJedis jedis = pool.getResource()) {
            jedis.getClient().getbit(Utils.toBytes(key), Utils.toLong(offset));
            return Utils.numify(ruby, jedis.getClient().getIntegerReply());
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject append(ThreadContext ctx, IRubyObject key, IRubyObject value) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.append(Utils.toBytes(key), Utils.toBytes(value)));
        }
    }

    @JRubyMethod(rest = true)
    public IRubyObject bitcount(ThreadContext ctx, IRubyObject[] args) {
        try (BinaryJedis jedis = pool.getResource()) {
            int key = 0;
            int start = 1;
            int stop = 2;

            long b = 0;
            long e = -1;
            byte[] k = Utils.toBytes(args[key]);

            IRubyObject istart = argAt(ctx, start, args);
            IRubyObject istop = argAt(ctx, stop, args);

            if (istart.isNil() && istop.isNil()) {
                return Utils.numify(rt(ctx), jedis.bitcount(k));
            }
            if (!istart.isNil()) {
                b = Utils.toLong(istart);
            }
            if (!istop.isNil()) {
                e = Utils.toLong(istop);
            }

            return Utils.numify(rt(ctx),
                    jedis.bitcount(k, b, e));
        }
    }

    @JRubyMethod(required = 2, rest = true)
    public IRubyObject bitop(ThreadContext ctx, IRubyObject[] args) {
        Ruby ruby = rt(ctx);
        IRubyObject operation = args[0];
        IRubyObject destkey = args[1];

        RubyArray restkeys = Helpers.createSubarray(args, ruby, 2);

        byte[][] keys = Utils.toFlatArrayBytes(ctx, restkeys);

        String op = null;
        if (operation instanceof RubySymbol) {
            op = ((RubySymbol) operation).toString();
        } else if (operation instanceof RubyString) {
            op = ((RubyString) operation).toString();
        } else {
            throw ruby.newRuntimeError("Operation must be Symbol or String");
        }
        BitOP bop = BitOP.AND;
        switch (op) {
            case OR:
                bop = BitOP.OR;
                break;
            case XOR:
                bop = BitOP.XOR;
                break;
            case NOT:
                bop = BitOP.NOT;
                break;
        }
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(ruby,
                    jedis.bitop(bop, Utils.toBytes(destkey), keys));
        }
    }

    @JRubyMethod(required = 2, rest = true)
    public IRubyObject bitpos(ThreadContext ctx, IRubyObject[] args) {
        int key = 0;
        int bit = 1;
        int start = 2;
        int stop = 3;

        long b = -1;
        long e = -1;

        BitPosParams p;

        byte[] k = Utils.toBytes(args[key]);
        boolean f = Utils.toBool(args[bit]);

        IRubyObject istart = argAt(ctx, start, args);
        IRubyObject istop = argAt(ctx, stop, args);

        if (istart.isNil() && istop.isNil()) {
            p = new BitPosParams();
        } else {
            if (!istop.isNil()) {
                e = Utils.toLong(istop);
            }
            if (!istart.isNil()) {
                b = Utils.toLong(istart);
            }
            if (e > -1) {
                if (b > -1) {
                    p = new BitPosParams(b, e);
                } else {
                    throw rt(ctx).newRuntimeError("stop parameter specified without start parameter");
                }
            } else {
                p = new BitPosParams(b);
            }
        }
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx), jedis.bitpos(k, f, p));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject getset(ThreadContext ctx, IRubyObject key, IRubyObject value) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.getSet(Utils.toBytes(key), Utils.toBytes(value)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject strlen(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.strlen(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject llen(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.llen(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject lpush(ThreadContext ctx, IRubyObject key, IRubyObject value) {
        byte[][] args = new byte[1][];

        if (value instanceof RubyArray) {
            RubyArray a = (RubyArray) value;
            args = Utils.toArrayBytes(a);
        } else {
            args[0] = Utils.toBytes(value);
        }

        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.lpush(Utils.toBytes(key), args));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject lpushx(ThreadContext ctx, IRubyObject key, IRubyObject value) {

        byte[][] args = {Utils.toBytes(value)};

        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.lpushx(Utils.toBytes(key), args));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject rpush(ThreadContext ctx, IRubyObject key, IRubyObject value) {
        byte[][] args = new byte[1][];

        if (value instanceof RubyArray) {
            RubyArray a = (RubyArray) value;
            args = Utils.toArrayBytes(a);
        } else {
            args[0] = Utils.toBytes(value);
        }

        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.rpush(Utils.toBytes(key), args));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject rpushx(ThreadContext ctx, IRubyObject key, IRubyObject value) {

        byte[][] args = {Utils.toBytes(value)};

        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.rpushx(Utils.toBytes(key), args));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject lpop(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.lpop(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject rpop(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.rpop(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject rpoplpush(ThreadContext ctx, IRubyObject srckey, IRubyObject dstkey) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx),
                    jedis.rpoplpush(Utils.toBytes(srckey), Utils.toBytes(dstkey)));
        }
    }

    @JRubyMethod(rest = true)
    public IRubyObject blpop(ThreadContext ctx, IRubyObject[] args) {
        return b_pop(ctx, args, Protocol.Command.BLPOP);
    }

    @JRubyMethod(rest = true)
    public IRubyObject brpop(ThreadContext ctx, IRubyObject[] args) {
        return b_pop(ctx, args, Protocol.Command.BRPOP);
    }

    private IRubyObject b_pop(ThreadContext ctx, IRubyObject[] args, Protocol.Command cmd) {
        Ruby ruby = rt(ctx);
        int last = args.length;
        int timeout = -1;
        RubyArray parts = null;
        if (args[last] instanceof RubyNumeric) {
            timeout = Utils.toInt(args[last]);
            parts = Helpers.createSubarray(args, ruby, 0, 1);
        } else if (args[last] instanceof RubyHash) {
            timeout = Utils.toInt(Utils.hashARef(ruby, (RubyHash) args[last], "timeout"));
            parts = Helpers.createSubarray(args, ruby, 0, 1);
        }
        if (parts == null) {
            parts = RubyArray.newArray(ruby, args);
        }

        byte[][] keys = Utils.toFlatArrayBytes(ctx, parts);

        List<byte[]> results = null;
        try (BinaryJedis jedis = pool.getResource()) {
            if (timeout == -1) {
                if (cmd == Protocol.Command.BLPOP) {
                    results = jedis.blpop(keys);
                }
                if (cmd == Protocol.Command.BRPOP) {
                    results = jedis.brpop(keys);
                }
            } else {
                if (cmd == Protocol.Command.BLPOP) {
                    results = jedis.blpop(timeout, keys);
                }
                if (cmd == Protocol.Command.BRPOP) {
                    results = jedis.brpop(timeout, keys);
                }
            }
            return Utils.arrayStringifyNil(ruby, results);
        }
    }

    @JRubyMethod(required = 2, rest = true)
    public IRubyObject brpoplpush(ThreadContext ctx, IRubyObject[] args) {
        int src = 0;
        int dst = 1;
        int timeout = -1;
        // check ruby to jedis timeout float seconds vs int milliseconds
        if (args[2] != null && args[2] instanceof RubyHash) {
            timeout = Utils.toInt(Utils.hashARef(rt(ctx), (RubyHash) args[2], "timeout"));
        }
        if (timeout == -1) {
            timeout = 0;
        }
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx), jedis.brpoplpush(
                    Utils.toBytes(args[src]),
                    Utils.toBytes(args[dst]),
                    timeout));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject lindex(ThreadContext ctx, IRubyObject key, IRubyObject index) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx), jedis.lindex(Utils.toBytes(key), Utils.toLong(index)));
        }
    }

    @JRubyMethod(rest = true)
    public IRubyObject linsert(ThreadContext ctx, IRubyObject[] args) {
        int key = 0;
        int place = 1;
        int pivot = 2;
        int value = 3;
        BinaryClient.LIST_POSITION placement;
        if (args[place].toString().equalsIgnoreCase("before")) {
            placement = BinaryClient.LIST_POSITION.BEFORE;
        } else {
            placement = BinaryClient.LIST_POSITION.AFTER;
        }
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx), jedis.linsert(
                    Utils.toBytes(args[key]), placement,
                    Utils.toBytes(args[pivot]), Utils.toBytes(args[value])));
        }
    }

    @JRubyMethod(required = 3)
    public IRubyObject lrange(ThreadContext ctx, IRubyObject key, IRubyObject start, IRubyObject stop) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.arrayStringify(rt(ctx), jedis.lrange(Utils.toBytes(key),
                    Utils.toLong(start), Utils.toLong(stop)));
        }
    }

    @JRubyMethod(required = 3)
    public IRubyObject lrem(ThreadContext ctx, IRubyObject key, IRubyObject count, IRubyObject value) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx), jedis.lrem(Utils.toBytes(key),
                    Utils.toLong(count), Utils.toBytes(value)));
        }
    }

    @JRubyMethod(required = 3)
    public IRubyObject lset(ThreadContext ctx, IRubyObject key, IRubyObject index, IRubyObject value) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx), jedis.lset(Utils.toBytes(key),
                    Utils.toLong(index), Utils.toBytes(value)));
        }
    }

    @JRubyMethod(required = 3)
    public IRubyObject ltrim(ThreadContext ctx, IRubyObject key, IRubyObject start, IRubyObject stop) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx), jedis.ltrim(Utils.toBytes(key),
                    Utils.toLong(start), Utils.toLong(stop)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject scard(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx), jedis.scard(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 2, rest = true)
    public IRubyObject sadd(ThreadContext ctx, IRubyObject[] args) {
        Ruby ruby = rt(ctx);

        RubyArray ary = RubyArray.newArray(ruby, args);
        byte[]   key = Utils.toBytes(ary.shift(ctx));
        byte[][] members =members = Utils.toFlatArrayBytes(ctx, ary);
        boolean return_boolean = members.length < 2;

        try (BinaryJedis jedis = pool.getResource()) {
            long result = jedis.sadd(key, members);
            return return_boolean ? Utils.boolify(ruby, result) : Utils.numify(ruby, result);
        }
    }

    @JRubyMethod(required = 2, rest = true)
    public IRubyObject srem(ThreadContext ctx, IRubyObject[] args) {
        Ruby ruby = rt(ctx);

        RubyArray ary = RubyArray.newArray(ruby, args);
        byte[]   key = Utils.toBytes(ary.shift(ctx));
        byte[][] members =members = Utils.toFlatArrayBytes(ctx, ary);
        boolean return_boolean = members.length < 2;

        try (BinaryJedis jedis = pool.getResource()) {
            long result = jedis.srem(key, members);
            return return_boolean ? Utils.boolify(ruby, result) : Utils.numify(ruby, result);
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject spop(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx), jedis.spop(Utils.toBytes(key)));
        }
    }
  //   ?? spop(key, count) ??

    @JRubyMethod(required = 1)
    public IRubyObject srandmember(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.stringify(rt(ctx), jedis.srandmember(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject srandmember(ThreadContext ctx, IRubyObject key, IRubyObject count) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.arrayStringifyNil(rt(ctx), jedis.srandmember(Utils.toBytes(key), Utils.toInt(count)));
        }
    }

    @JRubyMethod(required = 3)
    public IRubyObject smove(ThreadContext ctx, IRubyObject key, IRubyObject dest, IRubyObject member) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx), jedis.smove(Utils.toBytes(key), Utils.toBytes(dest), Utils.toBytes(member)));
        }
    }

    @JRubyMethod(required = 2)
    public IRubyObject sismember(ThreadContext ctx, IRubyObject key, IRubyObject member) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx), jedis.sismember(Utils.toBytes(key), Utils.toBytes(member)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject smembers(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.arrayStringify(rt(ctx), jedis.smembers(Utils.toBytes(key)));
        }
    }

    @JRubyMethod(rest = true)
    public IRubyObject sdiff(ThreadContext ctx, IRubyObject[] keys) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.arrayStringify(rt(ctx), jedis.sdiff(Utils.toFlatArrayBytes(ctx, keys)));
        }
    }

    @JRubyMethod(required = 2, rest = true)
    public IRubyObject sdiffstore(ThreadContext ctx, IRubyObject[] args) {
        Ruby ruby = rt(ctx);

        RubyArray ary = RubyArray.newArray(ruby, args);
        byte[]   dest = Utils.toBytes(ary.shift(ctx));
        byte[][] keys = Utils.toFlatArrayBytes(ctx, ary);

        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(ruby, jedis.sdiffstore(dest, keys));
        }
    }

    @JRubyMethod(rest = true)
    public IRubyObject sinter(ThreadContext ctx, IRubyObject[] keys) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.arrayStringify(rt(ctx), jedis.sinter(Utils.toFlatArrayBytes(ctx, keys)));
        }
    }

    @JRubyMethod(required = 2, rest = true)
    public IRubyObject sinterstore(ThreadContext ctx, IRubyObject[] args) {
        Ruby ruby = rt(ctx);

        RubyArray ary = RubyArray.newArray(ruby, args);
        byte[] dest = Utils.toBytes(ary.shift(ctx));
        byte[][] keys = Utils.toFlatArrayBytes(ctx, ary);

        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(ruby, jedis.sinterstore(dest, keys));
        }
    }

    @JRubyMethod(rest = true)
    public IRubyObject sunion(ThreadContext ctx, IRubyObject[] keys) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.arrayStringify(rt(ctx), jedis.sunion(Utils.toFlatArrayBytes(ctx, keys)));
        }
    }

    @JRubyMethod(required = 2, rest = true)
    public IRubyObject sunionstore(ThreadContext ctx, IRubyObject[] args) {
        Ruby ruby = rt(ctx);

        RubyArray ary = RubyArray.newArray(ruby, args);
        byte[] dest = Utils.toBytes(ary.shift(ctx));
        byte[][] keys = Utils.toFlatArrayBytes(ctx, ary);

        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(ruby, jedis.sunionstore(dest, keys));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject zcard(ThreadContext ctx, IRubyObject key) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx), jedis.zcard(Utils.toBytes(key)));
        }
    }

  // # Add one or more members to a sorted set, or update the score for members
  // # that already exist.
  // #
  // # @example Add a single `[score, member]` pair to a sorted set
  // #   redis.zadd("zset", 32.0, "member")
  // # @example Add an array of `[score, member]` pairs to a sorted set
  // #   redis.zadd("zset", [[32.0, "a"], [64.0, "b"]])
  // #
  // # @param [String] key
  // # @param [[Float, String], Array<[Float, String]>] args
  // #   - a single `[score, member]` pair
  // #   - an array of `[score, member]` pairs
  // #
  // # @return [Boolean, Fixnum]
  // #   - `Boolean` when a single pair is specified, holding whether or not it was
  // #   **added** to the sorted set
  // #   - `Fixnum` when an array of pairs is specified, holding the number of
  // #   pairs that were **added** to the sorted set
  // def zadd(key, *args)
  //   synchronize do |client|
  //     if args.size == 1 && args[0].is_a?(Array)
  //       # Variadic: return integer
  //       client.call([:zadd, key] + args[0])
  //     elsif args.size == 2
  //       # Single pair: return boolean
  //       client.call([:zadd, key, args[0], args[1]], &_boolify)
  //     else
  //       raise ArgumentError, "wrong number of arguments"
  //     end
  //   end
  // end

  // # Increment the score of a member in a sorted set.
  // #
  // # @example
  // #   redis.zincrby("zset", 32.0, "a")
  // #     # => 64.0
  // #
  // # @param [String] key
  // # @param [Float] increment
  // # @param [String] member
  // # @return [Float] score of the member after incrementing it
  // def zincrby(key, increment, member)
  //   synchronize do |client|
  //     client.call([:zincrby, key, increment, member], &_floatify)
  //   end
  // end

  // # Remove one or more members from a sorted set.
  // #
  // # @example Remove a single member from a sorted set
  // #   redis.zrem("zset", "a")
  // # @example Remove an array of members from a sorted set
  // #   redis.zrem("zset", ["a", "b"])
  // #
  // # @param [String] key
  // # @param [String, Array<String>] member
  // #   - a single member
  // #   - an array of members
  // #
  // # @return [Boolean, Fixnum]
  // #   - `Boolean` when a single member is specified, holding whether or not it
  // #   was removed from the sorted set
  // #   - `Fixnum` when an array of pairs is specified, holding the number of
  // #   members that were removed to the sorted set
  // def zrem(key, member)
  //   synchronize do |client|
  //     client.call([:zrem, key, member]) do |reply|
  //       if member.is_a? Array
  //         # Variadic: return integer
  //         reply
  //       else
  //         # Single argument: return boolean
  //         _boolify.call(reply)
  //       end
  //     end
  //   end
  // end

  // # Get the score associated with the given member in a sorted set.
  // #
  // # @example Get the score for member "a"
  // #   redis.zscore("zset", "a")
  // #     # => 32.0
  // #
  // # @param [String] key
  // # @param [String] member
  // # @return [Float] score of the member
  // def zscore(key, member)
  //   synchronize do |client|
  //     client.call([:zscore, key, member], &_floatify)
  //   end
  // end

  // # Return a range of members in a sorted set, by index.
  // #
  // # @example Retrieve all members from a sorted set
  // #   redis.zrange("zset", 0, -1)
  // #     # => ["a", "b"]
  // # @example Retrieve all members and their scores from a sorted set
  // #   redis.zrange("zset", 0, -1, :with_scores => true)
  // #     # => [["a", 32.0], ["b", 64.0]]
  // #
  // # @param [String] key
  // # @param [Fixnum] start start index
  // # @param [Fixnum] stop stop index
  // # @param [Hash] options
  // #   - `:with_scores => true`: include scores in output
  // #
  // # @return [Array<String>, Array<[String, Float]>]
  // #   - when `:with_scores` is not specified, an array of members
  // #   - when `:with_scores` is specified, an array with `[member, score]` pairs
  // def zrange(key, start, stop, options = {})
  //   args = []

  //   with_scores = options[:with_scores] || options[:withscores]

  //   if with_scores
  //     args << "WITHSCORES"
  //     block = _floatify_pairs
  //   end

  //   synchronize do |client|
  //     client.call([:zrange, key, start, stop] + args, &block)
  //   end
  // end

  // # Return a range of members in a sorted set, by index, with scores ordered
  // # from high to low.
  // #
  // # @example Retrieve all members from a sorted set
  // #   redis.zrevrange("zset", 0, -1)
  // #     # => ["b", "a"]
  // # @example Retrieve all members and their scores from a sorted set
  // #   redis.zrevrange("zset", 0, -1, :with_scores => true)
  // #     # => [["b", 64.0], ["a", 32.0]]
  // #
  // # @see #zrange
  // def zrevrange(key, start, stop, options = {})
  //   args = []

  //   with_scores = options[:with_scores] || options[:withscores]

  //   if with_scores
  //     args << "WITHSCORES"
  //     block = _floatify_pairs
  //   end

  //   synchronize do |client|
  //     client.call([:zrevrange, key, start, stop] + args, &block)
  //   end
  // end

  // # Determine the index of a member in a sorted set.
  // #
  // # @param [String] key
  // # @param [String] member
  // # @return [Fixnum]
  // def zrank(key, member)
  //   synchronize do |client|
  //     client.call([:zrank, key, member])
  //   end
  // end

  // # Determine the index of a member in a sorted set, with scores ordered from
  // # high to low.
  // #
  // # @param [String] key
  // # @param [String] member
  // # @return [Fixnum]
  // def zrevrank(key, member)
  //   synchronize do |client|
  //     client.call([:zrevrank, key, member])
  //   end
  // end

  // # Remove all members in a sorted set within the given indexes.
  // #
  // # @example Remove first 5 members
  // #   redis.zremrangebyrank("zset", 0, 4)
  // #     # => 5
  // # @example Remove last 5 members
  // #   redis.zremrangebyrank("zset", -5, -1)
  // #     # => 5
  // #
  // # @param [String] key
  // # @param [Fixnum] start start index
  // # @param [Fixnum] stop stop index
  // # @return [Fixnum] number of members that were removed
  // def zremrangebyrank(key, start, stop)
  //   synchronize do |client|
  //     client.call([:zremrangebyrank, key, start, stop])
  //   end
  // end

  // # Return a range of members with the same score in a sorted set, by lexicographical ordering
  // #
  // # @example Retrieve members matching a
  // #   redis.zrangebylex("zset", "[a", "[a\xff")
  // #     # => ["aaren", "aarika", "abagael", "abby"]
  // # @example Retrieve the first 2 members matching a
  // #   redis.zrangebylex("zset", "[a", "[a\xff", :limit => [0, 2])
  // #     # => ["aaren", "aarika"]
  // #
  // # @param [String] key
  // # @param [String] min
  // #   - inclusive minimum is specified by prefixing `(`
  // #   - exclusive minimum is specified by prefixing `[`
  // # @param [String] max
  // #   - inclusive maximum is specified by prefixing `(`
  // #   - exclusive maximum is specified by prefixing `[`
  // # @param [Hash] options
  // #   - `:limit => [offset, count]`: skip `offset` members, return a maximum of
  // #   `count` members
  // #
  // # @return [Array<String>, Array<[String, Float]>]
  // def zrangebylex(key, min, max, options = {})
  //   args = []

  //   limit = options[:limit]
  //   args.concat(["LIMIT"] + limit) if limit

  //   synchronize do |client|
  //     client.call([:zrangebylex, key, min, max] + args)
  //   end
  // end

  // # Return a range of members with the same score in a sorted set, by reversed lexicographical ordering.
  // # Apart from the reversed ordering, #zrevrangebylex is similar to #zrangebylex.
  // #
  // # @example Retrieve members matching a
  // #   redis.zrevrangebylex("zset", "[a", "[a\xff")
  // #     # => ["abbygail", "abby", "abagael", "aaren"]
  // # @example Retrieve the last 2 members matching a
  // #   redis.zrevrangebylex("zset", "[a", "[a\xff", :limit => [0, 2])
  // #     # => ["abbygail", "abby"]
  // #
  // # @see #zrangebylex
  // def zrevrangebylex(key, max, min, options = {})
  //   args = []

  //   limit = options[:limit]
  //   args.concat(["LIMIT"] + limit) if limit

  //   synchronize do |client|
  //     client.call([:zrevrangebylex, key, max, min] + args)
  //   end
  // end

  // # Return a range of members in a sorted set, by score.
  // #
  // # @example Retrieve members with score `>= 5` and `< 100`
  // #   redis.zrangebyscore("zset", "5", "(100")
  // #     # => ["a", "b"]
  // # @example Retrieve the first 2 members with score `>= 0`
  // #   redis.zrangebyscore("zset", "0", "+inf", :limit => [0, 2])
  // #     # => ["a", "b"]
  // # @example Retrieve members and their scores with scores `> 5`
  // #   redis.zrangebyscore("zset", "(5", "+inf", :with_scores => true)
  // #     # => [["a", 32.0], ["b", 64.0]]
  // #
  // # @param [String] key
  // # @param [String] min
  // #   - inclusive minimum score is specified verbatim
  // #   - exclusive minimum score is specified by prefixing `(`
  // # @param [String] max
  // #   - inclusive maximum score is specified verbatim
  // #   - exclusive maximum score is specified by prefixing `(`
  // # @param [Hash] options
  // #   - `:with_scores => true`: include scores in output
  // #   - `:limit => [offset, count]`: skip `offset` members, return a maximum of
  // #   `count` members
  // #
  // # @return [Array<String>, Array<[String, Float]>]
  // #   - when `:with_scores` is not specified, an array of members
  // #   - when `:with_scores` is specified, an array with `[member, score]` pairs
  // def zrangebyscore(key, min, max, options = {})
  //   args = []

  //   with_scores = options[:with_scores] || options[:withscores]

  //   if with_scores
  //     args << "WITHSCORES"
  //     block = _floatify_pairs
  //   end

  //   limit = options[:limit]
  //   args.concat(["LIMIT"] + limit) if limit

  //   synchronize do |client|
  //     client.call([:zrangebyscore, key, min, max] + args, &block)
  //   end
  // end

  // # Return a range of members in a sorted set, by score, with scores ordered
  // # from high to low.
  // #
  // # @example Retrieve members with score `< 100` and `>= 5`
  // #   redis.zrevrangebyscore("zset", "(100", "5")
  // #     # => ["b", "a"]
  // # @example Retrieve the first 2 members with score `<= 0`
  // #   redis.zrevrangebyscore("zset", "0", "-inf", :limit => [0, 2])
  // #     # => ["b", "a"]
  // # @example Retrieve members and their scores with scores `> 5`
  // #   redis.zrevrangebyscore("zset", "+inf", "(5", :with_scores => true)
  // #     # => [["b", 64.0], ["a", 32.0]]
  // #
  // # @see #zrangebyscore
  // def zrevrangebyscore(key, max, min, options = {})
  //   args = []

  //   with_scores = options[:with_scores] || options[:withscores]

  //   if with_scores
  //     args << ["WITHSCORES"]
  //     block = _floatify_pairs
  //   end

  //   limit = options[:limit]
  //   args.concat(["LIMIT"] + limit) if limit

  //   synchronize do |client|
  //     client.call([:zrevrangebyscore, key, max, min] + args, &block)
  //   end
  // end

  // # Remove all members in a sorted set within the given scores.
  // #
  // # @example Remove members with score `>= 5` and `< 100`
  // #   redis.zremrangebyscore("zset", "5", "(100")
  // #     # => 2
  // # @example Remove members with scores `> 5`
  // #   redis.zremrangebyscore("zset", "(5", "+inf")
  // #     # => 2
  // #
  // # @param [String] key
  // # @param [String] min
  // #   - inclusive minimum score is specified verbatim
  // #   - exclusive minimum score is specified by prefixing `(`
  // # @param [String] max
  // #   - inclusive maximum score is specified verbatim
  // #   - exclusive maximum score is specified by prefixing `(`
  // # @return [Fixnum] number of members that were removed
  // def zremrangebyscore(key, min, max)
  //   synchronize do |client|
  //     client.call([:zremrangebyscore, key, min, max])
  //   end
  // end

  // # Count the members in a sorted set with scores within the given values.
  // #
  // # @example Count members with score `>= 5` and `< 100`
  // #   redis.zcount("zset", "5", "(100")
  // #     # => 2
  // # @example Count members with scores `> 5`
  // #   redis.zcount("zset", "(5", "+inf")
  // #     # => 2
  // #
  // # @param [String] key
  // # @param [String] min
  // #   - inclusive minimum score is specified verbatim
  // #   - exclusive minimum score is specified by prefixing `(`
  // # @param [String] max
  // #   - inclusive maximum score is specified verbatim
  // #   - exclusive maximum score is specified by prefixing `(`
  // # @return [Fixnum] number of members in within the specified range
  // def zcount(key, min, max)
  //   synchronize do |client|
  //     client.call([:zcount, key, min, max])
  //   end
  // end

  // # Intersect multiple sorted sets and store the resulting sorted set in a new
  // # key.
  // #
  // # @example Compute the intersection of `2*zsetA` with `1*zsetB`, summing their scores
  // #   redis.zinterstore("zsetC", ["zsetA", "zsetB"], :weights => [2.0, 1.0], :aggregate => "sum")
  // #     # => 4
  // #
  // # @param [String] destination destination key
  // # @param [Array<String>] keys source keys
  // # @param [Hash] options
  // #   - `:weights => [Float, Float, ...]`: weights to associate with source
  // #   sorted sets
  // #   - `:aggregate => String`: aggregate function to use (sum, min, max, ...)
  // # @return [Fixnum] number of elements in the resulting sorted set
  // def zinterstore(destination, keys, options = {})
  //   args = []

  //   weights = options[:weights]
  //   args.concat(["WEIGHTS"] + weights) if weights

  //   aggregate = options[:aggregate]
  //   args.concat(["AGGREGATE", aggregate]) if aggregate

  //   synchronize do |client|
  //     client.call([:zinterstore, destination, keys.size] + keys + args)
  //   end
  // end

  // # Add multiple sorted sets and store the resulting sorted set in a new key.
  // #
  // # @example Compute the union of `2*zsetA` with `1*zsetB`, summing their scores
  // #   redis.zunionstore("zsetC", ["zsetA", "zsetB"], :weights => [2.0, 1.0], :aggregate => "sum")
  // #     # => 8
  // #
  // # @param [String] destination destination key
  // # @param [Array<String>] keys source keys
  // # @param [Hash] options
  // #   - `:weights => [Float, Float, ...]`: weights to associate with source
  // #   sorted sets
  // #   - `:aggregate => String`: aggregate function to use (sum, min, max, ...)
  // # @return [Fixnum] number of elements in the resulting sorted set
  // def zunionstore(destination, keys, options = {})
  //   args = []

  //   weights = options[:weights]
  //   args.concat(["WEIGHTS"] + weights) if weights

  //   aggregate = options[:aggregate]
  //   args.concat(["AGGREGATE", aggregate]) if aggregate

  //   synchronize do |client|
  //     client.call([:zunionstore, destination, keys.size] + keys + args)
  //   end
  // end

  // # Get the number of fields in a hash.
  // #
  // # @param [String] key
  // # @return [Fixnum] number of fields in the hash
  // def hlen(key)
  //   synchronize do |client|
  //     client.call([:hlen, key])
  //   end
  // end

  // # Set the string value of a hash field.
  // #
  // # @param [String] key
  // # @param [String] field
  // # @param [String] value
  // # @return [Boolean] whether or not the field was **added** to the hash
  // def hset(key, field, value)
  //   synchronize do |client|
  //     client.call([:hset, key, field, value], &_boolify)
  //   end
  // end

  // # Set the value of a hash field, only if the field does not exist.
  // #
  // # @param [String] key
  // # @param [String] field
  // # @param [String] value
  // # @return [Boolean] whether or not the field was **added** to the hash
  // def hsetnx(key, field, value)
  //   synchronize do |client|
  //     client.call([:hsetnx, key, field, value], &_boolify)
  //   end
  // end

  // # Set one or more hash values.
  // #
  // # @example
  // #   redis.hmset("hash", "f1", "v1", "f2", "v2")
  // #     # => "OK"
  // #
  // # @param [String] key
  // # @param [Array<String>] attrs array of fields and values
  // # @return `"OK"`
  // #
  // # @see #mapped_hmset
  // def hmset(key, *attrs)
  //   synchronize do |client|
  //     client.call([:hmset, key] + attrs)
  //   end
  // end

  // # Set one or more hash values.
  // #
  // # @example
  // #   redis.mapped_hmset("hash", { "f1" => "v1", "f2" => "v2" })
  // #     # => "OK"
  // #
  // # @param [String] key
  // # @param [Hash] a non-empty hash with fields mapping to values
  // # @return `"OK"`
  // #
  // # @see #hmset
  // def mapped_hmset(key, hash)
  //   hmset(key, hash.to_a.flatten)
  // end

  // # Get the value of a hash field.
  // #
  // # @param [String] key
  // # @param [String] field
  // # @return [String]
  // def hget(key, field)
  //   synchronize do |client|
  //     client.call([:hget, key, field])
  //   end
  // end

  // # Get the values of all the given hash fields.
  // #
  // # @example
  // #   redis.hmget("hash", "f1", "f2")
  // #     # => ["v1", "v2"]
  // #
  // # @param [String] key
  // # @param [Array<String>] fields array of fields
  // # @return [Array<String>] an array of values for the specified fields
  // #
  // # @see #mapped_hmget
  // def hmget(key, *fields, &blk)
  //   synchronize do |client|
  //     client.call([:hmget, key] + fields, &blk)
  //   end
  // end

  // # Get the values of all the given hash fields.
  // #
  // # @example
  // #   redis.mapped_hmget("hash", "f1", "f2")
  // #     # => { "f1" => "v1", "f2" => "v2" }
  // #
  // # @param [String] key
  // # @param [Array<String>] fields array of fields
  // # @return [Hash] a hash mapping the specified fields to their values
  // #
  // # @see #hmget
  // def mapped_hmget(key, *fields)
  //   hmget(key, *fields) do |reply|
  //     if reply.kind_of?(Array)
  //       Hash[fields.zip(reply)]
  //     else
  //       reply
  //     end
  //   end
  // end

  // # Delete one or more hash fields.
  // #
  // # @param [String] key
  // # @param [String, Array<String>] field
  // # @return [Fixnum] the number of fields that were removed from the hash
  // def hdel(key, field)
  //   synchronize do |client|
  //     client.call([:hdel, key, field])
  //   end
  // end

  // # Determine if a hash field exists.
  // #
  // # @param [String] key
  // # @param [String] field
  // # @return [Boolean] whether or not the field exists in the hash
  // def hexists(key, field)
  //   synchronize do |client|
  //     client.call([:hexists, key, field], &_boolify)
  //   end
  // end

  // # Increment the integer value of a hash field by the given integer number.
  // #
  // # @param [String] key
  // # @param [String] field
  // # @param [Fixnum] increment
  // # @return [Fixnum] value of the field after incrementing it
  // def hincrby(key, field, increment)
  //   synchronize do |client|
  //     client.call([:hincrby, key, field, increment])
  //   end
  // end

  // # Increment the numeric value of a hash field by the given float number.
  // #
  // # @param [String] key
  // # @param [String] field
  // # @param [Float] increment
  // # @return [Float] value of the field after incrementing it
  // def hincrbyfloat(key, field, increment)
  //   synchronize do |client|
  //     client.call([:hincrbyfloat, key, field, increment], &_floatify)
  //   end
  // end

  // # Get all the fields in a hash.
  // #
  // # @param [String] key
  // # @return [Array<String>]
  // def hkeys(key)
  //   synchronize do |client|
  //     client.call([:hkeys, key])
  //   end
  // end

  // # Get all the values in a hash.
  // #
  // # @param [String] key
  // # @return [Array<String>]
  // def hvals(key)
  //   synchronize do |client|
  //     client.call([:hvals, key])
  //   end
  // end

  // # Get all the fields and values in a hash.
  // #
  // # @param [String] key
  // # @return [Hash<String, String>]
  // def hgetall(key)
  //   synchronize do |client|
  //     client.call([:hgetall, key], &_hashify)
  //   end
  // end

  // # Post a message to a channel.
  // def publish(channel, message)
  //   synchronize do |client|
  //     client.call([:publish, channel, message])
  //   end
  // end

  // def subscribed?
  //   synchronize do |client|
  //     client.kind_of? SubscribedClient
  //   end
  // end

  // # Listen for messages published to the given channels.
  // def subscribe(*channels, &block)
  //   synchronize do |client|
  //     _subscription(:subscribe, channels, block)
  //   end
  // end

  // # Stop listening for messages posted to the given channels.
  // def unsubscribe(*channels)
  //   synchronize do |client|
  //     raise RuntimeError, "Can't unsubscribe if not subscribed." unless subscribed?
  //     client.unsubscribe(*channels)
  //   end
  // end

  // # Listen for messages published to channels matching the given patterns.
  // def psubscribe(*channels, &block)
  //   synchronize do |client|
  //     _subscription(:psubscribe, channels, block)
  //   end
  // end

  // # Stop listening for messages posted to channels matching the given patterns.
  // def punsubscribe(*channels)
  //   synchronize do |client|
  //     raise RuntimeError, "Can't unsubscribe if not subscribed." unless subscribed?
  //     client.punsubscribe(*channels)
  //   end
  // end

  // # Inspect the state of the Pub/Sub subsystem.
  // # Possible subcommands: channels, numsub, numpat.
  // def pubsub(subcommand, *args)
  //   synchronize do |client|
  //     client.call([:pubsub, subcommand] + args)
  //   end
  // end

  // # Watch the given keys to determine execution of the MULTI/EXEC block.
  // #
  // # Using a block is optional, but is necessary for thread-safety.
  // #
  // # An `#unwatch` is automatically issued if an exception is raised within the
  // # block that is a subclass of StandardError and is not a ConnectionError.
  // #
  // # @example With a block
  // #   redis.watch("key") do
  // #     if redis.get("key") == "some value"
  // #       redis.multi do |multi|
  // #         multi.set("key", "other value")
  // #         multi.incr("counter")
  // #       end
  // #     else
  // #       redis.unwatch
  // #     end
  // #   end
  // #     # => ["OK", 6]
  // #
  // # @example Without a block
  // #   redis.watch("key")
  // #     # => "OK"
  // #
  // # @param [String, Array<String>] keys one or more keys to watch
  // # @return [Object] if using a block, returns the return value of the block
  // # @return [String] if not using a block, returns `OK`
  // #
  // # @see #unwatch
  // # @see #multi
  // def watch(*keys)
  //   synchronize do |client|
  //     res = client.call([:watch] + keys)

  //     if block_given?
  //       begin
  //         yield(self)
  //       rescue ConnectionError
  //         raise
  //       rescue StandardError
  //         unwatch
  //         raise
  //       end
  //     else
  //       res
  //     end
  //   end
  // end

  // # Forget about all watched keys.
  // #
  // # @return [String] `OK`
  // #
  // # @see #watch
  // # @see #multi
  // def unwatch
  //   synchronize do |client|
  //     client.call([:unwatch])
  //   end
  // end

  // def pipelined
  //   synchronize do |client|
  //     begin
  //       original, @client = @client, Pipeline.new
  //       yield(self)
  //       original.call_pipeline(@client)
  //     ensure
  //       @client = original
  //     end
  //   end
  // end

  // # Mark the start of a transaction block.
  // #
  // # Passing a block is optional.
  // #
  // # @example With a block
  // #   redis.multi do |multi|
  // #     multi.set("key", "value")
  // #     multi.incr("counter")
  // #   end # => ["OK", 6]
  // #
  // # @example Without a block
  // #   redis.multi
  // #     # => "OK"
  // #   redis.set("key", "value")
  // #     # => "QUEUED"
  // #   redis.incr("counter")
  // #     # => "QUEUED"
  // #   redis.exec
  // #     # => ["OK", 6]
  // #
  // # @yield [multi] the commands that are called inside this block are cached
  // #   and written to the server upon returning from it
  // # @yieldparam [Redis] multi `self`
  // #
  // # @return [String, Array<...>]
  // #   - when a block is not given, `OK`
  // #   - when a block is given, an array with replies
  // #
  // # @see #watch
  // # @see #unwatch
  // def multi
  //   synchronize do |client|
  //     if !block_given?
  //       client.call([:multi])
  //     else
  //       begin
  //         pipeline = Pipeline::Multi.new
  //         original, @client = @client, pipeline
  //         yield(self)
  //         original.call_pipeline(pipeline)
  //       ensure
  //         @client = original
  //       end
  //     end
  //   end
  // end

  // # Execute all commands issued after MULTI.
  // #
  // # Only call this method when `#multi` was called **without** a block.
  // #
  // # @return [nil, Array<...>]
  // #   - when commands were not executed, `nil`
  // #   - when commands were executed, an array with their replies
  // #
  // # @see #multi
  // # @see #discard
  // def exec
  //   synchronize do |client|
  //     client.call([:exec])
  //   end
  // end

  // # Discard all commands issued after MULTI.
  // #
  // # Only call this method when `#multi` was called **without** a block.
  // #
  // # @return `"OK"`
  // #
  // # @see #multi
  // # @see #exec
  // def discard
  //   synchronize do |client|
  //     client.call([:discard])
  //   end
  // end

  // # Control remote script registry.
  // #
  // # @example Load a script
  // #   sha = redis.script(:load, "return 1")
  // #     # => <sha of this script>
  // # @example Check if a script exists
  // #   redis.script(:exists, sha)
  // #     # => true
  // # @example Check if multiple scripts exist
  // #   redis.script(:exists, [sha, other_sha])
  // #     # => [true, false]
  // # @example Flush the script registry
  // #   redis.script(:flush)
  // #     # => "OK"
  // # @example Kill a running script
  // #   redis.script(:kill)
  // #     # => "OK"
  // #
  // # @param [String] subcommand e.g. `exists`, `flush`, `load`, `kill`
  // # @param [Array<String>] args depends on subcommand
  // # @return [String, Boolean, Array<Boolean>, ...] depends on subcommand
  // #
  // # @see #eval
  // # @see #evalsha
  // def script(subcommand, *args)
  //   subcommand = subcommand.to_s.downcase

  //   if subcommand == "exists"
  //     synchronize do |client|
  //       arg = args.first

  //       client.call([:script, :exists, arg]) do |reply|
  //         reply = reply.map { |r| _boolify.call(r) }

  //         if arg.is_a?(Array)
  //           reply
  //         else
  //           reply.first
  //         end
  //       end
  //     end
  //   else
  //     synchronize do |client|
  //       client.call([:script, subcommand] + args)
  //     end
  //   end
  // end

  // def _eval(cmd, args)
  //   script = args.shift
  //   options = args.pop if args.last.is_a?(Hash)
  //   options ||= {}

  //   keys = args.shift || options[:keys] || []
  //   argv = args.shift || options[:argv] || []

  //   synchronize do |client|
  //     client.call([cmd, script, keys.length] + keys + argv)
  //   end
  // end

  // # Evaluate Lua script.
  // #
  // # @example EVAL without KEYS nor ARGV
  // #   redis.eval("return 1")
  // #     # => 1
  // # @example EVAL with KEYS and ARGV as array arguments
  // #   redis.eval("return { KEYS, ARGV }", ["k1", "k2"], ["a1", "a2"])
  // #     # => [["k1", "k2"], ["a1", "a2"]]
  // # @example EVAL with KEYS and ARGV in a hash argument
  // #   redis.eval("return { KEYS, ARGV }", :keys => ["k1", "k2"], :argv => ["a1", "a2"])
  // #     # => [["k1", "k2"], ["a1", "a2"]]
  // #
  // # @param [Array<String>] keys optional array with keys to pass to the script
  // # @param [Array<String>] argv optional array with arguments to pass to the script
  // # @param [Hash] options
  // #   - `:keys => Array<String>`: optional array with keys to pass to the script
  // #   - `:argv => Array<String>`: optional array with arguments to pass to the script
  // # @return depends on the script
  // #
  // # @see #script
  // # @see #evalsha
  // def eval(*args)
  //   _eval(:eval, args)
  // end

  // # Evaluate Lua script by its SHA.
  // #
  // # @example EVALSHA without KEYS nor ARGV
  // #   redis.evalsha(sha)
  // #     # => <depends on script>
  // # @example EVALSHA with KEYS and ARGV as array arguments
  // #   redis.evalsha(sha, ["k1", "k2"], ["a1", "a2"])
  // #     # => <depends on script>
  // # @example EVALSHA with KEYS and ARGV in a hash argument
  // #   redis.evalsha(sha, :keys => ["k1", "k2"], :argv => ["a1", "a2"])
  // #     # => <depends on script>
  // #
  // # @param [Array<String>] keys optional array with keys to pass to the script
  // # @param [Array<String>] argv optional array with arguments to pass to the script
  // # @param [Hash] options
  // #   - `:keys => Array<String>`: optional array with keys to pass to the script
  // #   - `:argv => Array<String>`: optional array with arguments to pass to the script
  // # @return depends on the script
  // #
  // # @see #script
  // # @see #eval
  // def evalsha(*args)
  //   _eval(:evalsha, args)
  // end

  // def _scan(command, cursor, args, options = {}, &block)
  //   # SSCAN/ZSCAN/HSCAN already prepend the key to +args+.

  //   args << cursor

  //   if match = options[:match]
  //     args.concat(["MATCH", match])
  //   end

  //   if count = options[:count]
  //     args.concat(["COUNT", count])
  //   end

  //   synchronize do |client|
  //     client.call([command] + args, &block)
  //   end
  // end

  // # Scan the keyspace
  // #
  // # @example Retrieve the first batch of keys
  // #   redis.scan(0)
  // #     # => ["4", ["key:21", "key:47", "key:42"]]
  // # @example Retrieve a batch of keys matching a pattern
  // #   redis.scan(4, :match => "key:1?")
  // #     # => ["92", ["key:13", "key:18"]]
  // #
  // # @param [String, Integer] cursor: the cursor of the iteration
  // # @param [Hash] options
  // #   - `:match => String`: only return keys matching the pattern
  // #   - `:count => Integer`: return count keys at most per iteration
  // #
  // # @return [String, Array<String>] the next cursor and all found keys
  // def scan(cursor, options={})
  //   _scan(:scan, cursor, [], options)
  // end

  // # Scan the keyspace
  // #
  // # @example Retrieve all of the keys (with possible duplicates)
  // #   redis.scan_each.to_a
  // #     # => ["key:21", "key:47", "key:42"]
  // # @example Execute block for each key matching a pattern
  // #   redis.scan_each(:match => "key:1?") {|key| puts key}
  // #     # => key:13
  // #     # => key:18
  // #
  // # @param [Hash] options
  // #   - `:match => String`: only return keys matching the pattern
  // #   - `:count => Integer`: return count keys at most per iteration
  // #
  // # @return [Enumerator] an enumerator for all found keys
  // def scan_each(options={}, &block)
  //   return to_enum(:scan_each, options) unless block_given?
  //   cursor = 0
  //   loop do
  //     cursor, keys = scan(cursor, options)
  //     keys.each(&block)
  //     break if cursor == "0"
  //   end
  // end

  // # Scan a hash
  // #
  // # @example Retrieve the first batch of key/value pairs in a hash
  // #   redis.hscan("hash", 0)
  // #
  // # @param [String, Integer] cursor: the cursor of the iteration
  // # @param [Hash] options
  // #   - `:match => String`: only return keys matching the pattern
  // #   - `:count => Integer`: return count keys at most per iteration
  // #
  // # @return [String, Array<[String, String]>] the next cursor and all found keys
  // def hscan(key, cursor, options={})
  //   _scan(:hscan, cursor, [key], options) do |reply|
  //     [reply[0], _pairify(reply[1])]
  //   end
  // end

  // # Scan a hash
  // #
  // # @example Retrieve all of the key/value pairs in a hash
  // #   redis.hscan_each("hash").to_a
  // #   # => [["key70", "70"], ["key80", "80"]]
  // #
  // # @param [Hash] options
  // #   - `:match => String`: only return keys matching the pattern
  // #   - `:count => Integer`: return count keys at most per iteration
  // #
  // # @return [Enumerator] an enumerator for all found keys
  // def hscan_each(key, options={}, &block)
  //   return to_enum(:hscan_each, key, options) unless block_given?
  //   cursor = 0
  //   loop do
  //     cursor, values = hscan(key, cursor, options)
  //     values.each(&block)
  //     break if cursor == "0"
  //   end
  // end

  // # Scan a sorted set
  // #
  // # @example Retrieve the first batch of key/value pairs in a hash
  // #   redis.zscan("zset", 0)
  // #
  // # @param [String, Integer] cursor: the cursor of the iteration
  // # @param [Hash] options
  // #   - `:match => String`: only return keys matching the pattern
  // #   - `:count => Integer`: return count keys at most per iteration
  // #
  // # @return [String, Array<[String, Float]>] the next cursor and all found
  // #   members and scores
  // def zscan(key, cursor, options={})
  //   _scan(:zscan, cursor, [key], options) do |reply|
  //     [reply[0], _floatify_pairs.call(reply[1])]
  //   end
  // end

  // # Scan a sorted set
  // #
  // # @example Retrieve all of the members/scores in a sorted set
  // #   redis.zscan_each("zset").to_a
  // #   # => [["key70", "70"], ["key80", "80"]]
  // #
  // # @param [Hash] options
  // #   - `:match => String`: only return keys matching the pattern
  // #   - `:count => Integer`: return count keys at most per iteration
  // #
  // # @return [Enumerator] an enumerator for all found scores and members
  // def zscan_each(key, options={}, &block)
  //   return to_enum(:zscan_each, key, options) unless block_given?
  //   cursor = 0
  //   loop do
  //     cursor, values = zscan(key, cursor, options)
  //     values.each(&block)
  //     break if cursor == "0"
  //   end
  // end

  // # Scan a set
  // #
  // # @example Retrieve the first batch of keys in a set
  // #   redis.sscan("set", 0)
  // #
  // # @param [String, Integer] cursor: the cursor of the iteration
  // # @param [Hash] options
  // #   - `:match => String`: only return keys matching the pattern
  // #   - `:count => Integer`: return count keys at most per iteration
  // #
  // # @return [String, Array<String>] the next cursor and all found members
  // def sscan(key, cursor, options={})
  //   _scan(:sscan, cursor, [key], options)
  // end

  // # Scan a set
  // #
  // # @example Retrieve all of the keys in a set
  // #   redis.sscan_each("set").to_a
  // #   # => ["key1", "key2", "key3"]
  // #
  // # @param [Hash] options
  // #   - `:match => String`: only return keys matching the pattern
  // #   - `:count => Integer`: return count keys at most per iteration
  // #
  // # @return [Enumerator] an enumerator for all keys in the set
  // def sscan_each(key, options={}, &block)
  //   return to_enum(:sscan_each, key, options) unless block_given?
  //   cursor = 0
  //   loop do
  //     cursor, keys = sscan(key, cursor, options)
  //     keys.each(&block)
  //     break if cursor == "0"
  //   end
  // end

  // # Add one or more members to a HyperLogLog structure.
  // #
  // # @param [String] key
  // # @param [String, Array<String>] member one member, or array of members
  // # @return [Boolean] true if at least 1 HyperLogLog internal register was altered. false otherwise.
  // def pfadd(key, member)
  //   synchronize do |client|
  //     client.call([:pfadd, key, member], &_boolify)
  //   end
  // end

  // # Get the approximate cardinality of members added to HyperLogLog structure.
  // #
  // # If called with multiple keys, returns the approximate cardinality of the
  // # union of the HyperLogLogs contained in the keys.
  // #
  // # @param [String, Array<String>] keys
  // # @return [Fixnum]
  // def pfcount(*keys)
  //   synchronize do |client|
  //     client.call([:pfcount] + keys)
  //   end
  // end

  // # Merge multiple HyperLogLog values into an unique value that will approximate the cardinality of the union of
  // # the observed Sets of the source HyperLogLog structures.
  // #
  // # @param [String] dest_key destination key
  // # @param [String, Array<String>] source_key source key, or array of keys
  // # @return [Boolean]
  // def pfmerge(dest_key, *source_key)
  //   synchronize do |client|
  //     client.call([:pfmerge, dest_key, *source_key], &_boolify_set)
  //   end
  // end










    // ----------------------------
    private Ruby rt(ThreadContext ctx) {
        return ctx.runtime;
    }

    private IRubyObject argAt(ThreadContext ctx, int pos, IRubyObject[] args) {
        if (args.length > pos) {
            return args[pos];
        }
        return ctx.nil;
    }

    private int maxDB() {
        return Integer.valueOf(SafeEncoder.encode(configGet("databases".getBytes()).get(1)));
    }

}
