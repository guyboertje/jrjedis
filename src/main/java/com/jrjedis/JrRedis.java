package com.jrjedis;

import java.util.HashMap;
import java.util.List;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import redis.clients.jedis.BinaryJedis;
import redis.clients.jedis.BitOP;
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
        this.options = (RubyHash)options;

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
        if(!pools.containsKey(db)) {
            pools.put(db,
                OptionsToPool.newPool(ruby, this.options, db));
        }
        pool = pools.get(db);
        return Utils.stringify(ruby, "OK");
    }

    @JRubyMethod(required = 2)
    public IRubyObject config(ThreadContext ctx, IRubyObject action, IRubyObject arg) {
        Ruby ruby = rt(ctx);
        if ( ruby.newSymbol("get").eql(action)) {
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

        RubyHash hash = (RubyHash)options;
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
            if(db == -1) {
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
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.numify(rt(ctx),
                    jedis.del(Utils.toBytes(key)));
        }
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
            store = Utils.toBytes(Utils.hashARef(rt(ctx), (RubyHash)options, "store"));
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
        RubyHash hash = (RubyHash)options;
        if (hash.isNil() || hash.isEmpty()) {
            return op_set(ctx, key, value);
        }

        Ruby ruby = ctx.runtime;
        byte[] expx = null;
        byte[] nxxx = null;

        int time = Utils.toInt(Utils.hashARef(ruby, hash, "px"), -1);

        if (time != -1) {
            expx = "PX".getBytes();
        }
        else {
            time = Utils.toInt(Utils.hashARef(ruby, hash, "ex"), -1);
        }
        if (time != -1) {
            expx = "EX".getBytes();
        }
        nxxx = hash.containsKey(ruby.newSymbol("nx")) ? "NX".getBytes() :
                    hash.containsKey(ruby.newSymbol("xx")) ? "XX".getBytes() : null;

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
                    jedis.mset(Utils.toArrayBytes(args)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject mapped_mset(ThreadContext ctx, IRubyObject hash) {
        if (!(hash instanceof RubyHash)) {
            return ctx.nil;
        }
        return mset(ctx, Utils.hashToArrayIRubyObject(ctx, (RubyHash)hash));
    }

    @JRubyMethod(rest = true)
    public IRubyObject msetnx(ThreadContext ctx, IRubyObject[] args) {
        try (BinaryJedis jedis = pool.getResource()) {
            return Utils.boolify(rt(ctx),
                    jedis.msetnx(Utils.toArrayBytes(args)));
        }
    }

    @JRubyMethod(required = 1)
    public IRubyObject mapped_msetnx(ThreadContext ctx, IRubyObject hash) {
        if (!(hash instanceof RubyHash)) {
            return ctx.nil;
        }
        return msetnx(ctx, Utils.hashToArrayIRubyObject(ctx, (RubyHash)hash));
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
            RubyArray results = (RubyArray)Utils.arrayStringify(rt(ctx),
                    jedis.mget(Utils.toArrayBytes(args)));

            if (block.isGiven()){
                return block.yield(ctx, results);
            } else {
                return results;
            }
        }
    }

    @JRubyMethod(rest = true)
    public IRubyObject mapped_mget(ThreadContext ctx, IRubyObject[] args, Block block) {
        Ruby ruby = rt(ctx);
        RubyArray results = (RubyArray)mget(ctx, args, block);
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

    @JRubyMethod(required = 1, optional = 2)
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

       IRubyObject[] restargs = Utils.restArgs(2, args);

       String op = null;
       if (operation instanceof RubySymbol) {
           op = ((RubySymbol)operation).toString();
       } else if (operation instanceof RubyString){
           op = ((RubyString)operation).toString();
       } else {
           throw ruby.newArgumentError("Operation must be Symbol or String");
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
                   jedis.bitop(bop, Utils.toBytes(destkey), Utils.toArrayBytes(restargs)));
       }
   }



    // ----------------------------

    private Ruby rt(ThreadContext ctx) {
        return ctx.runtime;
    }

    private IRubyObject argAt(ThreadContext ctx, int pos, IRubyObject[] args) {
        if (args.length > pos) return args[pos];
        return ctx.nil;
    }

    private int maxDB() {
        return Integer.valueOf(SafeEncoder.encode(configGet("databases".getBytes()).get(1)));
    }

}
