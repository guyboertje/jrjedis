package com.jrjedis;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyHash;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 *
 * @author guy
 */
public class Utils {

    static final byte[] NILWORD = new byte[] {'n', 'i', 'l'};

    // towards ruby -------------------------------------------

    public static IRubyObject boolify(Ruby ruby, String str) {
        if ("OK".equalsIgnoreCase(str)) {
            return ruby.getTrue();
        }
        return ruby.getFalse();
    }

    public static IRubyObject boolify(Ruby ruby, Long val) {
        if (1 == val) {
            return ruby.getTrue();
        }
        return ruby.getFalse();
    }

    public static IRubyObject boolify(Ruby ruby, Boolean val) {
        if (val) {
            return ruby.getTrue();
        }
        return ruby.getFalse();
    }

    public static IRubyObject arrayStringify(Ruby ruby, Set<byte[]> values) {
        if (values == null) {
            return ruby.getNil();
        }
        RubyArray ret = ruby.newArray(values.size());
        for (byte[] val : values) {
            ret.append(stringify(ruby, val));
        }
        return ret;
    }

    public static IRubyObject arrayStringify(Ruby ruby, List<byte[]> values) {
        if (values == null) {
            return ruby.getNil();
        }
        RubyArray ret = ruby.newArray(values.size());
        for (byte[] val : values) {
            ret.append(stringify(ruby, val));
        }
        return ret;
    }

    public static IRubyObject arrayStringifyNil(Ruby ruby, List<byte[]> values) {
        if (values == null) {
            return ruby.getNil();
        }
        RubyArray ret = ruby.newArray(values.size());
        for (byte[] val : values) {
            ret.append(nilStringify(ruby, val));
        }
        return ret;
    }

    public static IRubyObject stringify(Ruby ruby, String str) {
        if (str == null) {
            return ruby.getNil();
        }
        return ruby.newString(str);
    }

    public static IRubyObject stringify(Ruby ruby, byte[] str) {
        if (str == null) {
            return ruby.getNil();
        }
        return RubyString.newString(ruby, str);
    }
    public static IRubyObject nilStringify(Ruby ruby, byte[] str) {
        if (str == null || Arrays.equals(NILWORD, str)){
            return ruby.getNil();
        }
        return  RubyString.newString(ruby, str);
    }

    public static IRubyObject numify(Ruby ruby, boolean val) {
        return val ? ruby.newFixnum(1) : ruby.newFixnum(0);
    }

    public static IRubyObject numify(Ruby ruby, long val) {
        return RubyNumeric.int2fix(ruby, val);
    }

    public static IRubyObject numify(Ruby ruby, Long val) {
        return RubyNumeric.int2fix(ruby, val);
    }

    public static IRubyObject numify(Ruby ruby, double val) {
        return RubyNumeric.dbl2num(ruby, val);
    }




    // towards java -------------------------------------------

    public static IRubyObject[] hashToArrayIRubyObject(ThreadContext ctx, RubyHash hash) {
        RubyArray ary = (RubyArray) ((RubyHash) hash).to_a().flatten_bang(ctx);
        return ary.toJavaArray();
    }

    public static byte[][] hashToArrayBytes(ThreadContext ctx, RubyHash hash) {
        RubyArray ary = (RubyArray) ((RubyHash) hash).to_a().flatten_bang(ctx);
        return toArrayBytes(ary.toJavaArray());
    }
    public static byte[][] toArrayBytes(IRubyObject arg) {
        // caller should flatten first
        if (arg.isNil()) {
            return new byte[0][0];
        }
        if (arg instanceof RubyArray) {
            return toArrayBytes((RubyArray)arg);
        }
        return new byte[][]{toBytes(arg)};
    }

    public static byte[][] toFlatArrayBytes(ThreadContext ctx, IRubyObject[] args) {
        return toFlatArrayBytes(ctx, RubyArray.newArray(ctx.runtime, args));
    }

    public static byte[][] toFlatArrayBytes(ThreadContext ctx, RubyArray arg) {
        return toArrayBytes((RubyArray)arg.flatten(ctx));
    }

    public static byte[][] toArrayBytes(RubyArray arg) {

        if (arg.isEmpty()) {
            return new byte[0][0];
        }

        byte[][] result = new byte[arg.size()][];

        for (int i = 0; i < result.length; ++i) {
            result[i] = toBytes(arg.entry(i));
        }
        return result;
    }

    public static void toArrayBytes(IRubyObject[] args, ArrayList<byte[]> varargs) {
        if (args.length == 0) {
            return;
        }
        for (IRubyObject elm : args) {
            if (elm instanceof RubyArray) {
                toArrayBytes(((RubyArray)elm).toJavaArray(), varargs);
            } else if (elm == null || elm.isNil()) {
                // do nothing
            } else {
                varargs.add(toBytes(elm));
            }
        }
    }

    public static byte[][] toArrayBytes(IRubyObject[] args) {

        if (args.length == 0) {
            return new byte[0][0];
        }

        byte[][] result = new byte[args.length][];

        for (int i = 0; i < result.length; ++i) {
            result[i] = toBytes(args[i]);
        }
        return result;
    }

    public static int[] toArrayInt(IRubyObject val) {
        if (val.isNil()) {
            return new int[0];
        }
        RubyArray ary = val.convertToArray();
//        int[] result = (int[])ary.toJava(int[].class);

        int[] result = new int[ary.size()];
        for (int i = 0; i < result.length; ++i) {
            result[i] = RubyNumeric.num2int(ary.entry(i));
        }
        return result;
    }

    public static String[] toArrayString(IRubyObject val) {
        if (val.isNil()) {
            return new String[0];
        }
        RubyArray ary = val.convertToArray();
//        int[] result = (int[])ary.toJava(int[].class);

        String[] result = new String[ary.size()];
        for (int i = 0; i < result.length; ++i) {
            result[i] = ary.entry(i).toString();
        }
        return result;
    }

    public static String toStr(IRubyObject val, String alt) {
        if (val.isNil()) {
            return alt;
        }
        return val.toString();
    }

    public static String toStr(IRubyObject val) {
        if (val.isNil()) {
            return null;
        }
        return val.toString();
    }

    public static byte[] toBytes(IRubyObject val) {
        if (val instanceof RubyString) {
            return ((RubyString)val).getBytes();
        } else {
            RubyString str = (RubyString)((RubyObject)val).to_s();
            return str.getBytes();
        }
    }

    public static byte[] toBytes(IRubyObject val, byte[] alt) {
        if (val.isNil()) {
            return alt;
        }

        if (val instanceof RubyString) {
            RubyString str = (RubyString)val;
            return str.getBytes();
        }
        return val.toString().getBytes();
    }

    public static int toInt(IRubyObject val, int alt) {
        if (val.isNil()) {
            return alt;
        }
        int v = RubyNumeric.num2int(val);
        return v == 0 ? alt : v;
    }

    public static int toInt(IRubyObject val) {
        return RubyNumeric.num2int(val);
    }

    public static double toDouble(IRubyObject val) {
        return RubyNumeric.num2dbl(val);
    }

    public static double toDouble(IRubyObject val, double alt) {
        if (val.isNil()) {
            return alt;
        }
        return RubyNumeric.num2dbl(val);
    }

    public static long toLong(IRubyObject val) {
        return RubyNumeric.num2long(val);
    }

    public static boolean toBool(IRubyObject val) {
        int v = RubyNumeric.num2int(val);
        return (v == 1);
    }

    public static IRubyObject hashARef(Ruby ruby, RubyHash hash, String symbol) {
        IRubyObject value = hash.fastARef(ruby.newSymbol(symbol));
        return value == null ? ruby.getNil() : value;
    }
}
