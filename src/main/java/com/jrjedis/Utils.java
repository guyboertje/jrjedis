package com.jrjedis;

import org.jruby.Ruby;
import org.jruby.RubyHash;
import org.jruby.RubyNumeric;
import org.jruby.runtime.builtin.IRubyObject;

/**
 *
 * @author guy
 */
public class Utils {

    public static IRubyObject boolify(Ruby ruby, String str) {
        if ("OK".equalsIgnoreCase(str)) {
            return ruby.getTrue();
        }
        return ruby.getFalse();
    }

    public static IRubyObject stringify(Ruby ruby, String str) {
        return ruby.newString(str);
    }

    public static String toStr(IRubyObject val, String alt) {
        if (val.isNil()) {
            return alt;
        }
        return val.toString();
    }

    public static int toInt(IRubyObject val, int alt) {
        if (val.isNil()) {
            return alt;
        }
        int v = RubyNumeric.num2int(val);
        return v == 0 ? alt : v;
    }

    public static IRubyObject hashARef(Ruby ruby, RubyHash hash, String symbol) {
        IRubyObject value = hash.fastARef(ruby.newSymbol(symbol));
        return value == null ? ruby.getNil() : value;
    }
}
