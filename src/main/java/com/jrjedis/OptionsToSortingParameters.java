/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jrjedis;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyHash;
import org.jruby.RubyString;
import org.jruby.runtime.builtin.IRubyObject;
import redis.clients.jedis.SortingParams;

/**
 *
 * @author guy
 */
public class OptionsToSortingParameters {
    public static SortingParams build(Ruby ruby, IRubyObject options) {
        SortingParams sp = new SortingParams();
        if (options == null || !(options instanceof RubyHash)) {
            return sp;
        }

        RubyHash hash = (RubyHash)options;
        if (hash.isEmpty()) {
            return sp;
        }

        String by = Utils.toStr(Utils.hashARef(ruby, hash, "by"));
        if (by != null) {
            sp.by(by);
        }

        int[] limit = Utils.toArrayInt(Utils.hashARef(ruby, hash, "limit"));
        if (limit.length > 1) {
            sp.limit(limit[0], limit[1]);
        }
        String ord = Utils.toStr(Utils.hashARef(ruby, hash, "order")).toLowerCase();
        if (ord.contains("alpha")) {
            sp.alpha();
        }
        if (ord.contains("desc")) {
            sp.desc();
        }
        if (ord.contains("asc")) {
            sp.asc();
        }
        if (ord.contains("nosort")) {
            sp.nosort();
        }

        IRubyObject gets = Utils.hashARef(ruby, hash, "get");
        if (gets instanceof RubyString) {
            sp.get(new String[] {Utils.toStr(gets)});
        } else if(gets instanceof RubyArray) {
            sp.get(Utils.toArrayString(gets));
        }
        return sp;
    }
}
/*
    args = []

    by = options[:by]
    args.concat(["BY", by]) if by

    limit = options[:limit]
    args.concat(["LIMIT"] + limit) if limit

    get = Array(options[:get])
    args.concat(["GET"].product(get).flatten) unless get.empty?

    order = options[:order]
    args.concat(order.split(" ")) if order

    store = options[:store]
    args.concat(["STORE", store]) if store


e.g.
r.sort("bar", :get => "foo:*", :limit => [0, 1], :order => "desc alpha")
r.sort("bar", :get => ["foo:*:a", "foo:*:b"], :limit => [0, 1], :order => "desc alpha")
r.sort("bar", :get => ["foo:*:a", "foo:*:b"], :store => 'baz')
*/
