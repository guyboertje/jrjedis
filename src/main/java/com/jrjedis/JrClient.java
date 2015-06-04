/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jrjedis;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;

/**
 *
 * @author guy
 */
@JRubyClass(name = "JrJedis::Client", parent = "Object")
public class JrClient extends RubyObject {

    private IRubyObject db;
    private IRubyObject timeout;

    public static final ObjectAllocator JRCLIENT_ALLOCATOR = new ObjectAllocator() {
        @Override
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new JrClient(runtime, klass);
        }
    };

    public JrClient(final Ruby runtime, RubyClass rubyClass) {
        super(runtime, rubyClass);
    }

    public JrClient(Ruby ruby, int db, int timeout) {
        super(ruby, ruby.getModule("JrJedis").getClass("Client"));
        this.db = Utils.numify(ruby, db);
        this.timeout = Utils.floatify(ruby, (double)timeout / 1000.0);
    }

    @JRubyMethod(name = {"db"})
    public IRubyObject getDb() {
        return db;
    }

    @JRubyMethod(name = {"timeout"})
    public IRubyObject getTimeout() {
        return timeout;
    }
}
