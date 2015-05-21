package com.jrjedis;

import java.io.IOException;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.runtime.load.BasicLibraryService;

/**
 *
 * @author guy
 */
public class JrjedisService implements BasicLibraryService {

    @Override
    public boolean basicLoad(final Ruby runtime) throws IOException {

        RubyModule root = runtime.defineModule("JrJedis");
        RubyClass runtimeError = runtime.getRuntimeError();

        root.defineClassUnder("CredentialError", runtimeError, runtimeError.getAllocator());

        root.defineClassUnder("ReadError", runtimeError, runtimeError.getAllocator());

        root.defineClassUnder("WriteError", runtimeError, runtimeError.getAllocator());

        RubyClass jrRedis = root.defineClassUnder("Redis", runtime.getObject(), JrRedis.JRREDIS_ALLOCATOR);
        jrRedis.defineAnnotatedMethods(JrRedis.class);

        return true;
    }
}
