unless RUBY_PLATFORM =~ /java/
  puts "This library is only compatible with a java-based ruby environment like JRuby."
  exit 255
end

require_relative "jars/jrjedis-1.0.2.jar"
# require_relative "linked/jrjedis-1.0.2.jar"

require 'com/jrjedis/jrjedis'

require "jrjedis/version"
