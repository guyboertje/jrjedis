# jrjedis
JRuby wrapper aroung the Jedis Java driver for Redis

Using BinaryJedis and JedisBinaryPool

initial benchmarks:
```ruby
require 'benchmark/ips'
require 'redis'

jedis = JrJedis::Redis.new({})
redis = Redis.new

def run(one, two)
  one.set("foo-2", "bar")
  two.set("foo-1", "bar")
  Benchmark.ips do |x|
    x.config(:time => 3, :warmup => 3)
    x.report(one.class.name) { one.set("foo-1", "one"); one.get("foo-2") }
    x.report(two.class.name) { two.set("foo-2", "two"); two.get("foo-1") }
  end
  nil
end

run(redis, jedis)

```
```
run(redis, redis)
Calculating -------------------------------------
               Redis   745.000  i/100ms
               Redis   752.000  i/100ms
-------------------------------------------------
               Redis      7.205k (± 6.7%) i/s -     21.605k   min: 
               Redis      7.115k (± 9.4%) i/s -     21.808k

min: 6.722k  max: 7.688k   i/s @±6.7%

run(jedis, jedis)
Calculating -------------------------------------
      JrJedis::Redis   824.000  i/100ms
      JrJedis::Redis   818.000  i/100ms
-------------------------------------------------
      JrJedis::Redis      8.551k (± 4.5%) i/s -     26.368k
      JrJedis::Redis      8.733k (±10.8%) i/s -     26.176k

min: 8.166k  max: 8.935k   i/s @±4.5%
```
