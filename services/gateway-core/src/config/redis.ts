import { Redis } from 'ioredis';

declare module 'ioredis' {
  interface Redis {
    slidingWindowRateLimit(
      key: string,
      now: string | number,
      windowStart: string | number,
      maxLimit: string | number,
      expiryInSeconds: string | number,
      memberId?: string
    ): Promise<number>;
    rateLimitIncr(
      key: string,
      expiryInSeconds: string | number,
      maxLimit: string | number
    ): Promise<number>;
  }
}

const REDIS_URL = process.env.REDIS_URL;
const REDIS_HOST = process.env.REDIS_HOST || 'localhost';
const REDIS_PORT = Number(process.env.REDIS_PORT) || 6379;

export const redisClient = REDIS_URL
  ? new Redis(REDIS_URL, {
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        return Math.min(times * 50, 2000);
      }
    })
  : new Redis({
      host: REDIS_HOST,
      port: REDIS_PORT,
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        return Math.min(times * 50, 2000);
      }
    });

// Atomic fixed-window counter: increments hit count, sets initial TTL, and checks against max threshold
redisClient.defineCommand('rateLimitIncr', {
  numberOfKeys: 1,
  lua: `
    local current = redis.call("INCR", KEYS[1])
    if tonumber(current) == 1 then
      redis.call("EXPIRE", KEYS[1], ARGV[1])
    end
    if tonumber(current) > tonumber(ARGV[2]) then
      return 0
    else
      return 1
    end
  `
});

// Atomic sliding-window log: prunes expired scores, checks set cardinality, and appends current timestamp member
redisClient.defineCommand('slidingWindowRateLimit', {
  numberOfKeys: 1,
  lua: `
    redis.call("ZREMRANGEBYSCORE", KEYS[1], 0, ARGV[2])
    local current_hits = redis.call("ZCARD", KEYS[1])
    if tonumber(current_hits) < tonumber(ARGV[3]) then
      local member = ARGV[5] or (ARGV[1] .. ":" .. tostring(current_hits + 1))
      redis.call("ZADD", KEYS[1], ARGV[1], member)
      redis.call("EXPIRE", KEYS[1], ARGV[4])
      return 1
    else
      return 0
    end
  `
});

redisClient.on('connect', () => {
  console.log('📦 Connected to Redis Cache Cluster Successfully');
});

redisClient.on('error', (err) => {
  console.error('❌ Redis Cache Cluster Connection Failure:', err.message);
});