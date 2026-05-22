import { Redis } from 'ioredis';

const REDIS_HOST = process.env.REDIS_HOST || 'localhost';
const REDIS_PORT = Number(process.env.REDIS_PORT) || 6379;

// Initialize a highly performant persistent connection to our Docker container cache
export const redisClient = new Redis({
    host: REDIS_HOST,
    port: REDIS_PORT,
    maxRetriesPerRequest: 3,
    retryStrategy(times) {
        const delay = Math.min(times * 50, 2000);
        return delay;
    }
});

redisClient.on('connect', () => {
    console.log('📦 Connected to Redis Cache Cluster Successfully');
});

redisClient.on('error', (err) => {
    console.error('❌ Redis Cache Cluster Connection Failure:', err.message);
});