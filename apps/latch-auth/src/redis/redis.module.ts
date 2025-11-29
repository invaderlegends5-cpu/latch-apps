// src/redis/redis.module.ts
import { Module, Global } from '@nestjs/common';
import { Redis } from 'ioredis';
import { RedisService } from './redis.service';

@Global()
@Module({
  providers: [
    {
      provide: 'REDIS',
      useFactory: () => {
        // Use the full URL provided by the environment variable
        const redisUrl = process.env.REDIS_URL ?? 'redis://localhost:6379';
        
        // Pass the entire connection string to the Redis constructor
        const redis = new Redis(redisUrl, {
          maxRetriesPerRequest: 3,
          lazyConnect: true, // Don't connect immediately
          // You don't need host/port options if the URL is provided
        });

        // Handle connection events
        redis.on('error', (err) => {
          console.error('Redis Client Error', err);
        });

        redis.on('connect', () => {
          console.log('Redis Client Connected');
        });

        return redis;
      },
    },
    RedisService, 
  ],
  exports: ['REDIS', RedisService], 
})
export class RedisModule {}