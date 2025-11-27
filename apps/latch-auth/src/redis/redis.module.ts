import { Module, Global } from '@nestjs/common';
import { Redis } from 'ioredis';
import { RedisService } from './redis.service';

@Global()
@Module({
  providers: [
    {
      provide: 'REDIS',
      useFactory: () => {
        const redis = new Redis({
  host: process.env.REDIS_HOST ?? 'localhost',
  port: parseInt(process.env.REDIS_PORT!, 10) || 6379,
  maxRetriesPerRequest: 3,
  lazyConnect: true, // Don't connect immediately
  
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