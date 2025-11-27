import { Injectable, Logger, Inject } from '@nestjs/common';
import { Redis } from 'ioredis';

@Injectable()
export class RedisService {
  private readonly logger = new Logger(RedisService.name);

  constructor(@Inject('REDIS') private readonly redis: Redis) {
    // Redis instance is already provided by your RedisModule
  }

  async get(key: string): Promise<string | null> {
    try {
      return await this.redis.get(key);
    } catch (error) {
      this.logger.error(`Redis GET error for key ${key}:`, error);
      return null;
    }
  }

  async set(key: string, value: string): Promise<void> {
    try {
      await this.redis.set(key, value);
    } catch (error) {
      this.logger.error(`Redis SET error for key ${key}:`, error);
    }
  }

  async setex(key: string, seconds: number, value: string): Promise<void> {
    try {
      await this.redis.setex(key, seconds, value);
    } catch (error) {
      this.logger.error(`Redis SETEX error for key ${key}:`, error);
    }
  }

  async del(key: string): Promise<number> {
    try {
      return await this.redis.del(key);
    } catch (error) {
      this.logger.error(`Redis DEL error for key ${key}:`, error);
      return 0;
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      const result = await this.redis.exists(key);
      return result === 1;
    } catch (error) {
      this.logger.error(`Redis EXISTS error for key ${key}:`, error);
      return false;
    }
  }

  async keys(pattern: string): Promise<string[]> {
    try {
      return await this.redis.keys(pattern);
    } catch (error) {
      this.logger.error(`Redis KEYS error for pattern ${pattern}:`, error);
      return [];
    }
  }

  async expire(key: string, seconds: number): Promise<boolean> {
    try {
      const result = await this.redis.expire(key, seconds);
      return result === 1;
    } catch (error) {
      this.logger.error(`Redis EXPIRE error for key ${key}:`, error);
      return false;
    }
  }

  async ttl(key: string): Promise<number> {
    try {
      return await this.redis.ttl(key);
    } catch (error) {
      this.logger.error(`Redis TTL error for key ${key}:`, error);
      return -1;
    }
  }

  async hget(key: string, field: string): Promise<string | null> {
    try {
      return await this.redis.hget(key, field);
    } catch (error) {
      this.logger.error(`Redis HGET error for key ${key}, field ${field}:`, error);
      return null;
    }
  }

  async hset(key: string, field: string, value: string): Promise<void> {
    try {
      await this.redis.hset(key, field, value);
    } catch (error) {
      this.logger.error(`Redis HSET error for key ${key}, field ${field}:`, error);
    }
  }

  async hmget(key: string, ...fields: string[]): Promise<(string | null)[]> {
    try {
      return await this.redis.hmget(key, ...fields);
    } catch (error) {
      this.logger.error(`Redis HMGET error for key ${key}:`, error);
      return fields.map(() => null); // Return array of nulls with same length as fields
    }
  }

  async incr(key: string): Promise<number> {
    try {
      return await this.redis.incr(key);
    } catch (error) {
      this.logger.error(`Redis INCR error for key ${key}:`, error);
      return 0;
    }
  }

  async decr(key: string): Promise<number> {
    try {
      return await this.redis.decr(key);
    } catch (error) {
      this.logger.error(`Redis DECR error for key ${key}:`, error);
      return 0;
    }
  }
  async lrange(key: string, start: number, stop: number): Promise<string[]> {
    try {
      return await this.redis.lrange(key, start, stop);
    } catch (error) {
      this.logger.error(`Redis LRANGE error for key ${key}:`, error);
      return [];
    }
  }

  async lpush(key: string, ...values: string[]): Promise<number> {
    try {
      return await this.redis.lpush(key, ...values);
    } catch (error) {
      this.logger.error(`Redis LPUSH error for key ${key}:`, error);
      return 0;
    }
  }

  async rpush(key: string, ...values: string[]): Promise<number> {
    try {
      return await this.redis.rpush(key, ...values);
    } catch (error) {
      this.logger.error(`Redis RPUSH error for key ${key}:`, error);
      return 0;
    }
  }

  async ltrim(key: string, start: number, stop: number): Promise<void> {
    try {
      await this.redis.ltrim(key, start, stop);
    } catch (error) {
      this.logger.error(`Redis LTRIM error for key ${key}:`, error);
    }
  }

  async expireat(key: string, timestamp: number): Promise<boolean> {
    try {
      const result = await this.redis.expireat(key, timestamp);
      return result === 1;
    } catch (error) {
      this.logger.error(`Redis EXPIREAT error for key ${key}:`, error);
      return false;
    }
  }

  async zadd(key: string, score: number, member: string): Promise<number> {
    try {
      return await this.redis.zadd(key, score, member);
    } catch (error) {
      this.logger.error(`Redis ZADD error for key ${key}:`, error);
      return 0;
    }
  }

  async zrangebyscore(key: string, min: string | number, max: string | number): Promise<string[]> {
    try {
      return await this.redis.zrangebyscore(key, min, max);
    } catch (error) {
      this.logger.error(`Redis ZRANGEBYSCORE error for key ${key}:`, error);
      return [];
    }
  }

  async zremrangebyscore(key: string, min: string | number, max: string | number): Promise<number> {
    try {
      return await this.redis.zremrangebyscore(key, min, max);
    } catch (error) {
      this.logger.error(`Redis ZREMRANGEBYSCORE error for key ${key}:`, error);
      return 0;
    }
  }

  async hincrby(key: string, field: string, increment: number): Promise<number> {
    try {
      return await this.redis.hincrby(key, field, increment);
    } catch (error) {
      this.logger.error(`Redis HINCRBY error for key ${key}, field ${field}:`, error);
      return 0;
    }
  }
}