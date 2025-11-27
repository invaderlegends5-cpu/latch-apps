import {
    Controller,
    Get,
    Post,
    Put,
    Delete,
    Param,
    Query,
    Body,
    UseGuards,
    HttpCode,
    HttpStatus,
    BadRequestException,
    Logger,
    Res,
    UseInterceptors,
  } from '@nestjs/common';
  import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
  import { TenantGuard } from '../auth/guards/tenant.guard';
  import { RolesGuard } from '../auth/guards/roles.guard';
  import { AdminOnly } from '../auth/decorators/admin-only.decorator';
  import { CacheControlInterceptor } from '../interceptors/cache-control.interceptor';
  import { IPReputationService } from './ip-reputation.service';
  import { IPReputationScore, ReputationQueryOptions } from './types/reputation.types';
  import type { Response } from 'express';
  import * as Sentry from '@sentry/node';
  
  @Controller('admin/ip-reputation')
  @UseGuards(JwtAuthGuard, TenantGuard, RolesGuard)
  @UseInterceptors(CacheControlInterceptor)
  export class IPReputationController {
    private readonly logger = new Logger(IPReputationController.name);
  
    constructor(private readonly reputationService: IPReputationService) {}
  
    @Get(':ip')
    @AdminOnly()
    @HttpCode(HttpStatus.OK)
    async getReputation(@Param('ip') ip: string): Promise<IPReputationScore | null> {
      if (!this.isValidIP(ip)) {
        throw new BadRequestException('Invalid IP address format');
      }
  
      try {
        const reputation = await this.reputationService.getReputation(ip);
        
        if (!reputation) {
          return null;
        }
  
        return reputation;
      } catch (error) {
        this.logger.error(`Error getting reputation for IP ${ip}:`, error);
        Sentry.captureException(error);
        throw error;
      }
    }
  
    @Post(':ip/block')
    @AdminOnly()
    @HttpCode(HttpStatus.OK)
    async blockIP(
      @Param('ip') ip: string,
      @Body('reason') reason: string,
      @Body('duration') duration?: number,
    ): Promise<{ message: string }> {
      if (!this.isValidIP(ip)) {
        throw new BadRequestException('Invalid IP address format');
      }
  
      if (!reason) {
        throw new BadRequestException('Block reason is required');
      }
  
      try {
        await this.reputationService.blockIP(ip, reason, duration);
        
        return { message: `IP ${ip} has been blocked` };
      } catch (error) {
        this.logger.error(`Error blocking IP ${ip}:`, error);
        Sentry.captureException(error);
        throw error;
      }
    }
  
    @Delete(':ip/block')
    @AdminOnly()
    @HttpCode(HttpStatus.OK)
    async unblockIP(@Param('ip') ip: string): Promise<{ message: string }> {
      if (!this.isValidIP(ip)) {
        throw new BadRequestException('Invalid IP address format');
      }
  
      try {
        await this.reputationService.unblockIP(ip);
        
        return { message: `IP ${ip} has been unblocked` };
      } catch (error) {
        this.logger.error(`Error unblocking IP ${ip}:`, error);
        Sentry.captureException(error);
        throw error;
      }
    }
  
    @Post(':ip/whitelist')
    @AdminOnly()
    @HttpCode(HttpStatus.OK)
    async whitelistIP(
      @Param('ip') ip: string,
      @Body('reason') reason: string,
    ): Promise<{ message: string }> {
      if (!this.isValidIP(ip)) {
        throw new BadRequestException('Invalid IP address format');
      }
  
      if (!reason) {
        throw new BadRequestException('Whitelist reason is required');
      }
  
      try {
        await this.reputationService.whitelistIP(ip, reason);
        
        return { message: `IP ${ip} has been whitelisted` };
      } catch (error) {
        this.logger.error(`Error whitelisting IP ${ip}:`, error);
        Sentry.captureException(error);
        throw error;
      }
    }
  
    @Delete(':ip/whitelist')
    @AdminOnly()
    @HttpCode(HttpStatus.OK)
    async removeWhitelistIP(@Param('ip') ip: string): Promise<{ message: string }> {
      if (!this.isValidIP(ip)) {
        throw new BadRequestException('Invalid IP address format');
      }
  
      try {
        await this.reputationService.removeWhitelistIP(ip);
        
        return { message: `IP ${ip} has been removed from whitelist` };
      } catch (error) {
        this.logger.error(`Error removing IP ${ip} from whitelist:`, error);
        Sentry.captureException(error);
        throw error;
      }
    }
  
    @Get()
    @AdminOnly()
    @HttpCode(HttpStatus.OK)
    async queryReputations(
      @Res({ passthrough: true }) res: Response,
      @Query('minScore') minScore?: string,
      @Query('maxScore') maxScore?: string,
      @Query('riskLevel') riskLevel?: string,
      @Query('blockedOnly') blockedOnly?: string,
      @Query('daysBack') daysBack?: string,
    ): Promise<IPReputationScore[]> {
      try {
        const options: ReputationQueryOptions = {};
  
        if (minScore !== undefined) {
          const parsed = parseInt(minScore, 10);
          if (isNaN(parsed)) {
            throw new BadRequestException('Invalid minScore parameter');
          }
          options.minScore = parsed;
        }
  
        if (maxScore !== undefined) {
          const parsed = parseInt(maxScore, 10);
          if (isNaN(parsed)) {
            throw new BadRequestException('Invalid maxScore parameter');
          }
          options.maxScore = parsed;
        }
  
        if (riskLevel) {
          const levels = riskLevel.split(',').map(l => l.trim().toUpperCase());
          options.riskLevel = levels.filter(l => 
            ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(l)
          ) as any;
        }
  
        if (blockedOnly !== undefined) {
          options.blockedOnly = blockedOnly.toLowerCase() === 'true';
        }
  
        if (daysBack !== undefined) {
          const parsed = parseInt(daysBack, 10);
          if (isNaN(parsed) || parsed < 1 || parsed > 365) {
            throw new BadRequestException('Invalid daysBack parameter (1-365)');
          }
          options.daysBack = parsed;
        }
  
        const reputations = await this.reputationService.queryReputations(options);
        
        return reputations;
      } catch (error) {
        this.logger.error('Error querying reputations:', error);
        Sentry.captureException(error);
        throw error;
      }
    }
  
    @Post(':ip/reset')
    @AdminOnly()
    @HttpCode(HttpStatus.OK)
    async resetReputation(@Param('ip') ip: string): Promise<{ message: string }> {
      if (!this.isValidIP(ip)) {
        throw new BadRequestException('Invalid IP address format');
      }
  
      try {
        await this.reputationService.resetReputation(ip);
        
        return { message: `Reputation for IP ${ip} has been reset` };
      } catch (error) {
        this.logger.error(`Error resetting reputation for IP ${ip}:`, error);
        Sentry.captureException(error);
        throw error;
      }
    }
  
    @Get(':ip/threats')
    @AdminOnly()
    @HttpCode(HttpStatus.OK)
    async getThreats(@Param('ip') ip: string): Promise<any[]> {
      if (!this.isValidIP(ip)) {
        throw new BadRequestException('Invalid IP address format');
      }
  
      try {
        const reputation = await this.reputationService.getReputation(ip);
        
        return reputation?.threatIndicators || [];
      } catch (error) {
        this.logger.error(`Error getting threats for IP ${ip}:`, error);
        Sentry.captureException(error);
        throw error;
      }
    }
  
    private isValidIP(ip: string): boolean {
      // Basic IPv4 and IPv6 validation
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
      const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
      const ipv6CompressedRegex = /^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/;
      
      if (ipv4Regex.test(ip)) {
        // Additional validation for IPv4
        const octets = ip.split('.').map(Number);
        return octets.every(octet => octet >= 0 && octet <= 255);
      }
      
      return ipv6Regex.test(ip) || ipv6CompressedRegex.test(ip);
    }
  }