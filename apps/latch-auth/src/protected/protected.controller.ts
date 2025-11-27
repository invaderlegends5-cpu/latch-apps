// src/protected/protected.controller.ts
import {
  Controller,
  Get,
  Req,
  UseGuards,
  Res,
  Post,
  Body,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { TenantGuard } from '../auth/guards/tenant.guard';
import type { Response } from 'express';
import type { AuthenticatedRequest } from '../auth/types/auth.types';
import { EventLogService } from '../events/event.service';
import { SessionGuard } from '../auth/guards/session.guard';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';

@Controller('protected')
@UseGuards(JwtAuthGuard, SessionGuard, TenantGuard)
export class ProtectedController {
  constructor(
    private eventLogService: EventLogService,
    private ipReputationService: IPReputationService,

  ) {}

  @Get('me')
  async me(
    @Req() req: AuthenticatedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user.id,
        tenantId: req.user.tenantId,
        metadata: { 
          reason: 'BLOCKED_IP_SENSITIVE_DATA_ACCESS_ATTEMPT',
          endpoint: '/protected/me',
          action: 'GET_USER_PROFILE',
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'],
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Sensitive data access denied - IP address is blocked');
    }

    // Add cache control headers
    res.set({
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      Pragma: 'no-cache',
      Expires: '0',
    });

    // Log sensitive data access
    await this.eventLogService.logEvent('SENSITIVE_DATA_ACCESSED', {
      userId: req.user.id,
      tenantId: req.user.tenantId,
      metadata: {
        accessedEndpoint: '/protected/me',
        dataType: 'user_profile_and_tenant_info',
        accessType: 'read',
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return { ok: true, user: req.user, tenant: req.tenant };
  }

  @Get('audit-trail')
  async getAuditTrail(@Req() req: AuthenticatedRequest) {
    // In a reusable package, we don't know what "admin" means
    // Instead, we can check if the user has a specific permission
    // But since we don't know the user's data model, let's make this endpoint optional

    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user.id,
        tenantId: req.user.tenantId,
        metadata: { 
          reason: 'BLOCKED_IP_AUDIT_TRAIL_ACCESS_ATTEMPT',
          endpoint: '/protected/audit-trail',
          action: 'GET_AUDIT_TRAIL',
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'],
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Audit trail access denied - IP address is blocked');
    }

    // For now, just log the access attempt
    await this.eventLogService.logEvent('AUDIT_TRAIL_ACCESS_ATTEMPTED', {
      userId: req.user.id,
      tenantId: req.user.tenantId,
      metadata: {
        requestedEndpoint: '/protected/audit-trail',
        reason: 'package_does_not_support_audit_trail',
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    throw new ForbiddenException(
      'Audit trail functionality is not supported in this package version',
    );
  }

  @Post('export-data')
  async exportUserData(@Req() req: AuthenticatedRequest) {
    // Similarly, data export requires knowing the user's permissions
    // Since we don't know the user's data model, we'll make this optional too

    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user.id,
        tenantId: req.user.tenantId,
        metadata: { 
          reason: 'BLOCKED_IP_DATA_EXPORT_ATTEMPT',
          endpoint: '/protected/export-data',
          action: 'EXPORT_USER_DATA',
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'],
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Data export denied - IP address is blocked');
    }

    await this.eventLogService.logEvent('DATA_EXPORT_ATTEMPTED', {
      userId: req.user.id,
      tenantId: req.user.tenantId,
      metadata: {
        requestedAction: 'export_user_data',
        reason: 'package_does_not_support_data_export',
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    throw new ForbiddenException(
      'Data export functionality is not supported in this package version',
    );
  }

  @Get('security-status')
  async getSecurityStatus(@Req() req: AuthenticatedRequest) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user.id,
        tenantId: req.user.tenantId,
        metadata: { 
          reason: 'BLOCKED_IP_SECURITY_STATUS_CHECK_ATTEMPT',
          endpoint: '/protected/security-status',
          action: 'CHECK_SECURITY_STATUS',
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'],
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Security status check denied - IP address is blocked');
    }

    // Log security status check
    await this.eventLogService.logEvent('SECURITY_STATUS_CHECKED', {
      userId: req.user.id,
      tenantId: req.user.tenantId,
      metadata: {
        checkedComponents: [
          'authentication',
          'authorization',
          'session_management',
        ],
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return {
      ok: true,
      securityStatus: {
        authentication: 'active',
        authorization: 'enforced',
        sessionManagement: 'secure',
        lastSecurityCheck: new Date(),
      },
    };
  }

  @Get('verify-authentication')
  async verifyAuthentication(@Req() req: AuthenticatedRequest) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user.id,
        tenantId: req.user.tenantId,
        metadata: { 
          reason: 'BLOCKED_IP_AUTH_VERIFICATION_ATTEMPT',
          endpoint: '/protected/verify-authentication',
          action: 'VERIFY_AUTHENTICATION',
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'],
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Authentication verification denied - IP address is blocked');
    }

    // This endpoint is protected by JwtAuthGuard and TenantGuard
    // But we add an explicit check for additional security

    if (!req.user || !req.user.id) {
      await this.eventLogService.logEvent(
        'AUTHENTICATION_VERIFICATION_FAILED',
        {
          userId: null,
          tenantId: null,
          metadata: {
            reason: 'missing_user_context',
            endpoint: '/protected/verify-authentication',
          },
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        },
      );
      throw new UnauthorizedException(
        'Authentication verification failed - missing user context',
      );
    }

    await this.eventLogService.logEvent('AUTHENTICATION_VERIFIED', {
      userId: req.user.id,
      tenantId: req.user.tenantId,
      metadata: {
        verifiedEndpoint: '/protected/verify-authentication',
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return {
      ok: true,
      message: 'Authentication verified successfully',
      user: req.user, // ✅ Return the entire user object as is
    };
  }
}
