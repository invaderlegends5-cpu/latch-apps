// src/auth/guards/session.guard.ts
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from '../auth.service';
import { EventLogService } from '../../events/event.service';
import { ClearCookiesUnauthorizedException } from '../exceptions/clear-cookies-unauthorized.exception';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { BotDetectionService } from '@/bot-detection/bot-detection.service';

@Injectable()
export class SessionGuard implements CanActivate {
  constructor(
    private readonly authService: AuthService,
    private readonly eventLogService: EventLogService,
    private readonly ipReputationService: IPReputationService,
    private readonly behavioralAnalysis: BehavioralAnalysisService,
    private readonly botDetection: BotDetectionService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context
      .switchToHttp()
      .getRequest<Request & { user?: any; tenant?: any }>();

    const ipAddress = req.ip || null;
    const userAgent = (req.headers['user-agent'] as string) || null;

    if (ipAddress) {
      if (await this.ipReputationService.isIPBlocked(ipAddress)) {
        await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
          userId: null,
          tenantId: null,
          metadata: { 
            reason: 'BLOCKED_IP_ATTEMPT',
            path: req.path,
            method: req.method,
          },
          ipAddress,
          userAgent,
          severity: 'CRITICAL',
        });
        
        throw new ForbiddenException('IP address is blocked due to suspicious activity');
      }
    }

// Perform behavioral analysis for this request
const analysis = await this.behavioralAnalysis.analyzeRequest(
  req.user?.sub || null,
  req.user?.sessionId || null,
  ipAddress,
  userAgent,
  req.method,
  req.url,
);

// Check if behavioral analysis recommends blocking
if (analysis.recommendation === 'BLOCK') {
  await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
    userId: req.user?.sub ?? null,
    tenantId: req.user?.tenantId ?? null,
    metadata: {
      reason: 'behavioral_analysis_block',
      riskScore: analysis.riskScore,
      anomalyType: analysis.anomalyType,
      severity: analysis.severity,
    },
    ipAddress,
    userAgent,
    severity: 'CRITICAL',
  });
  
  throw new ForbiddenException('Request blocked due to suspicious behavior patterns');
}

const botAnalysis = await this.botDetection.analyzeRequest(
  req.user?.sub || null,
  req.user?.sessionId || null,
  ipAddress,
  userAgent,
  req.method,
  req.url,
);

// Check if bot analysis recommends blocking
if (botAnalysis.recommendation === 'BLOCK') {
  await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
    userId: req.user?.sub ?? null,
    tenantId: req.user?.tenantId ?? null,
    metadata: {
      reason: 'bot_detection_block',
      botRiskScore: botAnalysis.riskScore,
      botConfidence: botAnalysis.confidence,
      botIndicators: botAnalysis.indicators,
    },
    ipAddress,
    userAgent,
    severity: 'CRITICAL',
  });
  
  throw new ForbiddenException('Request blocked by bot detection system');
}

// If high confidence bot, require challenge
if (botAnalysis.recommendation === 'CHALLENGE') {
  // This would implement CAPTCHA or other challenge mechanisms
  // For now, log and continue
  await this.eventLogService.logEvent('SECURITY_STATUS_CHECKED', {
    userId: req.user?.sub ?? null,
    tenantId: req.user?.tenantId ?? null,
    metadata: {
      reason: 'bot_challenge_required',
      botRiskScore: botAnalysis.riskScore,
      botConfidence: botAnalysis.confidence,
      botIndicators: botAnalysis.indicators,
    },
    ipAddress,
    userAgent,
    severity: 'SECURITY',
  });
}

    // JwtStrategy attaches the JWT payload to req.user
    const jwtPayload = req.user;

    if (!jwtPayload || !jwtPayload.sessionId) {
      await this.eventLogService.logEvent('SESSION_REVOKE', {
        userId: jwtPayload?.sub ?? null,
        tenantId: jwtPayload?.tenantId ?? null,
        metadata: { reason: 'missing_session_in_token' },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
            throw new ClearCookiesUnauthorizedException('Missing or invalid session');
    }

    // ✅ Validate session in DB (revoked/expired)
    const sessionUser = await this.authService.getUserBySessionId(
      jwtPayload.sessionId,
      { ipAddress, userAgent },
    );

    if (!sessionUser) {
      // Already logged inside getUserBySessionId, but we add another explicit log for traceability
      await this.eventLogService.logEvent(
        'AUTHENTICATION_VERIFICATION_FAILED',
        {
          userId: jwtPayload?.sub ?? null,
          tenantId: jwtPayload?.tenantId ?? null,
          metadata: {
            reason: 'session_invalid_or_expired',
            sessionId: jwtPayload.sessionId,
          },
          ipAddress,
          userAgent,
          severity: 'SECURITY',
        },
      );
      
      throw new ClearCookiesUnauthorizedException('Invalid or expired session');
    }

    // ✅ Only attach enriched user if session is valid
    req.user = {
      ...jwtPayload, // from token
      id: jwtPayload.sub,
      sessionId: jwtPayload.sessionId,
      tenantId: jwtPayload.tenantId,
      // from DB
      dbUserId: sessionUser.id,
      dbTenantId: sessionUser.tenantId,
    };

    req.tenant = { id: sessionUser.tenantId, slug: undefined };
        return true;
  }
}
