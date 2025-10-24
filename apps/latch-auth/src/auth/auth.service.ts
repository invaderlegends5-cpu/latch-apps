// src/auth/auth.service.ts
import { ClearCookiesUnauthorizedException } from './exceptions/clear-cookies-unauthorized.exception';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RequestOtpDto } from './dto/request-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import * as crypto from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { hashToken } from './utils/hash.util';
import { EventLogService } from '../events/event.service';
import { PrismaError } from './types/auth.types';
import { RefreshToken, Session } from '@prisma/client';
import { DevOtpStore } from '../../test/utils/dev-otp-store';
type RequestContext = {
  ipAddress?: string | null;
  userAgent?: string | null;
};

function maskPhone(phone: string): string {
  if (!phone) return '***';
  if (phone.length <= 4) return '***';
  return `${phone.slice(0, 2)}*****${phone.slice(-2)}`;
}

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private eventLogService: EventLogService,
  ) {}

  async requestOtp(dto: RequestOtpDto, requestContext?: RequestContext) {
    const { phone, tenantSlug } = dto;
    let tenant = await this.prisma.tenant.findUnique({
      where: { slug: tenantSlug ?? 'default' },
    });
    if (!tenant) {
      tenant = await this.prisma.tenant.create({
        data: { name: tenantSlug ?? 'default', slug: tenantSlug ?? 'default' },
      });
    }

    let user = await this.prisma.user.findFirst({
      where: { tenantId: tenant.id, phone },
    });
    if (!user) {
      user = await this.prisma.user.create({
        data: { tenantId: tenant.id, phone },
      });
    }

    
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 15); // 15m

    if (process.env.NODE_ENV === 'test') {
      DevOtpStore.set(phone, code);
    }

    await this.prisma.oTP.create({
      data: {
        tenantId: tenant.id,
        userId: user.id,
        channel: 'PHONE',
        codeHash,
        expiresAt,
      },
    });

    console.log(`[DEV OTP] ${phone} -> ${code}`);
    // console.log(`[DEV OTP] ${this.maskPhone(phone)} -> ${code}`);

    await this.eventLogService.logEvent('OTP_REQUEST', {
      userId: user.id,
      tenantId: tenant.id,
      metadata: { phone: maskPhone(phone) },
      ipAddress: requestContext?.ipAddress ?? null,
      userAgent: requestContext?.userAgent ?? null,
      severity: 'INFO',
    });

    return { ok: true, message: 'OTP sent (dev: check server logs)' };
  }

  async verifyOtp(dto: VerifyOtpDto, requestContext?: RequestContext) {
    const { phone, code, tenantSlug } = dto;
    const tenant = await this.prisma.tenant.findUnique({
      where: { slug: tenantSlug ?? 'default' },
    });
    if (!tenant) {
      // log verification failure for missing tenant
      await this.eventLogService.logEvent(
        'AUTHENTICATION_VERIFICATION_FAILED',
        {
          userId: null,
          tenantId: null,
          metadata: { phone, reason: 'tenant_not_found' },
          ipAddress: requestContext?.ipAddress ?? null,
          userAgent: requestContext?.userAgent ?? null,
          severity: 'SECURITY',
        },
      );
      throw new UnauthorizedException('Tenant not found');
    }

    const user = await this.prisma.user.findFirst({
      where: { tenantId: tenant.id, phone },
    });
    if (!user) {
      await this.eventLogService.logEvent(
        'AUTHENTICATION_VERIFICATION_FAILED',
        {
          userId: null,
          tenantId: tenant.id,
          metadata: { phone, reason: 'user_not_found' },
          ipAddress: requestContext?.ipAddress ?? null,
          userAgent: requestContext?.userAgent ?? null,
          severity: 'SECURITY',
        },
      );
      throw new UnauthorizedException('User not found');
    }

    const now = new Date();
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');

    const otp = await this.prisma.oTP.findFirst({
      where: {
        tenantId: tenant.id,
        userId: user.id,
        codeHash,
        consumed: false,
        expiresAt: { gt: now },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!otp) {
      // Invalid or expired OTP — log and throw
      await this.eventLogService.logEvent(
        'AUTHENTICATION_VERIFICATION_FAILED',
        {
          userId: user.id,
          tenantId: tenant.id,
          metadata: {
            phone: maskPhone(phone),
            reason: 'invalid_or_expired_otp',
          },
          ipAddress: requestContext?.ipAddress ?? null,
          userAgent: requestContext?.userAgent ?? null,
          severity: 'SECURITY',
        },
      );
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    await this.prisma.oTP.update({
      where: { id: otp.id },
      data: { consumed: true },
    });

    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7);
    const nowForSession = new Date();
    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        tenantId: tenant.id,
        refreshHash: '',
        ipAddress: requestContext?.ipAddress ?? null,
        userAgent: requestContext?.userAgent ?? null,
        lastActiveAt: nowForSession,
        expiresAt,
      },
    });

    const refreshTokenPlain = crypto.randomBytes(40).toString('hex');
    const refreshHash = hashToken(refreshTokenPlain);

    await this.prisma.refreshToken.create({
      data: {
        sessionId: session.id,
        tokenHash: refreshHash,
        parentId: null,
        familyId: crypto.randomUUID(),
        revoked: false,
        expiresAt,
      },
    });

    const csrfToken = crypto.randomBytes(16).toString('hex');

    await this.prisma.session.update({
      where: { id: session.id },
      data: {
        refreshHash,
        csrfToken,
      },
    });

    // after creating session (session.id exists)
    const payload = {
      sub: user.id,
      tenantId: tenant.id,
      sessionId: session.id,
      mfa: false,
    };
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
    });

    const activeSessions = await this.getActiveSessionCount(user.id);

    await this.eventLogService.logEvent('LOGIN', {
      userId: user.id,
      tenantId: tenant.id,
      metadata: {
        sessionId: session.id,
        csrfTokenSet: true,
        activeSessions,
      },
      ipAddress: requestContext?.ipAddress ?? null,
      userAgent: requestContext?.userAgent ?? null,
      severity: 'SECURITY',
    });

    return {
      ok: true,
      accessToken,
      refreshToken: refreshTokenPlain,
      sessionId: session.id,
      csrfToken,
      user: { id: user.id, phone: user.phone, tenantId: tenant.id },
    };
  }

  async getUserBySessionId(sessionId: string, requestContext?: RequestContext) {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { user: true },
    });
    if (!session) return null;

    // If session is revoked => null
    if (session.revoked) return null;

    // If expired => mark revoked and log SESSION_EXPIRED
    if (session.expiresAt < new Date()) {
      await this.prisma.session.update({
        where: { id: session.id },
        data: { revoked: true },
      });

      await this.eventLogService.logEvent('SESSION_EXPIRED', {
        userId: session.userId,
        tenantId: session.tenantId,
        metadata: { sessionId: session.id },
        ipAddress: requestContext?.ipAddress ?? null,
        userAgent: requestContext?.userAgent ?? null,
        severity: 'SECURITY',
      });

      return null;
    }

    return {
      id: session.user.id,
      tenantId: session.tenantId,
    };
  }

  async refreshTokens(
    refreshToken: string,
    sessionId: string,
    requestContext?: RequestContext,
  ) {
    const hashed = hashToken(refreshToken);
    const now = new Date();

    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { user: true },
    });

    if (!session) {
      await this.eventLogService.logEvent('REFRESH_FAILED', {
        userId: null,
        tenantId: null,
        metadata: {
          reason: 'no_session',
          sessionId,
        },
        ipAddress: requestContext?.ipAddress ?? null,
        userAgent: requestContext?.userAgent ?? null,
        severity: 'SECURITY',
      });
      // throw new UnauthorizedException('Invalid session');
      throw new ClearCookiesUnauthorizedException('Invalid session');
    }

    if (session.revoked) {
      await this.eventLogService.logEvent('REFRESH_FAILED', {
        userId: session.userId,
        tenantId: session.tenantId,
        metadata: {
          reason: 'revoked',
          sessionId,
        },
        ipAddress: requestContext?.ipAddress ?? null,
        userAgent: requestContext?.userAgent ?? null,
        severity: 'SECURITY',
      });
      // throw new UnauthorizedException('Session revoked');
      throw new ClearCookiesUnauthorizedException('Session revoked');
    }

    if (session.expiresAt < now) {
      await this.prisma.session.update({
        where: { id: session.id },
        data: { revoked: true },
      });
      await this.eventLogService.logEvent('SESSION_EXPIRED', {
        userId: session.userId,
        tenantId: session.tenantId,
        metadata: { sessionId },
        ipAddress: requestContext?.ipAddress ?? null,
        userAgent: requestContext?.userAgent ?? null,
        severity: 'SECURITY',
      });
      // throw new UnauthorizedException('Session expired');
      throw new ClearCookiesUnauthorizedException('Session expired');
    }

    let tokenToRevoke: (RefreshToken & { session: Session }) | null = null;

    try {
      tokenToRevoke = await this.prisma.refreshToken.update({
        where: {
          tokenHash: hashed,
          sessionId: session.id,
          revoked: false,
          expiresAt: { gte: now },
        },
        data: { revoked: true },
        include: { session: true },
      });
    } catch (error) {
      const prismaError = error as PrismaError;
      if (prismaError.code === 'P2025') {
        // No record found - token was already used, revoked, or expired
        const existingToken = await this.prisma.refreshToken.findUnique({
          where: { tokenHash: hashed },
        });

        if (existingToken) {
          if (existingToken.revoked) {
            await this.handleTokenReuse(existingToken, requestContext);
            // throw new UnauthorizedException(
            //   'Refresh token revoked (possible reuse). Session revoked.',
            // );
            throw new ClearCookiesUnauthorizedException(
              'Refresh token revoked (possible reuse). Session revoked.',
            );
          }
          if (existingToken.expiresAt < now) {
            await this.prisma.session.update({
              where: { id: session.id },
              data: { revoked: true },
            });
            await this.prisma.refreshToken.updateMany({
              where: { familyId: existingToken.familyId },
              data: { revoked: true },
            });
            await this.eventLogService.logEvent('REFRESH_FAILED', {
              userId: session.userId,
              tenantId: session.tenantId,
              metadata: {
                reason: 'token_expired',
                sessionId,
                familyId: existingToken.familyId,
              },
              ipAddress: requestContext?.ipAddress ?? null,
              userAgent: requestContext?.userAgent ?? null,
              severity: 'SECURITY',
            });
            // throw new UnauthorizedException('Refresh token expired');
            throw new ClearCookiesUnauthorizedException(
              'Refresh token expired',
            );
          }
          if (existingToken.sessionId !== session.id) {
            await this.eventLogService.logEvent('REFRESH_FAILED', {
              userId: session.userId,
              tenantId: session.tenantId,
              metadata: {
                reason: 'token_session_mismatch',
                tokenSessionId: existingToken.sessionId,
                sessionId,
              },
              ipAddress: requestContext?.ipAddress ?? null,
              userAgent: requestContext?.userAgent ?? null,
              severity: 'SECURITY',
            });
            // throw new UnauthorizedException(
            //   'Invalid refresh token for this session',
            // );
            throw new ClearCookiesUnauthorizedException(
              'Invalid refresh token for this session',
            );
          }
        }

        await this.eventLogService.logEvent('REFRESH_FAILED', {
          userId: session.userId,
          tenantId: session.tenantId,
          metadata: { reason: 'token_not_found', sessionId },
          ipAddress: requestContext?.ipAddress ?? null,
          userAgent: requestContext?.userAgent ?? null,
          severity: 'SECURITY',
        });
        // throw new UnauthorizedException('Invalid refresh token');
        throw new ClearCookiesUnauthorizedException('Invalid refresh token');
      }
      throw error; // Re-throw if it's a different error
    }

    // If we get here, the token was successfully revoked (first request wins)
    const tokenRecord = tokenToRevoke;
    // After successfully revoking the token in the atomic update
    await this.prisma.usedRefreshToken.create({
      data: {
        tokenHash: tokenRecord.tokenHash,
        sessionId: session.id,
        userId: session.userId,
        usedAt: new Date(),
        refreshTokenId: tokenRecord.id,
      },
    });

    const newPlain = crypto.randomBytes(40).toString('hex');
    const newHash = hashToken(newPlain);
    const newExpiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7);

    await this.prisma.refreshToken.create({
      data: {
        sessionId: session.id,
        tokenHash: newHash,
        parentId: tokenRecord.id,
        familyId: tokenRecord.familyId,
        revoked: false,
        expiresAt: newExpiresAt,
      },
    });

    await this.prisma.refreshToken.update({
      where: { id: tokenRecord.id },
      data: { revoked: true },
    });

    const newCsrf = crypto.randomBytes(16).toString('hex');

    await this.prisma.session.update({
      where: { id: session.id },
      data: {
        refreshHash: newHash,
        expiresAt: newExpiresAt,
        csrfToken: newCsrf,
        lastActiveAt: new Date(),
      },
    });

    const payload = {
      sub: session.user.id,
      tenantId: session.tenantId,
      sessionId: session.id,
      mfa: false,
    };
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
    });

    const activeSessions = await this.getActiveSessionCount(session.user.id);
    await this.eventLogService.logEvent('REFRESH_SUCCESS', {
      userId: session.user.id,
      tenantId: session.tenantId,
      metadata: {
        sessionId: session.id,
        csrfTokenRotated: true,
        familyId: tokenRecord.familyId,
        activeSessions,
      },
      ipAddress: requestContext?.ipAddress ?? null,
      userAgent: requestContext?.userAgent ?? null,
      severity: 'INFO',
    });

    return {
      ok: true,
      accessToken,
      refreshToken: newPlain,
      sessionId: session.id,
      csrfToken: newCsrf,
      familyId: tokenRecord.familyId,
      user: {
        id: session.user.id,
        phone: session.user.phone,
        tenantId: session.tenantId,
      },
    };
  }

  private async handleTokenReuse(
    tokenRecord: RefreshToken,
    requestContext?: RequestContext,
  ) {
    const familyId = tokenRecord.familyId;

    await this.prisma.refreshToken.updateMany({
      where: { familyId },
      data: { revoked: true },
    });

    const session = await this.prisma.session.update({
      where: { id: tokenRecord.sessionId },
      data: { revoked: true },
    });

    try {
      await this.prisma.usedRefreshToken.create({
        data: {
          tokenHash: tokenRecord.tokenHash,
          sessionId: tokenRecord.sessionId,
          userId: session.userId,
          usedAt: new Date(),
          refreshTokenId: tokenRecord.id,
        },
      });
    } catch (err: any) {
      if (err.code !== 'P2002') throw err;
      // ignore duplicate insert — token already marked as used
    }

    await this.eventLogService.logEvent('TOKEN_REUSE', {
      userId: session.userId,
      tenantId: session.tenantId,
      metadata: {
        familyId,
        tokenId: tokenRecord.id,
        sessionId: tokenRecord.sessionId,
        reason: 'token_reuse_detected',
      },
      ipAddress: requestContext?.ipAddress ?? null,
      userAgent: requestContext?.userAgent ?? null,
      severity: 'SECURITY',
    });

    console.warn('[SECURITY] TOKEN_REUSE detected', {
      familyId,
      tokenId: tokenRecord.id,
      sessionId: tokenRecord.sessionId,
      ...(requestContext && {
        ip: requestContext.ipAddress,
        ua: requestContext.userAgent,
      }),
    });
  }

  async getActiveSessionCount(userId: string): Promise<number> {
    return this.prisma.session.count({
      where: {
        userId,
        revoked: false,
        expiresAt: { gt: new Date() },
      },
    });
  }

  async revokeSession(sessionId: string, requestContext?: RequestContext) {
    await this.prisma.session.updateMany({
      where: { id: sessionId },
      data: { revoked: true },
    });

    await this.prisma.refreshToken.updateMany({
      where: { sessionId },
      data: { revoked: true },
    });

    let userId: string | null = null;
    let tenantId: string | null = null;

    const sessionUser = await this.getUserBySessionId(sessionId);
    if (sessionUser) {
      userId = sessionUser.id;
      tenantId = sessionUser.tenantId;
    }

    await this.eventLogService.logEvent('SESSION_REVOKE', {
      userId,
      tenantId,
      metadata: { sessionId },
      ipAddress: requestContext?.ipAddress ?? null,
      userAgent: requestContext?.userAgent ?? null,
      severity: 'INFO',
    });

    return { ok: true };
  }

  async revokeAllSessionsForUser(
    userId: string,
    requestContext?: RequestContext,
  ) {
    const sessions = await this.prisma.session.findMany({
      where: { userId },
      include: { user: true },
    });

    if (sessions.length === 0) return 0;

    await this.prisma.$transaction([
      this.prisma.session.updateMany({
        where: { userId },
        data: { revoked: true },
      }),
      this.prisma.refreshToken.updateMany({
        where: { sessionId: { in: sessions.map((s) => s.id) } },
        data: { revoked: true },
      }),
    ]);

    // log each session revoke for auditability (INFO)
    for (const session of sessions) {
      await this.eventLogService.logEvent('SESSION_REVOKE', {
        userId: session.userId,
        tenantId: session.tenantId,
        metadata: {
          sessionId: session.id,
          reason: 'revoke_all',
        },
        ipAddress: requestContext?.ipAddress ?? null,
        userAgent: requestContext?.userAgent ?? null,
        severity: 'INFO',
      });
    }

    // single aggregate event
    await this.eventLogService.logEvent('SESSION_REVOKE_ALL', {
      userId,
      tenantId: sessions[0]?.tenantId || null,
      metadata: {
        reason: 'revoke_all_sessions',
        revokedCount: sessions.length,
        activeSessionsAfter: 0,
      },
      ipAddress: requestContext?.ipAddress ?? null,
      userAgent: requestContext?.userAgent ?? null,
      severity: 'INFO',
    });

    return sessions.length;
  }
}
