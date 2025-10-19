"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var EventLogService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.EventLogService = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const prisma_service_1 = require("../prisma/prisma.service");
const crypto = __importStar(require("crypto"));
const rxjs_1 = require("rxjs");
let EventLogService = EventLogService_1 = class EventLogService {
    prisma;
    config;
    logger = new common_1.Logger(EventLogService_1.name);
    eventSubject = new rxjs_1.ReplaySubject(1);
    event$ = this.eventSubject.asObservable();
    signingSecret;
    constructor(prisma, config) {
        this.prisma = prisma;
        this.config = config;
        this.signingSecret = this.config.get('EVENT_SIGNING_SECRET') ?? '';
        if (!this.signingSecret && process.env.NODE_ENV !== 'development') {
            throw new Error('EVENT_SIGNING_SECRET is required in production');
        }
        if (!this.signingSecret) {
            this.logger.warn('EVENT_SIGNING_SECRET is empty — integrity hashes will be predictable. Set EVENT_SIGNING_SECRET in env for production.');
        }
    }
    maskIp(ip) {
        if (!ip)
            return null;
        if (ip.includes(':')) {
            const parts = ip.split(':');
            const head = parts.slice(0, 4).join(':');
            return `${head}::`;
        }
        const parts = ip.split('.');
        if (parts.length === 4) {
            parts[3] = 'x';
            return parts.join('.');
        }
        return null;
    }
    truncateUserAgent(ua, max = 256) {
        if (!ua)
            return null;
        return ua.length > max ? ua.substring(0, max) : ua;
    }
    computeIntegrity(payload) {
        const stable = JSON.stringify(this.sortObjectKeys(payload));
        const toHash = `${stable}::${this.signingSecret}`;
        return crypto.createHash('sha256').update(toHash).digest('hex');
    }
    sortObjectKeys(obj) {
        if (obj === null || typeof obj !== 'object' || Array.isArray(obj))
            return obj;
        return Object.keys(obj)
            .sort()
            .reduce((acc, k) => {
            acc[k] = this.sortObjectKeys(obj[k]);
            return acc;
        }, {});
    }
    async logEvent(type, opts = {}) {
        const { userId = null, tenantId = null, metadata = {}, ipAddress = null, userAgent = null, severity = 'INFO', } = opts;
        try {
            const created = await this.prisma.$transaction(async (tx) => {
                const last = await tx.event.findFirst({
                    orderBy: { createdAt: 'desc' },
                    select: { integrityHash: true },
                });
                const prevHash = last?.integrityHash ?? null;
                const sortedMetadata = metadata ? this.sortObjectKeys(metadata) : {};
                const eventDataForHash = {
                    userId,
                    tenantId,
                    type,
                    severity,
                    metadata: sortedMetadata,
                    ipAddress: this.maskIp(ipAddress),
                    userAgent: this.truncateUserAgent(userAgent),
                    prevHash,
                    createdAt: new Date().toISOString(),
                };
                const integrityHash = this.computeIntegrity(eventDataForHash);
                const row = await tx.event.create({
                    data: {
                        userId,
                        tenantId,
                        type,
                        severity,
                        sessionId: metadata.sessionId ?? null,
                        familyId: metadata.familyId ?? null,
                        reason: metadata.reason ?? null,
                        metadata: sortedMetadata,
                        ipAddress: this.maskIp(ipAddress),
                        userAgent: this.truncateUserAgent(userAgent),
                        integrityHash,
                        prevHash,
                    },
                });
                return row;
            });
            setImmediate(() => {
                try {
                    const emitted = {
                        id: created.id,
                        type: created.type,
                        severity: created.severity,
                        userId: created.userId ?? null,
                        tenantId: created.tenantId ?? null,
                        ipAddress: created.ipAddress ?? null,
                        userAgent: created.userAgent ?? null,
                        sessionId: created.sessionId ?? null,
                        familyId: created.familyId ?? null,
                        reason: created.reason ?? null,
                        metadata: created.metadata ?? {},
                        integrityHash: created.integrityHash,
                        prevHash: created.prevHash,
                        createdAt: created.createdAt,
                    };
                    this.eventSubject.next(emitted);
                }
                catch (emitErr) {
                    this.logger.warn('Failed to emit SecurityEvent', emitErr.message);
                }
            });
            return created;
        }
        catch (err) {
            if (err instanceof Error) {
                this.logger.warn('[EVENT_LOG_ERROR]', err.stack);
            }
            else {
                this.logger.warn('[EVENT_LOG_ERROR]', { err });
            }
            return null;
        }
    }
    async verifyChain() {
        const events = await this.prisma.event.findMany({
            orderBy: { createdAt: 'asc' },
            select: {
                id: true,
                integrityHash: true,
                prevHash: true,
                userId: true,
                tenantId: true,
                type: true,
                severity: true,
                reason: true,
                metadata: true,
                ipAddress: true,
                userAgent: true,
                createdAt: true,
            },
        });
        if (events.length === 0) {
            return { valid: true, total: 0 };
        }
        let prevHash = null;
        for (let i = 0; i < events.length; i++) {
            const e = events[i];
            const sortedMetadata = e.metadata ? this.sortObjectKeys(e.metadata) : {};
            const payload = {
                userId: e.userId ?? null,
                tenantId: e.tenantId ?? null,
                type: e.type,
                severity: e.severity,
                metadata: sortedMetadata,
                ipAddress: e.ipAddress ?? null,
                userAgent: e.userAgent ?? null,
                prevHash,
            };
            const recomputed = this.computeIntegrity(payload);
            if (recomputed !== e.integrityHash || e.prevHash !== prevHash) {
                this.logger.error(`Integrity chain broken at index ${i} id=${e.id}`);
                return { valid: false, brokenIndex: i, total: events.length };
            }
            prevHash = e.integrityHash;
        }
        this.logger.log(`Integrity chain verified: ${events.length} events`);
        return { valid: true, total: events.length };
    }
    async findRecent(limit = 50, offset = 0, from, to) {
        const where = {};
        if (from)
            where.createdAt = { gte: new Date(from) };
        if (to)
            where.createdAt = { ...where.createdAt, lte: new Date(to) };
        const [events, total] = await Promise.all([
            this.prisma.event.findMany({
                where,
                orderBy: { createdAt: 'desc' },
                take: limit,
                skip: offset,
                select: {
                    id: true,
                    userId: true,
                    tenantId: true,
                    type: true,
                    severity: true,
                    sessionId: true,
                    familyId: true,
                    reason: true,
                    metadata: true,
                    ipAddress: true,
                    userAgent: true,
                    integrityHash: true,
                    prevHash: true,
                    createdAt: true,
                },
            }),
            this.prisma.event.count({ where }),
        ]);
        return this.attachUserTenant(events, total, limit, offset);
    }
    async findByType(type, limit = 50, offset = 0, from, to) {
        const where = { type };
        if (from)
            where.createdAt = { gte: new Date(from) };
        if (to)
            where.createdAt = { ...where.createdAt, lte: new Date(to) };
        const [events, total] = await Promise.all([
            this.prisma.event.findMany({
                where,
                orderBy: { createdAt: 'desc' },
                take: limit,
                skip: offset,
                select: {
                    id: true,
                    userId: true,
                    tenantId: true,
                    type: true,
                    severity: true,
                    sessionId: true,
                    familyId: true,
                    reason: true,
                    metadata: true,
                    ipAddress: true,
                    userAgent: true,
                    integrityHash: true,
                    prevHash: true,
                    createdAt: true,
                },
            }),
            this.prisma.event.count({ where }),
        ]);
        return this.attachUserTenant(events, total, limit, offset);
    }
    async findByUser(userId, limit = 50, offset = 0, from, to) {
        const where = { userId };
        if (from)
            where.createdAt = { gte: new Date(from) };
        if (to)
            where.createdAt = { ...where.createdAt, lte: new Date(to) };
        const [events, total] = await Promise.all([
            this.prisma.event.findMany({
                where,
                orderBy: { createdAt: 'desc' },
                take: limit,
                skip: offset,
                select: {
                    id: true,
                    userId: true,
                    tenantId: true,
                    type: true,
                    severity: true,
                    sessionId: true,
                    familyId: true,
                    reason: true,
                    metadata: true,
                    ipAddress: true,
                    userAgent: true,
                    integrityHash: true,
                    prevHash: true,
                    createdAt: true,
                },
            }),
            this.prisma.event.count({ where }),
        ]);
        return this.attachUserTenant(events, total, limit, offset);
    }
    async queryEvents(params) {
        const { tenantId, type, userId, sessionId, startDate, endDate, limit = 50, offset = 0, } = params;
        const where = {};
        if (tenantId)
            where.tenantId = tenantId;
        if (type)
            where.type = type;
        if (userId)
            where.userId = userId;
        if (sessionId)
            where.sessionId = sessionId;
        if (startDate || endDate) {
            where.createdAt = {
                ...(startDate && { gte: startDate }),
                ...(endDate && { lte: endDate }),
            };
        }
        const [events, total] = await Promise.all([
            this.prisma.event.findMany({
                where,
                orderBy: { createdAt: 'desc' },
                take: limit,
                skip: offset,
                select: {
                    id: true,
                    userId: true,
                    tenantId: true,
                    type: true,
                    severity: true,
                    sessionId: true,
                    reason: true,
                    metadata: true,
                    ipAddress: true,
                    userAgent: true,
                    createdAt: true,
                },
            }),
            this.prisma.event.count({ where }),
        ]);
        return this.attachUserTenant(events, total, limit, offset);
    }
    async attachUserTenant(events, total, limit, offset) {
        const userIds = [
            ...new Set(events.map((e) => e.userId).filter(Boolean)),
        ];
        const tenantIds = [
            ...new Set(events.map((e) => e.tenantId).filter(Boolean)),
        ];
        const users = userIds.length
            ? await this.prisma.user.findMany({
                where: { id: { in: userIds } },
                select: { id: true, phone: true, name: true },
            })
            : [];
        const tenants = tenantIds.length
            ? await this.prisma.tenant.findMany({
                where: { id: { in: tenantIds } },
                select: { id: true, name: true, slug: true },
            })
            : [];
        const userMap = new Map(users.map((u) => [u.id, u]));
        const tenantMap = new Map(tenants.map((t) => [t.id, t]));
        return {
            data: events.map((event) => ({
                ...event,
                user: event.userId ? userMap.get(event.userId) || null : null,
                tenant: event.tenantId ? tenantMap.get(event.tenantId) || null : null,
            })),
            meta: { total, limit, offset, hasNext: offset + limit < total },
        };
    }
};
exports.EventLogService = EventLogService;
exports.EventLogService = EventLogService = EventLogService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        config_1.ConfigService])
], EventLogService);
//# sourceMappingURL=event.service.js.map