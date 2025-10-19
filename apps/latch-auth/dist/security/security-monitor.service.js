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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var SecurityMonitoringService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityMonitoringService = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const event_service_1 = require("../events/event.service");
const Sentry = __importStar(require("@sentry/node"));
const axios_1 = __importDefault(require("axios"));
let SecurityMonitoringService = SecurityMonitoringService_1 = class SecurityMonitoringService {
    events;
    config;
    logger = new common_1.Logger(SecurityMonitoringService_1.name);
    webhookUrl;
    windowMinutes;
    thresholds = {
        TOKEN_REUSE: 5,
        SECURITY_CSRF_MISMATCH: 3,
        AUTH_JWT_FAILURE: 10,
        REFRESH_FAILED: 5,
        OTP_FAILED: 5,
    };
    eventBuckets = new Map();
    cleanupInterval;
    constructor(events, config) {
        this.events = events;
        this.config = config;
        this.webhookUrl = this.config.get('SECURITY_ALERT_WEBHOOK_URL');
        if (this.webhookUrl && !this.webhookUrl.startsWith('https://')) {
            this.logger.warn('SECURITY_ALERT_WEBHOOK_URL should use HTTPS for security');
        }
        this.windowMinutes = this.config.get('SECURITY_ALERT_WINDOW_MINUTES', 60);
        Object.keys(this.thresholds).forEach((key) => {
            const envValue = this.config.get(`SECURITY_ALERT_THRESHOLD_${key}`);
            if (envValue && key in this.thresholds) {
                this.thresholds[key] = envValue;
            }
        });
    }
    onModuleInit() {
        this.events.event$.subscribe((event) => this.handleEvent(event));
        this.cleanupInterval = setInterval(() => this.pruneOldEntries(), 5 * 60 * 1000);
        this.logger.log('SecurityMonitoringService initialized');
    }
    onModuleDestroy() {
        if (this.cleanupInterval)
            clearInterval(this.cleanupInterval);
    }
    handleEvent(event) {
        if (!event.integrityHash) {
            this.logger.warn(`Event ${event.id} missing integrityHash, skipping monitoring`);
            return;
        }
        const key = this.getAggregationKey(event);
        if (!key)
            return;
        const now = Date.now();
        const bucketKey = `${event.type}:${key}`;
        const timestamps = this.eventBuckets.get(bucketKey) ?? [];
        timestamps.push(now);
        this.eventBuckets.set(bucketKey, timestamps);
        this.evaluateThreshold(event.type, bucketKey, timestamps);
        this.limitBuckets();
    }
    getAggregationKey(event) {
        switch (event.type) {
            case 'TOKEN_REUSE':
            case 'REFRESH_FAILED':
                return event.userId ?? null;
            case 'SECURITY_CSRF_MISMATCH':
            case 'AUTH_JWT_FAILURE':
            case 'OTP_FAILED':
                return event.ipAddress ?? null;
            default:
                this.logger.warn(`Unknown event type for aggregation: ${event.type}`);
                return null;
        }
    }
    evaluateThreshold(type, bucketKey, timestamps) {
        const cutoff = Date.now() - this.windowMinutes * 60 * 1000;
        const recent = timestamps.filter((t) => t >= cutoff);
        this.eventBuckets.set(bucketKey, recent);
        const limit = this.thresholds[type] ?? 0;
        if (recent.length > limit) {
            this.triggerAlert(type, bucketKey, recent.length).catch((err) => {
                this.logger.error(`Security alert delivery failed for ${type}:`, err);
            });
            this.eventBuckets.set(bucketKey, []);
        }
    }
    pruneOldEntries() {
        const cutoff = Date.now() - this.windowMinutes * 60 * 1000;
        for (const [key, timestamps] of this.eventBuckets) {
            const recent = timestamps.filter((t) => t >= cutoff);
            if (recent.length === 0)
                this.eventBuckets.delete(key);
            else
                this.eventBuckets.set(key, recent);
        }
    }
    limitBuckets(maxBuckets = 10_000) {
        if (this.eventBuckets.size > maxBuckets) {
            this.logger.warn(`eventBuckets exceeded max ${maxBuckets}, trimming oldest entries`);
            const keys = Array.from(this.eventBuckets.keys()).slice(0, this.eventBuckets.size - maxBuckets);
            keys.forEach((k) => this.eventBuckets.delete(k));
        }
    }
    async postWithRetry(url, data, maxRetries = 2) {
        for (let i = 0; i <= maxRetries; i++) {
            try {
                return await axios_1.default.post(url, data);
            }
            catch (err) {
                this.logger.error(`Webhook attempt ${i + 1}/${maxRetries + 1} failed: ${err.message}`);
                if (i === maxRetries)
                    throw err;
                await new Promise((res) => setTimeout(res, 1000 * 2 ** i));
            }
        }
    }
    async triggerAlert(type, key, count) {
        const message = `⚠️ Security alert: ${count} ${type} events detected`;
        this.logger.warn(message);
        Sentry.captureMessage(`[${type}] ${message}`, 'warning');
        if (this.webhookUrl) {
            await this.postWithRetry(this.webhookUrl, {
                type,
                key,
                count,
                windowMinutes: this.windowMinutes,
            });
        }
    }
    getSecurityStatus() {
        const status = {};
        for (const [bucketKey, timestamps] of this.eventBuckets) {
            const [type] = bucketKey.split(':');
            status[type] = (status[type] || 0) + timestamps.length;
        }
        return status;
    }
};
exports.SecurityMonitoringService = SecurityMonitoringService;
exports.SecurityMonitoringService = SecurityMonitoringService = SecurityMonitoringService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [event_service_1.EventLogService,
        config_1.ConfigService])
], SecurityMonitoringService);
//# sourceMappingURL=security-monitor.service.js.map