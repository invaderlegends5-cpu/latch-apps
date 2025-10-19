"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeIp = normalizeIp;
exports.normalizeUserAgent = normalizeUserAgent;
function normalizeIp(ip) {
    if (!ip)
        return null;
    if (ip.startsWith('::ffff:')) {
        return ip.substring(7);
    }
    return ip;
}
function normalizeUserAgent(ua) {
    if (!ua)
        return null;
    const trimmed = ua.trim();
    return trimmed.length > 200 ? trimmed.substring(0, 200) : trimmed;
}
//# sourceMappingURL=normalize.util.js.map