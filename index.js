// index.js - PRODUCTION READY - FULL BUTTON-BASED VERSION
// ============================================
// 🚀 Bot Telegram Produk Digital - Full Button Interface
// Version: 4.0.0 - Button-Based Edition
// Author: JeeyHosting
// ============================================

const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const fs = require('fs').promises;
const fsSync = require('fs');
const fse = require('fs-extra');
const path = require('path');
const QRCode = require('qrcode');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const lockfile = require('proper-lockfile');
const config = require('./config.js');

// ============================================
// 🔧 UTILITIES & HELPERS
// ============================================

class Logger {
    static log(level, message, data = {}) {
        if (config.FEATURES.ACTIVITY_LOG_ENABLED) {
            const timestamp = new Date().toISOString();
            const logEntry = {
                timestamp,
                level,
                message,
                data
            };
            console.log(`[${timestamp}] [${level}] ${message}`, data);
        }
    }

    static info(message, data) {
        this.log('INFO', message, data);
    }

    static error(message, data) {
        this.log('ERROR', message, data);
    }

    static warn(message, data) {
        this.log('WARN', message, data);
    }

    static security(message, data) {
        this.log('SECURITY', message, data);
    }
}

class InputValidator {
    static sanitizeString(input) {
        if (typeof input !== 'string') return '';
        return input.trim().replace(/[<>]/g, '');
    }

    static validateNumeric(input, min = 0, max = Number.MAX_SAFE_INTEGER) {
        const num = parseInt(input);
        if (isNaN(num)) return { valid: false, error: 'Bukan angka valid' };
        if (num < min) return { valid: false, error: `Minimal ${min}` };
        if (num > max) return { valid: false, error: `Maksimal ${max}` };
        return { valid: true, value: num };
    }

    static validateUserId(userId) {
        const validation = this.validateNumeric(userId, 1);
        if (!validation.valid) return validation;
        
        const userIdStr = userId.toString();
        if (!/^\d+$/.test(userIdStr)) {
            return { valid: false, error: 'User ID hanya boleh angka' };
        }
        return { valid: true, value: userId };
    }

    static validateAmount(amount) {
        return this.validateNumeric(amount, 100, 1000000000);
    }

    static threeLayerValidation(input, type = 'string') {
        let sanitized = input;
        if (type === 'numeric') {
            if (!/^\d+$/.test(input.toString())) {
                return { valid: false, error: 'Hanya angka yang diperbolehkan' };
            }
            sanitized = parseInt(input);
        } else if (type === 'alphanumeric') {
            if (!/^[a-zA-Z0-9_-]+$/.test(input)) {
                return { valid: false, error: 'Hanya huruf, angka, underscore, dan dash' };
            }
        }

        if (type === 'numeric' && typeof sanitized !== 'number') {
            return { valid: false, error: 'Tipe data harus numeric' };
        }
        if (type === 'string' && typeof sanitized !== 'string') {
            return { valid: false, error: 'Tipe data harus string' };
        }

        if (type === 'string') {
            sanitized = this.sanitizeString(sanitized);
            const sqlKeywords = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'SELECT', 'UNION'];
            const upperInput = sanitized.toUpperCase();
            for (const keyword of sqlKeywords) {
                if (upperInput.includes(keyword)) {
                    return { valid: false, error: 'Input mengandung karakter terlarang' };
                }
            }
        }

        return { valid: true, value: sanitized };
    }
}

// ============================================
// 🔐 SECURITY MANAGER
// ============================================

class SecurityManager {
    constructor(encryptionKey) {
        this.algorithm = config.ENCRYPTION_ALGORITHM;
        this.key = crypto.scryptSync(encryptionKey, 'salt', 32);
        this.rateLimits = new Map();
        this.failedAttempts = new Map();
        this.fraudScores = new Map();
        this.processedHashes = new Set();
    }

    encrypt(text) {
        if (!config.FEATURES.ENCRYPTION_ENABLED) return text;
        try {
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            return iv.toString('hex') + ':' + encrypted;
        } catch (error) {
            Logger.error('Encryption failed', { error: error.message });
            return text;
        }
    }

    decrypt(encryptedText) {
        if (!config.FEATURES.ENCRYPTION_ENABLED) return encryptedText;
        try {
            const parts = encryptedText.split(':');
            if (parts.length !== 2) return null;
            
            const iv = Buffer.from(parts[0], 'hex');
            const encrypted = parts[1];
            const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            Logger.error('Decryption failed', { error: error.message });
            return null;
        }
    }

    hashData(data) {
        return crypto.createHash(config.HASH_ALGORITHM).update(data.toString()).digest('hex');
    }

    hashPassword(password) {
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.scryptSync(password, salt, 64).toString('hex');
        return `${salt}:${hash}`;
    }

    verifyPassword(password, storedHash) {
        try {
            const [salt, hash] = storedHash.split(':');
            const hashToVerify = crypto.scryptSync(password, salt, 64).toString('hex');
            return hash === hashToVerify;
        } catch (error) {
            return false;
        }
    }

    checkRateLimit(userId) {
        if (!config.FEATURES.RATE_LIMITING_ENABLED) return { allowed: true };

        const now = Date.now();
        const userKey = `rate_${userId}`;
        
        if (!this.rateLimits.has(userKey)) {
            this.rateLimits.set(userKey, []);
        }

        const requests = this.rateLimits.get(userKey);
        const recentRequests = requests.filter(time => now - time < config.RATE_LIMIT_WINDOW);
        
        if (recentRequests.length >= config.MAX_REQUESTS_PER_MINUTE) {
            this.incrementFailedAttempts(userId, 'RATE_LIMIT_EXCEEDED');
            Logger.security('Rate limit exceeded', { userId, requests: recentRequests.length });
            return { 
                allowed: false, 
                message: config.ERROR_MESSAGES.RATE_LIMIT 
            };
        }

        recentRequests.push(now);
        this.rateLimits.set(userKey, recentRequests);
        return { allowed: true };
    }

    incrementFailedAttempts(userId, reason) {
        const key = `failed_${userId}`;
        if (!this.failedAttempts.has(key)) {
            this.failedAttempts.set(key, []);
        }

        const attempts = this.failedAttempts.get(key);
        attempts.push({ timestamp: Date.now(), reason });
        this.failedAttempts.set(key, attempts);

        const recentAttempts = attempts.filter(a => 
            Date.now() - a.timestamp < config.FRAUD_DETECTION.FAILED_ATTEMPT_WINDOW
        );

        if (recentAttempts.length >= config.FRAUD_DETECTION.FAILED_ATTEMPT_LIMIT) {
            this.addFraudScore(userId, 'EXCESSIVE_FAILED_ATTEMPTS', 2);
        }
    }

    addFraudScore(userId, reason, score = 1) {
        if (!config.FEATURES.FRAUD_DETECTION_ENABLED) return;

        const key = `fraud_${userId}`;
        if (!this.fraudScores.has(key)) {
            this.fraudScores.set(key, []);
        }

        const scores = this.fraudScores.get(key);
        scores.push({ timestamp: Date.now(), reason, score });
        this.fraudScores.set(key, scores);

        const recentScores = scores.filter(s => 
            Date.now() - s.timestamp < config.FRAUD_DETECTION.FRAUD_SCORE_WINDOW
        );

        const totalScore = recentScores.reduce((sum, s) => sum + s.score, 0);

        Logger.security('Fraud score added', { 
            userId, 
            reason, 
            score, 
            totalScore 
        });

        if (totalScore >= config.FRAUD_DETECTION.FRAUD_SCORE_THRESHOLD) {
            Logger.security('Fraud threshold reached - auto ban triggered', { userId, totalScore });
            return { shouldBan: true, totalScore };
        }

        return { shouldBan: false, totalScore };
    }

    getFraudScore(userId) {
        const key = `fraud_${userId}`;
        if (!this.fraudScores.has(key)) return 0;

        const scores = this.fraudScores.get(key);
        const recentScores = scores.filter(s => 
            Date.now() - s.timestamp < config.FRAUD_DETECTION.FRAUD_SCORE_WINDOW
        );

        return recentScores.reduce((sum, s) => sum + s.score, 0);
    }

    hasProcessedTransaction(transactionId) {
        const hash = this.hashData(transactionId);
        return this.processedHashes.has(hash);
    }

    markTransactionProcessed(transactionId) {
        const hash = this.hashData(transactionId);
        this.processedHashes.add(hash);
        
        setTimeout(() => {
            this.processedHashes.delete(hash);
        }, 24 * 60 * 60 * 1000);
    }

    async validateFile(fileBuffer, expectedType = 'image') {
        try {
            if (fileBuffer.length > config.MAX_PRODUCT_FILE_SIZE) {
                return { valid: false, error: config.ERROR_MESSAGES.FILE_TOO_LARGE };
            }

            const magicBytes = fileBuffer.slice(0, 4).toString('hex');
            
            if (expectedType === 'image') {
                const imageSignatures = {
                    'ffd8ffe0': 'jpeg',
                    'ffd8ffe1': 'jpeg',
                    'ffd8ffe2': 'jpeg',
                    '89504e47': 'png',
                    '47494638': 'gif',
                    '52494646': 'webp'
                };

                const signature = Object.keys(imageSignatures).find(sig => 
                    magicBytes.startsWith(sig)
                );

                if (!signature) {
                    return { valid: false, error: 'Invalid image file signature' };
                }

                try {
                    const sizeOf = require('image-size');
                    const dimensions = sizeOf(fileBuffer);
                    
                    if (dimensions.width < config.MIN_IMAGE_WIDTH || 
                        dimensions.height < config.MIN_IMAGE_HEIGHT) {
                        return { 
                            valid: false, 
                            error: `Image minimal ${config.MIN_IMAGE_WIDTH}x${config.MIN_IMAGE_HEIGHT}px` 
                        };
                    }
                } catch (dimError) {
                    Logger.warn('Could not validate image dimensions', { error: dimError.message });
                }
            }

            if (fileBuffer.length < 1000 && magicBytes.startsWith('504b0304')) {
                return { valid: false, error: 'Suspicious compressed file detected' };
            }

            return { valid: true };
        } catch (error) {
            Logger.error('File validation error', { error: error.message });
            return { valid: false, error: 'File validation failed' };
        }
    }

    validateWebhookSignature(payload, signature, timestamp) {
        try {
            const now = Date.now();
            const payloadTimestamp = parseInt(timestamp);
            
            if (Math.abs(now - payloadTimestamp) > config.WEBHOOK_TIMESTAMP_TOLERANCE) {
                Logger.security('Webhook timestamp too old', { timestamp, now });
                return false;
            }

            const expectedSignature = crypto
                .createHmac('sha256', config.WEBHOOK_SECRET)
                .update(`${timestamp}.${JSON.stringify(payload)}`)
                .digest('hex');

            return crypto.timingSafeEqual(
                Buffer.from(signature),
                Buffer.from(expectedSignature)
            );
        } catch (error) {
            Logger.error('Webhook signature validation failed', { error: error.message });
            return false;
        }
    }

    cleanup() {
        const now = Date.now();

        for (const [key, requests] of this.rateLimits.entries()) {
            const recent = requests.filter(time => now - time < config.RATE_LIMIT_WINDOW);
            if (recent.length === 0) {
                this.rateLimits.delete(key);
            } else {
                this.rateLimits.set(key, recent);
            }
        }

        for (const [key, attempts] of this.failedAttempts.entries()) {
            const recent = attempts.filter(a => 
                now - a.timestamp < config.FRAUD_DETECTION.FAILED_ATTEMPT_WINDOW
            );
            if (recent.length === 0) {
                this.failedAttempts.delete(key);
            } else {
                this.failedAttempts.set(key, recent);
            }
        }

        for (const [key, scores] of this.fraudScores.entries()) {
            const recent = scores.filter(s => 
                now - s.timestamp < config.FRAUD_DETECTION.FRAUD_SCORE_WINDOW
            );
            if (recent.length === 0) {
                this.fraudScores.delete(key);
            } else {
                this.fraudScores.set(key, recent);
            }
        }

        Logger.info('Security manager cleanup completed');
    }
}

// ============================================
// 💾 ATOMIC FILE MANAGER WITH LOCKING
// ============================================

class AtomicFileManager {
    constructor() {
        this.locks = new Map();
        this.writeQueue = new Map();
    }

    async acquireLock(filePath, timeout = 5000) {
        const absolutePath = path.resolve(filePath);
        const lockKey = absolutePath;
        
        const startTime = Date.now();
        
        while (this.locks.has(lockKey)) {
            if (Date.now() - startTime > timeout) {
                throw new Error(`Lock timeout for ${filePath}`);
            }
            await new Promise(resolve => setTimeout(resolve, 10));
        }
        
        this.locks.set(lockKey, { acquiredAt: Date.now(), pid: process.pid });
        return lockKey;
    }

    async releaseLock(lockKey) {
        this.locks.delete(lockKey);
    }

    async atomicWrite(filePath, data, options = {}) {
        const lockKey = await this.acquireLock(filePath);
        
        try {
            await fse.ensureDir(path.dirname(filePath));

            if (config.BACKUP_ENABLED && await fse.pathExists(filePath)) {
                const backupPath = `${filePath}.backup`;
                await fse.copy(filePath, backupPath);
            }

            const tempFile = `${filePath}.${Date.now()}.tmp`;
            const jsonData = JSON.stringify(data, null, 2);
            await fs.writeFile(tempFile, jsonData, 'utf8');

            const writtenData = await fs.readFile(tempFile, 'utf8');
            JSON.parse(writtenData);

            await fs.rename(tempFile, filePath);

            if (config.BACKUP_ENABLED) {
                const backupPath = `${filePath}.backup`;
                if (await fse.pathExists(backupPath)) {
                    await fse.remove(backupPath);
                }
            }

            Logger.info('Atomic write successful', { filePath });
            return true;

        } catch (error) {
            Logger.error('Atomic write failed', { filePath, error: error.message });

            if (config.BACKUP_ENABLED) {
                const backupPath = `${filePath}.backup`;
                if (await fse.pathExists(backupPath)) {
                    await fse.copy(backupPath, filePath);
                    Logger.info('Restored from backup', { filePath });
                }
            }

            throw error;
        } finally {
            await this.releaseLock(lockKey);
        }
    }

    async atomicRead(filePath, defaultValue = null) {
        const lockKey = await this.acquireLock(filePath, 2000);
        
        try {
            if (!await fse.pathExists(filePath)) {
                return defaultValue;
            }

            const data = await fs.readFile(filePath, 'utf8');
            const parsed = JSON.parse(data);
            return parsed;

        } catch (error) {
            Logger.error('Atomic read failed', { filePath, error: error.message });

            if (config.BACKUP_ENABLED) {
                const backupPath = `${filePath}.backup`;
                if (await fse.pathExists(backupPath)) {
                    try {
                        const backupData = await fs.readFile(backupPath, 'utf8');
                        const parsed = JSON.parse(backupData);
                        Logger.warn('Read from backup', { filePath });
                        return parsed;
                    } catch (backupError) {
                        Logger.error('Backup read also failed', { backupError: backupError.message });
                    }
                }
            }

            return defaultValue;

        } finally {
            await this.releaseLock(lockKey);
        }
    }

    async safeDelete(filePath) {
        const lockKey = await this.acquireLock(filePath);
        
        try {
            if (await fse.pathExists(filePath)) {
                await fse.remove(filePath);
                Logger.info('File deleted', { filePath });
            }
        } finally {
            await this.releaseLock(lockKey);
        }
    }
}

// ============================================
// 🗄️ DATABASE MANAGER
// ============================================

class DatabaseManager {
    constructor(security) {
        this.fileManager = new AtomicFileManager();
        this.security = security;
        this.baseDir = config.DATABASE_DIR;
        this.cache = new Map();
        this.cacheTimestamps = new Map();
        
        this.paths = {
            users: {
                index: path.join(this.baseDir, 'users/users_index.json'),
                profileDir: path.join(this.baseDir, 'users/users_profile'),
                securityDir: path.join(this.baseDir, 'users/users_security'),
                sessionsDir: path.join(this.baseDir, 'users/users_sessions'),
                activityDir: path.join(this.baseDir, 'users/users_activity'),
                statsDir: path.join(this.baseDir, 'users/users_stats')
            },
            products: {
                index: path.join(this.baseDir, 'products/products_index.json'),
                detailDir: path.join(this.baseDir, 'products/products_detail'),
                inventoryDir: path.join(this.baseDir, 'products/products_inventory'),
                ratingDir: path.join(this.baseDir, 'products/products_rating'),
                metaDir: path.join(this.baseDir, 'products/products_meta')
            },
            transactions: {
                index: path.join(this.baseDir, 'transactions/transactions_index.json'),
                depositDir: path.join(this.baseDir, 'transactions/transactions_deposit'),
                purchaseDir: path.join(this.baseDir, 'transactions/transactions_purchase'),
                refundDir: path.join(this.baseDir, 'transactions/transactions_refund'),
                pending: path.join(this.baseDir, 'transactions/transactions_pending.json')
            },
            payments: {
                qrisDir: path.join(this.baseDir, 'payments/payments_qris'),
                manualDir: path.join(this.baseDir, 'payments/payments_manual'),
                failed: path.join(this.baseDir, 'payments/payments_failed.json'),
                webhookLog: path.join(this.baseDir, 'payments/payments_webhook_log.json')
            },
            orders: {
                index: path.join(this.baseDir, 'orders/orders_index.json'),
                detailDir: path.join(this.baseDir, 'orders/orders_detail'),
                deliveryDir: path.join(this.baseDir, 'orders/orders_delivery'),
                statusTracking: path.join(this.baseDir, 'orders/orders_status_tracking.json')
            },
            security: {
                bannedUsers: path.join(this.baseDir, 'security/banned_users.json'),
                suspendedUsers: path.join(this.baseDir, 'security/suspended_users.json'),
                fraudDetection: path.join(this.baseDir, 'security/fraud_detection.json'),
                rateLimits: path.join(this.baseDir, 'security/rate_limits.json'),
                securityLog: path.join(this.baseDir, 'security/security_log.json'),
                failedLogins: path.join(this.baseDir, 'security/failed_logins.json'),
                suspiciousActivity: path.join(this.baseDir, 'security/suspicious_activity.json')
            },
            broadcast: {
                users: path.join(this.baseDir, 'broadcast/broadcast_users.json'),
                historyDir: path.join(this.baseDir, 'broadcast/broadcast_history'),
                stats: path.join(this.baseDir, 'broadcast/broadcast_stats.json')
            },
            admin: {
                actions: path.join(this.baseDir, 'admin/admin_actions.json'),
                approvalsDir: path.join(this.baseDir, 'admin/admin_approvals'),
                settings: path.join(this.baseDir, 'admin/admin_settings.json')
            },
            system: {
                errorLog: path.join(this.baseDir, 'system/error_log.json'),
                systemHealth: path.join(this.baseDir, 'system/system_health.json'),
                backupSchedule: path.join(this.baseDir, 'system/backup_schedule.json'),
                dataCleanupLog: path.join(this.baseDir, 'system/data_cleanup_log.json'),
                apiUsage: path.join(this.baseDir, 'system/api_usage.json')
            },
            channel: {
                testify: path.join(this.baseDir, 'channel/channel_testify.json'),
                failedSend: path.join(this.baseDir, 'channel/channel_failed_send.json'),
                config: path.join(this.baseDir, 'channel/channel_config.json')
            },
            cache: {
                products: path.join(this.baseDir, 'cache/cache_products.json'),
                userBalance: path.join(this.baseDir, 'cache/cache_user_balance.json'),
                stats: path.join(this.baseDir, 'cache/cache_stats.json')
            }
        };
    }

    async initialize() {
        try {
            Logger.info('Initializing database structure...');

            const allDirs = [];
            const processObject = (obj) => {
                for (const [key, value] of Object.entries(obj)) {
                    if (typeof value === 'string' && key.endsWith('Dir')) {
                        allDirs.push(value);
                    } else if (typeof value === 'object') {
                        processObject(value);
                    }
                }
            };
            processObject(this.paths);

            for (const dir of allDirs) {
                await fse.ensureDir(dir);
            }

            const jsonFiles = [
                { path: this.paths.users.index, default: [] },
                { path: this.paths.products.index, default: [] },
                { path: this.paths.transactions.index, default: [] },
                { path: this.paths.transactions.pending, default: [] },
                { path: this.paths.payments.failed, default: [] },
                { path: this.paths.payments.webhookLog, default: [] },
                { path: this.paths.orders.index, default: [] },
                { path: this.paths.orders.statusTracking, default: {} },
                { path: this.paths.security.bannedUsers, default: [] },
                { path: this.paths.security.suspendedUsers, default: [] },
                { path: this.paths.security.fraudDetection, default: {} },
                { path: this.paths.security.rateLimits, default: {} },
                { path: this.paths.security.securityLog, default: [] },
                { path: this.paths.security.failedLogins, default: {} },
                { path: this.paths.security.suspiciousActivity, default: [] },
                { path: this.paths.broadcast.users, default: [] },
                { path: this.paths.broadcast.stats, default: {} },
                { path: this.paths.admin.actions, default: [] },
                { path: this.paths.admin.settings, default: {} },
                { path: this.paths.system.errorLog, default: [] },
                { path: this.paths.system.systemHealth, default: {} },
                { path: this.paths.system.backupSchedule, default: [] },
                { path: this.paths.system.dataCleanupLog, default: [] },
                { path: this.paths.system.apiUsage, default: [] },
                { path: this.paths.channel.testify, default: [] },
                { path: this.paths.channel.failedSend, default: [] },
                { path: this.paths.channel.config, default: {} },
                { path: this.paths.cache.products, default: null },
                { path: this.paths.cache.userBalance, default: {} },
                { path: this.paths.cache.stats, default: null }
            ];

            for (const file of jsonFiles) {
                if (!await fse.pathExists(file.path)) {
                    await this.fileManager.atomicWrite(file.path, file.default);
                    Logger.info(`Created ${file.path}`);
                }
            }

            Logger.info('Database initialization completed successfully');
            return true;

        } catch (error) {
            Logger.error('Database initialization failed', { error: error.message });
            throw error;
        }
    }

    getCacheKey(category, id = null) {
        return id ? `${category}_${id}` : category;
    }

    isCacheValid(key, ttl) {
        if (!config.CACHE_ENABLED) return false;
        
        const timestamp = this.cacheTimestamps.get(key);
        if (!timestamp) return false;
        
        return (Date.now() - timestamp) < ttl;
    }

    setCache(key, data, ttl) {
        if (config.CACHE_ENABLED) {
            this.cache.set(key, data);
            this.cacheTimestamps.set(key, Date.now());
            
            setTimeout(() => {
                this.cache.delete(key);
                this.cacheTimestamps.delete(key);
            }, ttl);
        }
    }

    getCache(key) {
        return this.cache.get(key);
    }

    invalidateCache(pattern = null) {
        if (pattern) {
            for (const key of this.cache.keys()) {
                if (key.includes(pattern)) {
                    this.cache.delete(key);
                    this.cacheTimestamps.delete(key);
                }
            }
        } else {
            this.cache.clear();
            this.cacheTimestamps.clear();
        }
        Logger.info('Cache invalidated', { pattern });
    }

    async getUserProfile(userId) {
        const cacheKey = this.getCacheKey('user_profile', userId);
        
        if (this.isCacheValid(cacheKey, config.CACHE_TTL.USER_BALANCE)) {
            return this.getCache(cacheKey);
        }

        const filePath = path.join(this.paths.users.profileDir, `${userId}.json`);
        const profile = await this.fileManager.atomicRead(filePath, null);
        
        if (profile) {
            this.setCache(cacheKey, profile, config.CACHE_TTL.USER_BALANCE);
        }
        
        return profile;
    }

    async saveUserProfile(userId, profileData) {
        const filePath = path.join(this.paths.users.profileDir, `${userId}.json`);
        
        profileData.lastUpdated = new Date().toISOString();
        
        await this.fileManager.atomicWrite(filePath, profileData);
        
        await this.addToIndex('users', userId);
        
        this.invalidateCache(`user_profile_${userId}`);
        
        Logger.info('User profile saved', { userId });
    }

    async getUserSecurity(userId) {
        const filePath = path.join(this.paths.users.securityDir, `${userId}.json`);
        return await this.fileManager.atomicRead(filePath, {
            userId,
            passwordHash: null,
            twoFactorEnabled: false,
            failedLoginAttempts: 0,
            lastFailedLogin: null,
            securityQuestions: []
        });
    }

    async saveUserSecurity(userId, securityData) {
        const filePath = path.join(this.paths.users.securityDir, `${userId}.json`);
        
        if (securityData.passwordHash) {
            securityData.passwordHash = this.security.encrypt(securityData.passwordHash);
        }
        
        await this.fileManager.atomicWrite(filePath, securityData);
        Logger.info('User security saved', { userId });
    }

    async getUserSession(userId) {
        const filePath = path.join(this.paths.users.sessionsDir, `${userId}.json`);
        return await this.fileManager.atomicRead(filePath, null);
    }

    async saveUserSession(userId, sessionData) {
        const filePath = path.join(this.paths.users.sessionsDir, `${userId}.json`);
        
        sessionData.sessionId = this.security.encrypt(sessionData.sessionId || crypto.randomBytes(32).toString('hex'));
        sessionData.createdAt = sessionData.createdAt || new Date().toISOString();
        sessionData.expiresAt = new Date(Date.now() + config.SESSION_TIMEOUT).toISOString();
        
        await this.fileManager.atomicWrite(filePath, sessionData);
        Logger.info('User session saved', { userId });
    }

    async deleteUserSession(userId) {
        const filePath = path.join(this.paths.users.sessionsDir, `${userId}.json`);
        await this.fileManager.safeDelete(filePath);
        Logger.info('User session deleted', { userId });
    }

    async logUserActivity(userId, activity) {
        const filePath = path.join(this.paths.users.activityDir, `${userId}.json`);
        
        let activities = await this.fileManager.atomicRead(filePath, []);
        
        activities.push({
            timestamp: new Date().toISOString(),
            action: activity.action,
            details: activity.details || {},
            ipHash: activity.ipHash || null
        });
        
        if (activities.length > 1000) {
            activities = activities.slice(-1000);
        }
        
        await this.fileManager.atomicWrite(filePath, activities);
    }

    async getUserStats(userId) {
        const cacheKey = this.getCacheKey('user_stats', userId);
        
        if (this.isCacheValid(cacheKey, config.CACHE_TTL.BOT_STATS)) {
            return this.getCache(cacheKey);
        }

        const filePath = path.join(this.paths.users.statsDir, `${userId}.json`);
        const stats = await this.fileManager.atomicRead(filePath, {
            userId,
            totalPurchases: 0,
            totalSpent: 0,
            totalDeposits: 0,
            totalDeposited: 0,
            lastActivity: null,
            registeredAt: new Date().toISOString()
        });
        
        this.setCache(cacheKey, stats, config.CACHE_TTL.BOT_STATS);
        return stats;
    }

    async updateUserStats(userId, updates) {
        const filePath = path.join(this.paths.users.statsDir, `${userId}.json`);
        const stats = await this.getUserStats(userId);
        
        Object.assign(stats, updates);
        stats.lastActivity = new Date().toISOString();
        
        await this.fileManager.atomicWrite(filePath, stats);
        this.invalidateCache(`user_stats_${userId}`);
    }

    async getProduct(productId) {
        const cacheKey = this.getCacheKey('product', productId);
        
        if (this.isCacheValid(cacheKey, config.CACHE_TTL.PRODUCTS)) {
            return this.getCache(cacheKey);
        }

        const filePath = path.join(this.paths.products.detailDir, `${productId}.json`);
        const product = await this.fileManager.atomicRead(filePath, null);
        
        if (product) {
            this.setCache(cacheKey, product, config.CACHE_TTL.PRODUCTS);
        }
        
        return product;
    }

    async saveProduct(productId, productData) {
        const filePath = path.join(this.paths.products.detailDir, `${productId}.json`);
        
        productData.lastUpdated = new Date().toISOString();
        
        await this.fileManager.atomicWrite(filePath, productData);
        await this.addToIndex('products', productId);
        
        this.invalidateCache('products');
        this.invalidateCache(`product_${productId}`);
        
        Logger.info('Product saved', { productId });
    }

    async getProductInventory(productId) {
        const filePath = path.join(this.paths.products.inventoryDir, `${productId}.json`);
        return await this.fileManager.atomicRead(filePath, {
            productId,
            stock: 0,
            reserved: 0,
            sold: 0,
            lastRestocked: null
        });
    }

    async updateProductInventory(productId, updates) {
        const filePath = path.join(this.paths.products.inventoryDir, `${productId}.json`);
        const inventory = await this.getProductInventory(productId);
        
        Object.assign(inventory, updates);
        inventory.lastUpdated = new Date().toISOString();
        
        await this.fileManager.atomicWrite(filePath, inventory);
        this.invalidateCache(`product_${productId}`);
        
        Logger.info('Product inventory updated', { productId, updates });
    }

    async decrementProductStock(productId) {
        const filePath = path.join(this.paths.products.inventoryDir, `${productId}.json`);
        const inventory = await this.getProductInventory(productId);
        
        if (inventory.stock <= 0) {
            throw new Error('Stock empty');
        }
        
        inventory.stock -= 1;
        inventory.sold += 1;
        inventory.lastUpdated = new Date().toISOString();
        
        await this.fileManager.atomicWrite(filePath, inventory);
        this.invalidateCache(`product_${productId}`);
        
        return inventory;
    }

    async getAllProducts() {
        const cacheKey = 'all_products';
        
        if (this.isCacheValid(cacheKey, config.CACHE_TTL.PRODUCTS)) {
            return this.getCache(cacheKey);
        }

        const index = await this.fileManager.atomicRead(this.paths.products.index, []);
        const products = [];
        
        for (const productId of index) {
            const product = await this.getProduct(productId);
            if (product) {
                const inventory = await this.getProductInventory(productId);
                products.push({ ...product, stock: inventory.stock });
            }
        }
        
        this.setCache(cacheKey, products, config.CACHE_TTL.PRODUCTS);
        return products;
    }

    async deleteProduct(productId) {
        const detailPath = path.join(this.paths.products.detailDir, `${productId}.json`);
        const inventoryPath = path.join(this.paths.products.inventoryDir, `${productId}.json`);
        const metaPath = path.join(this.paths.products.metaDir, `${productId}.json`);
        
        await this.fileManager.safeDelete(detailPath);
        await this.fileManager.safeDelete(inventoryPath);
        await this.fileManager.safeDelete(metaPath);
        
        await this.removeFromIndex('products', productId);
        this.invalidateCache('products');
        
        Logger.info('Product deleted', { productId });
    }

    async saveTransaction(transactionId, transactionData, type = 'deposit') {
        const dirPath = type === 'deposit' ? 
            this.paths.transactions.depositDir : 
            this.paths.transactions.purchaseDir;
        
        const filePath = path.join(dirPath, `${transactionId}.json`);
        
        transactionData.transactionId = transactionId;
        transactionData.createdAt = transactionData.createdAt || new Date().toISOString();
        transactionData.hash = this.security.hashData(JSON.stringify(transactionData));
        
        await this.fileManager.atomicWrite(filePath, transactionData);
        await this.addToIndex('transactions', transactionId);
        
        Logger.info('Transaction saved', { transactionId, type });
    }

    async getTransaction(transactionId, type = 'deposit') {
        const dirPath = type === 'deposit' ? 
            this.paths.transactions.depositDir : 
            this.paths.transactions.purchaseDir;
        
        const filePath = path.join(dirPath, `${transactionId}.json`);
        return await this.fileManager.atomicRead(filePath, null);
    }

    async saveOrder(orderId, orderData) {
        const filePath = path.join(this.paths.orders.detailDir, `${orderId}.json`);
        
        orderData.orderId = orderId;
        orderData.createdAt = orderData.createdAt || new Date().toISOString();
        orderData.hash = this.security.hashData(JSON.stringify(orderData));
        
        await this.fileManager.atomicWrite(filePath, orderData);
        await this.addToIndex('orders', orderId);
        await this.updateOrderStatusTracking(orderId, orderData.status);
        
        Logger.info('Order saved', { orderId });
    }

    async getOrder(orderId) {
        const filePath = path.join(this.paths.orders.detailDir, `${orderId}.json`);
        return await this.fileManager.atomicRead(filePath, null);
    }

    async updateOrderStatusTracking(orderId, status) {
        const tracking = await this.fileManager.atomicRead(this.paths.orders.statusTracking, {});
        
        if (!tracking[status]) {
            tracking[status] = [];
        }
        
        if (!tracking[status].includes(orderId)) {
            tracking[status].push(orderId);
        }
        
        await this.fileManager.atomicWrite(this.paths.orders.statusTracking, tracking);
    }

    async getOrdersByStatus(status) {
        const tracking = await this.fileManager.atomicRead(this.paths.orders.statusTracking, {});
        const orderIds = tracking[status] || [];
        
        const orders = [];
        for (const orderId of orderIds) {
            const order = await this.getOrder(orderId);
            if (order && order.status === status) {
                orders.push(order);
            }
        }
        
        return orders;
    }

    async getBannedUsers() {
        return await this.fileManager.atomicRead(this.paths.security.bannedUsers, []);
    }

    async banUser(userId, reason, duration = config.BAN_DURATION, bannedBy = null) {
        const bannedUsers = await this.getBannedUsers();
        
        const banRecord = {
            userId: userId.toString(),
            reason,
            bannedAt: new Date().toISOString(),
            unbanAt: duration ? new Date(Date.now() + duration).toISOString() : null,
            duration,
            bannedBy,
            notes: ''
        };
        
        bannedUsers.push(banRecord);
        await this.fileManager.atomicWrite(this.paths.security.bannedUsers, bannedUsers);
        
        await this.logSecurityEvent({
            type: 'USER_BANNED',
            userId,
            reason,
            bannedBy
        });
        
        Logger.security('User banned', { userId, reason });
    }

    async unbanUser(userId) {
        let bannedUsers = await this.getBannedUsers();
        bannedUsers = bannedUsers.filter(b => b.userId !== userId.toString());
        
        await this.fileManager.atomicWrite(this.paths.security.bannedUsers, bannedUsers);
        
        await this.logSecurityEvent({
            type: 'USER_UNBANNED',
            userId
        });
        
        Logger.security('User unbanned', { userId });
    }

    async isUserBanned(userId) {
        const bannedUsers = await this.getBannedUsers();
        const banRecord = bannedUsers.find(b => b.userId === userId.toString());
        
        if (!banRecord) return { banned: false };
        
        if (banRecord.unbanAt) {
            const unbanTime = new Date(banRecord.unbanAt).getTime();
            if (Date.now() > unbanTime) {
                await this.unbanUser(userId);
                return { banned: false };
            }
        }
        
        return { 
            banned: true, 
            reason: banRecord.reason,
            unbanAt: banRecord.unbanAt 
        };
    }

    async logSecurityEvent(event) {
        if (!config.SECURITY_LOG_ENABLED) return;
        
        const log = await this.fileManager.atomicRead(this.paths.security.securityLog, []);
        
        log.push({
            timestamp: new Date().toISOString(),
            ...event
        });
        
        if (log.length > 10000) {
            log.splice(0, log.length - 10000);
        }
        
        await this.fileManager.atomicWrite(this.paths.security.securityLog, log);
    }

    async logSuspiciousActivity(userId, activityType, details = {}) {
        const activities = await this.fileManager.atomicRead(this.paths.security.suspiciousActivity, []);
        
        activities.push({
            timestamp: new Date().toISOString(),
            userId: userId.toString(),
            activityType,
            details
        });
        
        await this.fileManager.atomicWrite(this.paths.security.suspiciousActivity, activities);
        
        Logger.security('Suspicious activity logged', { userId, activityType });
    }

    async getBroadcastUsers() {
        return await this.fileManager.atomicRead(this.paths.broadcast.users, []);
    }

    async addBroadcastUser(userId) {
        const users = await this.getBroadcastUsers();
        
        if (!users.includes(userId)) {
            users.push(userId);
            await this.fileManager.atomicWrite(this.paths.broadcast.users, users);
        }
    }

    async saveBroadcastHistory(broadcastId, data) {
        const filePath = path.join(this.paths.broadcast.historyDir, `${broadcastId}.json`);
        await this.fileManager.atomicWrite(filePath, data);
    }

    async logAdminAction(action) {
        if (!config.ADMIN_LOG_ENABLED) return;
        
        const log = await this.fileManager.atomicRead(this.paths.admin.actions, []);
        
        log.push({
            timestamp: new Date().toISOString(),
            ...action
        });
        
        await this.fileManager.atomicWrite(this.paths.admin.actions, log);
    }

    async logError(error, context = {}) {
        const log = await this.fileManager.atomicRead(this.paths.system.errorLog, []);
        
        log.push({
            timestamp: new Date().toISOString(),
            message: error.message,
            stack: error.stack,
            context
        });
        
        if (log.length > 5000) {
            log.splice(0, log.length - 5000);
        }
        
        await this.fileManager.atomicWrite(this.paths.system.errorLog, log);
    }

    async updateSystemHealth(metrics) {
        await this.fileManager.atomicWrite(this.paths.system.systemHealth, {
            timestamp: new Date().toISOString(),
            ...metrics
        });
    }

    async logApiUsage(endpoint, method, responseTime, success) {
        const log = await this.fileManager.atomicRead(this.paths.system.apiUsage, []);
        
        log.push({
            timestamp: new Date().toISOString(),
            endpoint,
            method,
            responseTime,
            success
        });
        
        if (log.length > 10000) {
            log.splice(0, log.length - 10000);
        }
        
        await this.fileManager.atomicWrite(this.paths.system.apiUsage, log);
    }

    async addToIndex(indexType, id) {
        let indexPath;
        
        switch(indexType) {
            case 'users':
                indexPath = this.paths.users.index;
                break;
            case 'products':
                indexPath = this.paths.products.index;
                break;
            case 'transactions':
                indexPath = this.paths.transactions.index;
                break;
            case 'orders':
                indexPath = this.paths.orders.index;
                break;
            default:
                return;
        }
        
        const index = await this.fileManager.atomicRead(indexPath, []);
        
        if (!index.includes(id)) {
            index.push(id);
            await this.fileManager.atomicWrite(indexPath, index);
        }
    }

    async removeFromIndex(indexType, id) {
        let indexPath;
        
        switch(indexType) {
            case 'users':
                indexPath = this.paths.users.index;
                break;
            case 'products':
                indexPath = this.paths.products.index;
                break;
            case 'transactions':
                indexPath = this.paths.transactions.index;
                break;
            case 'orders':
                indexPath = this.paths.orders.index;
                break;
            default:
                return;
        }
        
        let index = await this.fileManager.atomicRead(indexPath, []);
        index = index.filter(item => item !== id);
        
        await this.fileManager.atomicWrite(indexPath, index);
    }

    async cleanup() {
        Logger.info('Starting database cleanup...');
        
        try {
            const now = Date.now();
            const retentionMs = config.LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
            
            const transactionIndex = await this.fileManager.atomicRead(this.paths.transactions.index, []);
            for (const txId of transactionIndex) {
                const depositPath = path.join(this.paths.transactions.depositDir, `${txId}.json`);
                const purchasePath = path.join(this.paths.transactions.purchaseDir, `${txId}.json`);
                
                for (const txPath of [depositPath, purchasePath]) {
                    if (await fse.pathExists(txPath)) {
                        const tx = await this.fileManager.atomicRead(txPath, null);
                        if (tx && tx.createdAt) {
                            const txTime = new Date(tx.createdAt).getTime();
                            if (now - txTime > retentionMs) {
                                await this.fileManager.safeDelete(txPath);
                                await this.removeFromIndex('transactions', txId);
                                Logger.info('Deleted old transaction', { txId });
                            }
                        }
                    }
                }
            }
            
            const errorLog = await this.fileManager.atomicRead(this.paths.system.errorLog, []);
            const errorRetentionMs = config.ERROR_LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
            const recentErrors = errorLog.filter(e => {
                const errorTime = new Date(e.timestamp).getTime();
                return now - errorTime < errorRetentionMs;
            });
            
            if (recentErrors.length !== errorLog.length) {
                await this.fileManager.atomicWrite(this.paths.system.errorLog, recentErrors);
                Logger.info('Cleaned up old error logs', { 
                    deleted: errorLog.length - recentErrors.length 
                });
            }
            
            const userIndex = await this.fileManager.atomicRead(this.paths.users.index, []);
            for (const userId of userIndex) {
                const session = await this.getUserSession(userId);
                if (session && session.expiresAt) {
                    const expiryTime = new Date(session.expiresAt).getTime();
                    if (now > expiryTime) {
                        await this.deleteUserSession(userId);
                        Logger.info('Deleted expired session', { userId });
                    }
                }
            }
            
            Logger.info('Database cleanup completed');
            
            const cleanupLog = await this.fileManager.atomicRead(this.paths.system.dataCleanupLog, []);
            cleanupLog.push({
                timestamp: new Date().toISOString(),
                type: 'scheduled_cleanup',
                success: true
            });
            await this.fileManager.atomicWrite(this.paths.system.dataCleanupLog, cleanupLog);
            
        } catch (error) {
            Logger.error('Database cleanup failed', { error: error.message });
        }
    }

    async backup() {
        if (!config.BACKUP_ENABLED) return;
        
        try {
            Logger.info('Starting database backup...');
            
            const backupDir = path.join(config.BACKUP_DIR, new Date().toISOString().split('T')[0]);
            await fse.ensureDir(backupDir);
            
            await fse.copy(this.baseDir, backupDir);
            
            Logger.info('Database backup completed', { backupDir });
            
            const backupSchedule = await this.fileManager.atomicRead(this.paths.system.backupSchedule, []);
            backupSchedule.push({
                timestamp: new Date().toISOString(),
                backupDir,
                success: true
            });
            await this.fileManager.atomicWrite(this.paths.system.backupSchedule, backupSchedule);
            
            await this.cleanupOldBackups();
            
        } catch (error) {
            Logger.error('Database backup failed', { error: error.message });
        }
    }

    async cleanupOldBackups() {
        try {
            const backupDirs = await fse.readdir(config.BACKUP_DIR);
            const now = Date.now();
            const retentionMs = config.BACKUP_RETENTION_DAYS * 24 * 60 * 60 * 1000;
            
            for (const dir of backupDirs) {
                const dirPath = path.join(config.BACKUP_DIR, dir);
                const stats = await fse.stat(dirPath);
                
                if (stats.isDirectory() && now - stats.mtimeMs > retentionMs) {
                    await fse.remove(dirPath);
                    Logger.info('Deleted old backup', { dir });
                }
            }
        } catch (error) {
            Logger.error('Cleanup old backups failed', { error: error.message });
        }
    }

    async recover() {
        Logger.info('Starting recovery process...');
        
        try {
            const checkAndRestore = async (filePath) => {
                try {
                    if (await fse.pathExists(filePath)) {
                        const data = await fs.readFile(filePath, 'utf8');
                        JSON.parse(data);
                    }
                } catch (error) {
                    Logger.warn('Corrupted file detected', { filePath });
                    
                    const backupPath = `${filePath}.backup`;
                    if (await fse.pathExists(backupPath)) {
                        await fse.copy(backupPath, filePath);
                        Logger.info('Restored from backup', { filePath });
                    }
                }
            };
            
            const criticalFiles = [
                this.paths.users.index,
                this.paths.products.index,
                this.paths.transactions.index,
                this.paths.orders.index,
                this.paths.security.bannedUsers
            ];
            
            for (const file of criticalFiles) {
                await checkAndRestore(file);
            }
            
            const pending = await this.fileManager.atomicRead(this.paths.transactions.pending, []);
            const now = Date.now();
            const cleanPending = pending.filter(tx => {
                if (tx.createdAt) {
                    const txTime = new Date(tx.createdAt).getTime();
                    if (now - txTime > 24 * 60 * 60 * 1000) {
                        Logger.info('Auto-cancelled old pending transaction', { txId: tx.id });
                        return false;
                    }
                }
                return true;
            });
            
            if (cleanPending.length !== pending.length) {
                await this.fileManager.atomicWrite(this.paths.transactions.pending, cleanPending);
            }
            
            Logger.info('Recovery process completed');
            
        } catch (error) {
            Logger.error('Recovery process failed', { error: error.message });
        }
    }
}

// ============================================
// 💰 PAYMENT HANDLER
// ============================================

class PaymentHandler {
    constructor(db, security) {
        this.db = db;
        this.security = security;
        this.pendingPayments = new Map();
    }

    async createQRISPayment(userId, amount) {
        try {
            const validation = InputValidator.validateAmount(amount);
            if (!validation.valid) {
                return { success: false, error: validation.error };
            }

            const startTime = Date.now();

            const params = new URLSearchParams({
                nominal: amount.toString(),
                metode: 'QRISFAST'
            });

            const response = await axios.get(`${config.CIAATOPUP_CREATE_URL}?${params}`, {
                headers: { 
                    'X-APIKEY': config.CIAATOPUP_API_KEY,
                    'Content-Type': 'application/json'
                },
                timeout: config.CIAATOPUP_TIMEOUT
            });

            const responseTime = Date.now() - startTime;
            await this.db.logApiUsage('ciaatopup/create', 'GET', responseTime, response.data.success);

            if (!response.data || !response.data.success || !response.data.data) {
                throw new Error('Invalid API response');
            }

            const paymentData = response.data.data;
            
            const qrBuffer = await QRCode.toBuffer(paymentData.qr_string);

            const paymentId = `PAY-${Date.now()}`;
            await this.db.fileManager.atomicWrite(
                path.join(this.db.paths.payments.qrisDir, `${paymentId}.json`),
                {
                    paymentId,
                    userId: userId.toString(),
                    transactionId: paymentData.id,
                    amount,
                    fee: paymentData.fee,
                    totalAmount: paymentData.nominal,
                    getBalance: paymentData.get_balance,
                    qrString: paymentData.qr_string,
                    expiredAt: paymentData.expired_at,
                    status: 'pending',
                    createdAt: new Date().toISOString()
                }
            );

            this.pendingPayments.set(paymentData.id, {
                userId,
                paymentId,
                amount: paymentData.get_balance,
                startTime: Date.now()
            });

            Logger.info('QRIS payment created', { userId, paymentId, transactionId: paymentData.id });

            return {
                success: true,
                data: paymentData,
                qrBuffer,
                paymentId
            };

        } catch (error) {
            Logger.error('Create QRIS payment failed', { userId, error: error.message });
            
            await this.db.fileManager.atomicWrite(
                this.db.paths.payments.failed,
                await this.db.fileManager.atomicRead(this.db.paths.payments.failed, [])
                    .then(failed => {
                        failed.push({
                            userId: userId.toString(),
                            amount,
                            error: error.message,
                            timestamp: new Date().toISOString()
                        });
                        return failed;
                    })
            );

            return { 
                success: false, 
                error: config.ERROR_MESSAGES.PAYMENT_FAILED 
            };
        }
    }

    async checkPaymentStatus(transactionId) {
        try {
            if (this.security.hasProcessedTransaction(transactionId)) {
                Logger.warn('Transaction already processed', { transactionId });
                return { status: 'already_processed' };
            }

            const params = new URLSearchParams({ id: transactionId });
            
            const startTime = Date.now();
            const response = await axios.get(`${config.CIAATOPUP_STATUS_URL}?${params}`, {
                headers: { 
                    'X-APIKEY': config.CIAATOPUP_API_KEY,
                    'Content-Type': 'application/json'
                },
                timeout: config.CIAATOPUP_TIMEOUT
            });

            const responseTime = Date.now() - startTime;
            await this.db.logApiUsage('ciaatopup/status', 'GET', responseTime, response.data.success);

            if (response.data && response.data.data) {
                return { status: response.data.data.status };
            }

            return { status: 'unknown' };

        } catch (error) {
            Logger.error('Check payment status failed', { transactionId, error: error.message });
            return { status: 'error' };
        }
    }

    async cancelPayment(transactionId) {
        try {
            const params = new URLSearchParams({ id: transactionId });
            
            await axios.get(`${config.CIAATOPUP_CANCEL_URL}?${params}`, {
                headers: { 
                    'X-APIKEY': config.CIAATOPUP_API_KEY,
                    'Content-Type': 'application/json'
                },
                timeout: 3000
            });

            this.pendingPayments.delete(transactionId);

            Logger.info('Payment cancelled', { transactionId });
            return { success: true };

        } catch (error) {
            Logger.error('Cancel payment failed', { transactionId, error: error.message });
            return { success: false };
        }
    }

    async processSuccessfulPayment(transactionId, userId, amount, type = 'deposit') {
        try {
            if (this.security.hasProcessedTransaction(transactionId)) {
                Logger.warn('Attempted double-spend', { transactionId, userId });
                return { 
                    success: false, 
                    error: config.ERROR_MESSAGES.TRANSACTION_EXISTS 
                };
            }

            this.security.markTransactionProcessed(transactionId);

            if (type === 'deposit') {
                const profile = await this.db.getUserProfile(userId) || {
                    userId: userId.toString(),
                    saldo: 0,
                    registeredAt: new Date().toISOString()
                };

                profile.saldo = (profile.saldo || 0) + amount;
                profile.lastTransaction = new Date().toISOString();

                await this.db.saveUserProfile(userId, profile);

                const stats = await this.db.getUserStats(userId);
                await this.db.updateUserStats(userId, {
                    totalDeposits: (stats.totalDeposits || 0) + 1,
                    totalDeposited: (stats.totalDeposited || 0) + amount
                });

                await this.db.saveTransaction(transactionId, {
                    userId: userId.toString(),
                    type: 'deposit',
                    amount,
                    status: 'success',
                    method: 'qris_auto',
                    completedAt: new Date().toISOString()
                }, 'deposit');

                await this.db.logUserActivity(userId, {
                    action: 'DEPOSIT_SUCCESS',
                    details: { transactionId, amount }
                });

                Logger.info('Deposit processed successfully', { transactionId, userId, amount });

                return { success: true, newBalance: profile.saldo };
            }

            return { success: true };

        } catch (error) {
            Logger.error('Process payment failed', { transactionId, userId, error: error.message });
            await this.db.logError(error, { transactionId, userId });
            
            return { 
                success: false, 
                error: config.ERROR_MESSAGES.SYSTEM_ERROR 
            };
        }
    }

    getPendingPayments() {
        return Array.from(this.pendingPayments.entries()).map(([txId, data]) => ({
            transactionId: txId,
            ...data
        }));
    }

    removePendingPayment(transactionId) {
        this.pendingPayments.delete(transactionId);
    }
}

// ============================================
// 📦 PRODUCT MANAGER
// ============================================

class ProductManager {
    constructor(db, security) {
        this.db = db;
        this.security = security;
    }

    async purchaseProduct(userId, productId, paymentMethod = 'saldo') {
        try {
            const userValidation = InputValidator.validateUserId(userId);
            if (!userValidation.valid) {
                return { success: false, error: userValidation.error };
            }

            const product = await this.db.getProduct(productId);
            if (!product) {
                return { success: false, error: config.ERROR_MESSAGES.PRODUCT_NOT_FOUND };
            }

            const inventory = await this.db.getProductInventory(productId);
            if (inventory.stock <= 0) {
                return { success: false, error: config.ERROR_MESSAGES.STOCK_EMPTY };
            }

            if (paymentMethod === 'saldo') {
                const profile = await this.db.getUserProfile(userId);
                if (!profile || profile.saldo < product.price) {
                    return { 
                        success: false, 
                        error: config.ERROR_MESSAGES.INSUFFICIENT_BALANCE 
                    };
                }

                profile.saldo -= product.price;
                await this.db.saveUserProfile(userId, profile);

                await this.db.decrementProductStock(productId);

                const orderId = `ORD-${Date.now()}`;
                await this.db.saveOrder(orderId, {
                    userId: userId.toString(),
                    productId,
                    productName: product.name,
                    price: product.price,
                    status: 'completed',
                    paymentMethod: 'saldo',
                    completedAt: new Date().toISOString()
                });

                const stats = await this.db.getUserStats(userId);
                await this.db.updateUserStats(userId, {
                    totalPurchases: (stats.totalPurchases || 0) + 1,
                    totalSpent: (stats.totalSpent || 0) + product.price
                });

                await this.db.logUserActivity(userId, {
                    action: 'PRODUCT_PURCHASE',
                    details: { orderId, productId, amount: product.price }
                });

                Logger.info('Product purchased successfully', { userId, productId, orderId });

                return {
                    success: true,
                    orderId,
                    product,
                    newBalance: profile.saldo
                };
            }

            const orderId = `ORD-${Date.now()}`;
            await this.db.saveOrder(orderId, {
                userId: userId.toString(),
                productId,
                productName: product.name,
                price: product.price,
                status: 'pending',
                paymentMethod,
                createdAt: new Date().toISOString()
            });

            return {
                success: true,
                orderId,
                product,
                pending: true
            };

        } catch (error) {
            Logger.error('Purchase product failed', { userId, productId, error: error.message });
            await this.db.logError(error, { userId, productId });
            
            return { 
                success: false, 
                error: config.ERROR_MESSAGES.SYSTEM_ERROR 
            };
        }
    }

    async deliverProduct(orderId, userId) {
        try {
            const order = await this.db.getOrder(orderId);
            if (!order) {
                return { success: false, error: 'Order tidak ditemukan' };
            }

            const product = await this.db.getProduct(order.productId);
            if (!product) {
                return { success: false, error: 'Produk tidak ditemukan' };
            }

            const deliveryData = {
                orderId,
                productId: product.id,
                productName: product.name,
                deliveredAt: new Date().toISOString()
            };

            if (product.productData) {
                if (product.productData.type === 'text') {
                    deliveryData.content = product.productData.content;
                    deliveryData.contentType = 'text';
                } else if (product.productData.type === 'file') {
                    deliveryData.fileId = product.productData.fileId;
                    deliveryData.fileName = product.productData.fileName;
                    deliveryData.contentType = 'file';
                }

                const dataStr = product.productData.type === 'text' ? 
                    product.productData.content : 
                    product.productData.fileId;
                deliveryData.checksum = this.security.hashData(dataStr);
            }

            const deliveryPath = path.join(this.db.paths.orders.deliveryDir, `${orderId}.json`);
            await this.db.fileManager.atomicWrite(deliveryPath, deliveryData);

            Logger.info('Product delivered', { orderId, userId });

            return { success: true, deliveryData };

        } catch (error) {
            Logger.error('Deliver product failed', { orderId, error: error.message });
            return { success: false, error: config.ERROR_MESSAGES.SYSTEM_ERROR };
        }
    }
}

// ============================================
// 👤 USER MANAGER
// ============================================

class UserManager {
    constructor(db, security) {
        this.db = db;
        this.security = security;
    }

    async getUser(userId) {
        const profile = await this.db.getUserProfile(userId);
        return profile;
    }

    async createUser(userId, initialData = {}) {
        const profile = {
            userId: userId.toString(),
            saldo: initialData.saldo || 0,
            registeredAt: new Date().toISOString(),
            lastActivity: new Date().toISOString(),
            ...initialData
        };

        await this.db.saveUserProfile(userId, profile);
        await this.db.addBroadcastUser(userId);

        Logger.info('User created', { userId });
        return profile;
    }

    async updateUserBalance(userId, amount, operation = 'add') {
        try {
            let profile = await this.db.getUserProfile(userId);
            
            if (!profile) {
                if (operation === 'subtract') {
                    return { 
                        success: false, 
                        error: config.ERROR_MESSAGES.INSUFFICIENT_BALANCE 
                    };
                }
                profile = await this.createUser(userId, { saldo: 0 });
            }

            if (operation === 'add') {
                profile.saldo = (profile.saldo || 0) + amount;
            } else if (operation === 'subtract') {
                if (profile.saldo < amount) {
                    return { 
                        success: false, 
                        error: config.ERROR_MESSAGES.INSUFFICIENT_BALANCE 
                    };
                }
                profile.saldo -= amount;
            }

            await this.db.saveUserProfile(userId, profile);

            Logger.info('User balance updated', { userId, amount, operation, newBalance: profile.saldo });

            return { success: true, newBalance: profile.saldo };

        } catch (error) {
            Logger.error('Update user balance failed', { userId, error: error.message });
            return { success: false, error: config.ERROR_MESSAGES.SYSTEM_ERROR };
        }
    }

    async checkUserStatus(userId) {
        const banStatus = await this.db.isUserBanned(userId);
        if (banStatus.banned) {
            return {
                allowed: false,
                reason: 'banned',
                message: config.ERROR_MESSAGES.BANNED,
                details: banStatus
            };
        }

        const rateLimit = this.security.checkRateLimit(userId);
        if (!rateLimit.allowed) {
            return {
                allowed: false,
                reason: 'rate_limit',
                message: rateLimit.message
            };
        }

        const fraudScore = this.security.getFraudScore(userId);
        if (fraudScore >= config.FRAUD_DETECTION.FRAUD_SCORE_THRESHOLD) {
            return {
                allowed: false,
                reason: 'fraud_score',
                message: config.ERROR_MESSAGES.BANNED
            };
        }

        return { allowed: true };
    }
}

// ============================================
// 🤖 MAIN BOT CLASS - FULL BUTTON BASED
// ============================================

class DigitalProductBot {
    constructor() {
        this.config = config;
        
        this.bot = new TelegramBot(this.config.BOT_TOKEN, { 
            polling: {
                interval: 300,
                autoStart: true,
                params: { timeout: 10 }
            },
            filepath: false
        });

        this.bot.on('polling_error', (error) => {
            Logger.error('Polling error', { code: error.code, message: error.message });
        });

        this.security = new SecurityManager(this.config.ENCRYPTION_KEY);
        this.db = new DatabaseManager(this.security);
        this.paymentHandler = new PaymentHandler(this.db, this.security);
        this.productManager = new ProductManager(this.db, this.security);
        this.userManager = new UserManager(this.db, this.security);

        this.processingCallbacks = new Set();
        
        // ✅ WIZARD STATES - Untuk input via button
        this.depositWizardStates = new Map();
        this.productAddWizardStates = new Map();
        this.broadcastWizardStates = new Map();
        this.addSaldoWizardStates = new Map();
        this.banUserWizardStates = new Map();

        this.initPromise = this.initialize();
        
        this.setupHandlers();
        
        this.startDepositMonitoring();
        this.startCleanupWorker();
        this.startHealthMonitoring();

        this.setupGracefulShutdown();

        Logger.info('Digital Product Bot initialized - FULL BUTTON MODE');
    }

    async initialize() {
        try {
            this.validateConfiguration();

            await this.db.initialize();

            await this.db.recover();

            if (config.BACKUP_ENABLED) {
                await this.db.backup();
            }

            Logger.info('Bot initialization completed successfully');
            return true;

        } catch (error) {
            Logger.error('Bot initialization failed', { error: error.message });
            process.exit(1);
        }
    }

    validateConfiguration() {
        const required = ['BOT_TOKEN', 'OWNER_ID', 'CIAATOPUP_API_KEY'];
        
        for (const field of required) {
            if (!this.config[field]) {
                throw new Error(`Missing required configuration: ${field}`);
            }
        }

        if (this.config.ENCRYPTION_KEY === 'CHANGE_THIS_32_CHAR_SECRET_KEY!') {
            Logger.warn('Using default encryption key - CHANGE THIS IN PRODUCTION!');
        }

        Logger.info('Configuration validated');
    }

    setupHandlers() {
        // ✅ HANYA /start command yang ada
        this.bot.onText(/\/start/, (msg) => this.handleStart(msg));
        
        // ❌ SEMUA COMMAND INI DIHAPUS - DIGANTI BUTTON
        // this.bot.onText(/\/deposit...
        // this.bot.onText(/\/reff...
        // this.bot.onText(/\/bc...
        // this.bot.onText(/\/produk_add...
        // dst...
        
        // ✅ Semua interaksi via callback query (button)
        this.bot.on('callback_query', (query) => this.handleCallback(query));
        
        // Photo & Document untuk wizard
        this.bot.on('photo', (msg) => this.handlePhoto(msg));
        this.bot.on('document', (msg) => this.handleDocument(msg));
        
        // Text message untuk wizard input
        this.bot.on('message', (msg) => this.handleMessage(msg));

        Logger.info('Handlers setup completed - BUTTON MODE');
    }

    async handleStart(msg) {
        if (msg.chat.type !== 'private') {
            return this.bot.sendMessage(msg.chat.id, 
                "⚠️ Bot ini hanya bekerja di private chat."
            );
        }

        const userId = msg.from.id;

        try {
            const status = await this.userManager.checkUserStatus(userId);
            if (!status.allowed) {
                return this.bot.sendMessage(msg.chat.id, status.message);
            }

            let user = await this.userManager.getUser(userId);
            if (!user) {
                user = await this.userManager.createUser(userId);
            }

            await this.db.addBroadcastUser(userId);

            await this.db.logUserActivity(userId, {
                action: 'START_COMMAND',
                details: {}
            });

            const products = await this.db.getAllProducts();
            const broadcastUsers = await this.db.getBroadcastUsers();
            const allUsers = await this.db.fileManager.atomicRead(this.db.paths.users.index, []);

            const keyboard = {
                inline_keyboard: [
                    [
                        { text: '🛍️ Produk Digital', callback_data: 'produk_digital' },
                        { text: '💰 Cek Saldo', callback_data: 'check_balance' }
                    ],
                    [
                        { text: '📜 Riwayat Order', callback_data: 'order_history' },
                        { text: '💳 Top Up Saldo', callback_data: 'topup_menu' }
                    ],
                    [
                        { text: '📖 Syarat & Ketentuan', callback_data: 'rules' },
                        { text: 'ℹ️ Bantuan', callback_data: 'help' }
                    ]
                ]
            };

            if (userId === this.config.OWNER_ID) {
                keyboard.inline_keyboard.push([
                    { text: '👑 Owner Panel', callback_data: 'owner_panel' }
                ]);
            }

            const timeInfo = this.getIndonesianTime();
            const saldoDisplay = (user.saldo || 0).toLocaleString('id-ID');
            
            const sanitizeName = (name) => {
                if (!name) return 'Tidak ada';
                return name.replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&');
            };
            
            const username = msg.from.username ? '@' + sanitizeName(msg.from.username) : 'Tidak ada';
            
            const welcomeText = user.registeredAt ? 
                `╔══════════════════════╗\n` +
                `║   👋 *SELAMAT DATANG*   ║\n` +
                `╚══════════════════════╝\n\n` +
                `Hai *${msg.from.first_name}*! 🎉\nSenang melihat Anda kembali.\n\n` :
                `╔═══════════════════════╗\n` +
                `║  🌟 *SELAMAT BERGABUNG*  ║\n` +
                `╚═══════════════════════╝\n\n` +
                `Hai *${msg.from.first_name}*! 🎊\nSelamat datang di platform kami.\n\n`;
            
            const fullText = welcomeText +
                `┏━━━━━ *👤 INFO AKUN* ━━━━━┓\n` +
                `┃ 📱 Username: ${username}\n` +
                `┃ 🆔 User ID: \`${userId}\`\n` +
                `┃ 📅 Tanggal: ${timeInfo.date}\n` +
                `┃ 🕐 Waktu: ${timeInfo.time} WIB\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `💰 *Saldo Anda:* Rp ${saldoDisplay}\n\n` +
                `┏━━━━ *📊 STATISTIK BOT* ━━━━┓\n` +
                `┃ 👥 Total User: ${allUsers.length}\n` +
                `┃ 💳 User Aktif: ${broadcastUsers.length}\n` +
                `┃ 📦 Total Produk: ${products.length}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━ *🚀 FITUR UNGGULAN* ━━━┓\n` +
                `┃ ⚡ Pembayaran QRIS Otomatis\n` +
                `┃ 📦 Pengiriman Produk Instan\n` +
                `┃ 🔐 Sistem Keamanan Tinggi\n` +
                `┃ 💬 Support 24/7\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `⚠️ *DISCLAIMER PENTING:*\n` +
                `• Saldo di bot TIDAK BISA di-refund\n` +
                `• Pastikan pilih produk dengan benar\n` +
                `• Transaksi bersifat final\n\n` +
                `👨‍💻 *Bot Creator:* @Jeeyhosting\n` +
                `🌐 *Platform:* Digital Store Premium\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `Pilih menu di bawah untuk memulai:`;

            await this.bot.sendPhoto(msg.chat.id, this.config.BOT_LOGO, {
                caption: fullText,
                reply_markup: keyboard,
                parse_mode: 'Markdown'
            });

        } catch (error) {
            Logger.error('Handle start error', { userId, error: error.message });
            await this.db.logError(error, { command: 'start', userId });
            
            await this.bot.sendMessage(msg.chat.id,
                config.ERROR_MESSAGES.SYSTEM_ERROR
            );
        }
    }

    async handleCallback(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const data = query.data;
        const userId = query.from.id;
        const callbackKey = `${chatId}_${messageId}_${data}`;

        try {
            const status = await this.userManager.checkUserStatus(userId);
            if (!status.allowed) {
                return this.bot.answerCallbackQuery(query.id, {
                    text: status.message,
                    show_alert: true
                });
            }

            if (this.processingCallbacks.has(callbackKey)) {
                return this.bot.answerCallbackQuery(query.id, {
                    text: "⏳ Sedang diproses, tunggu...",
                    show_alert: false
                });
            }

            this.processingCallbacks.add(callbackKey);
            await this.bot.answerCallbackQuery(query.id);

            await this.routeCallback(query, data);

        } catch (error) {
            Logger.error('Handle callback error', { userId, data, error: error.message });
            await this.db.logError(error, { callback: data, userId });

            await this.bot.sendMessage(chatId,
                config.ERROR_MESSAGES.SYSTEM_ERROR
            );

        } finally {
            this.processingCallbacks.delete(callbackKey);
        }
    }

    async routeCallback(query, data) {
        const handlers = {
            'check_balance': () => this.showBalance(query),
            'order_history': () => this.showOrderHistory(query),
            'topup_menu': () => this.showTopupMenu(query),
            'help': () => this.showHelp(query),
            'rules': () => this.showRules(query),
            'owner_panel': () => this.showOwnerPanel(query),
            'back_main': () => this.showMainMenu(query),
            'produk_digital': () => this.showProdukDigital(query),
            
            // ✅ TOPUP CALLBACKS
            'topup_qris': () => this.showDepositOptions(query),
            'topup_manual': () => this.showManualPaymentInfo(query),
            
            // ✅ OWNER PANEL CALLBACKS
            'owner_stats': () => this.showOwnerStats(query),
            'owner_manage_users': () => this.showOwnerManageUsers(query),
            'owner_manage_saldo': () => this.showOwnerManageSaldo(query),
            'owner_manage_products': () => this.showOwnerManageProducts(query),
            'owner_broadcast': () => this.startBroadcastWizard(query),
            'owner_settings': () => this.showOwnerSettings(query),
            
            // ✅ PRODUCT MANAGEMENT
            'owner_add_product': () => this.startProductAddWizard(query),
            'owner_list_products': () => this.showOwnerProductList(query),
            'owner_manage_stock': () => this.showOwnerManageStock(query),
            
            // ✅ USER MANAGEMENT
            'owner_add_saldo_menu': () => this.startAddSaldoWizard(query),
            'owner_ban_user_menu': () => this.startBanUserWizard(query),
            'owner_view_users': () => this.showAllUsers(query),
        };

        // Dynamic callbacks
        if (data.startsWith('produk_page_')) {
            const page = parseInt(data.replace('produk_page_', ''));
            await this.showProdukDigital(query, page);
        } 
        else if (data.startsWith('buy_product_')) {
            await this.confirmProductPurchase(query, data);
        } 
        else if (data.startsWith('confirm_buy_product_')) {
            await this.processProductPurchase(query, data);
        } 
        else if (data.startsWith('cancel_deposit_')) {
            await this.cancelDeposit(query, data);
        }
        else if (data.startsWith('deposit_amount_')) {
            await this.handleDepositAmount(query, data);
        }
        else if (data.startsWith('owner_del_product_')) {
            await this.confirmDeleteProduct(query, data);
        }
        else if (data.startsWith('confirm_del_product_')) {
            await this.processDeleteProduct(query, data);
        }
        else if (data.startsWith('owner_view_user_')) {
            await this.showUserDetail(query, data);
        }
        else if (data.startsWith('owner_unban_user_')) {
            await this.processUnbanUser(query, data);
        }
        else if (data === 'page_info') {
            // Do nothing
        }
        else if (handlers[data]) {
            await handlers[data]();
        } else {
            Logger.warn('Unknown callback data', { data });
        }
    }

    // ============================================
    // 💳 TOPUP & DEPOSIT DENGAN BUTTON
    // ============================================

    async showTopupMenu(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;

        const keyboard = {
            inline_keyboard: [
                [{ text: '⚡ QRIS Otomatis (Instant)', callback_data: 'topup_qris' }],
                [{ text: '📸 Transfer Manual', callback_data: 'topup_manual' }],
                [{ text: '🔙 Menu Utama', callback_data: 'back_main' }]
            ]
        };

        const text = `╔═══════════════════════╗\n` +
            `║  💳 *PILIH METODE TOPUP*  ║\n` +
            `╚═══════════════════════╝\n\n` +
            `┏━━━ *⚡ QRIS OTOMATIS* ━━━┓\n` +
            `┃ ✅ Saldo masuk 1-5 menit\n` +
            `┃ ✅ Support semua e-wallet\n` +
            `┃ ✅ Proses full otomatis\n` +
            `┃ 💰 Minimal: Rp 1.000\n` +
            `┗━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
            `┏━━━ *📸 TRANSFER MANUAL* ━━┓\n` +
            `┃ 📱 Transfer ke rekening\n` +
            `┃ 📸 Upload bukti transfer\n` +
            `┃ ⏱️ Diproses 5-30 menit\n` +
            `┃ 💰 Minimal: Rp 10.000\n` +
            `┗━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
            `━━━━━━━━━━━━━━━━━━━━━━\n` +
            `💡 *Rekomendasi:* QRIS Otomatis\n` +
            `Untuk proses tercepat & termudah!\n\n` +
            `Pilih metode topup:`;

        await this.editPhotoCaption(chatId, messageId, text, keyboard);
    }

    async showDepositOptions(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        const keyboard = {
            inline_keyboard: [
                [
                    { text: 'Rp 10.000', callback_data: 'deposit_amount_10000' },
                    { text: 'Rp 25.000', callback_data: 'deposit_amount_25000' }
                ],
                [
                    { text: 'Rp 50.000', callback_data: 'deposit_amount_50000' },
                    { text: 'Rp 100.000', callback_data: 'deposit_amount_100000' }
                ],
                [
                    { text: 'Rp 200.000', callback_data: 'deposit_amount_200000' },
                    { text: 'Rp 500.000', callback_data: 'deposit_amount_500000' }
                ],
                [{ text: '💰 Input Nominal Sendiri', callback_data: 'deposit_amount_custom' }],
                [{ text: '🔙 Kembali', callback_data: 'topup_menu' }]
            ]
        };

        const text = `╔═══════════════════════╗\n` +
            `║  ⚡ *DEPOSIT VIA QRIS*   ║\n` +
            `╚═══════════════════════╝\n\n` +
            `Pilih nominal deposit atau input manual:\n\n` +
            `┏━━━━━ *💳 INFORMASI* ━━━━━┓\n` +
            `┃ 📌 Minimal: Rp 1.000\n` +
            `┃ 📌 Maksimal: Rp 1.000.000.000\n` +
            `┃ ⚡ Proses: Otomatis & Instan\n` +
            `┃ 💳 Support: Semua E-Wallet\n` +
            `┗━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
            `━━━━━━━━━━━━━━━━━━━━━━\n` +
            `💡 *Pilih nominal atau input manual*`;

        await this.editPhotoCaption(chatId, messageId, text, keyboard);
    }

    async handleDepositAmount(query, data) {
        const userId = query.from.id;
        const chatId = query.message.chat.id;

        if (data === 'deposit_amount_custom') {
            this.depositWizardStates.set(userId, {
                step: 'waiting_amount',
                chatId
            });

            await this.bot.sendMessage(chatId,
                `╔═══════════════════════╗\n` +
                `║  💰 *INPUT NOMINAL*     ║\n` +
                `╚═══════════════════════╝\n\n` +
                `Ketik nominal yang ingin Anda deposit:\n\n` +
                `📌 *Contoh:* 50000\n` +
                `📌 *Minimal:* 1000\n` +
                `📌 *Maksimal:* 1000000000\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `Ketik nominal sekarang:`,
                { parse_mode: 'Markdown' }
            );
        } else {
            const amount = parseInt(data.replace('deposit_amount_', ''));
            await this.processDeposit(userId, chatId, amount);
        }
    }

    async processDeposit(userId, chatId, amount) {
        try {
            const payment = await this.paymentHandler.createQRISPayment(userId, amount);
            
            if (!payment.success) {
                return this.bot.sendMessage(chatId, payment.error);
            }

            const text = `╔═══════════════════════╗\n` +
                `║  💳 *PEMBAYARAN QRIS*   ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *📋 DETAIL TRANSAKSI* ━━━━┓\n` +
                `┃ 🆔 ID: \`${payment.data.id}\`\n` +
                `┃ 💰 Nominal: Rp ${amount.toLocaleString("id-ID")}\n` +
                `┃ 🧾 Biaya Admin: Rp ${payment.data.fee.toLocaleString("id-ID")}\n` +
                `┃ 💸 Total Bayar: Rp ${payment.data.nominal.toLocaleString("id-ID")}\n` +
                `┃ 💎 Diterima: Rp ${payment.data.get_balance.toLocaleString("id-ID")}\n` +
                `┃ 📅 Expired: ${payment.data.expired_at}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━ *📲 CARA PEMBAYARAN* ━━━┓\n` +
                `┃ 1️⃣ Buka aplikasi e-wallet\n` +
                `┃ 2️⃣ Scan QR Code di atas\n` +
                `┃ 3️⃣ Bayar sesuai nominal\n` +
                `┃ 4️⃣ Saldo masuk otomatis\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `✅ *Support:* DANA, OVO, ShopeePay,\n` +
                `    GoPay, LinkAja, dll\n\n` +
                `⚠️ *PENTING:*\n` +
                `• Saldo masuk otomatis dalam 1-5 menit\n` +
                `• QR Code berlaku ${payment.data.expired_at}\n` +
                `• Jangan tutup halaman ini\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━`;

            await this.bot.sendPhoto(chatId, payment.qrBuffer, {
                caption: text,
                parse_mode: "Markdown",
                reply_markup: {
                    inline_keyboard: [[
                        { text: "❌ BATALKAN DEPOSIT", callback_data: `cancel_deposit_${payment.data.id}` }
                    ]]
                }
            });

            await this.db.logUserActivity(userId, {
                action: 'DEPOSIT_CREATED',
                details: { transactionId: payment.data.id, amount }
            });

        } catch (error) {
            Logger.error('Process deposit error', { userId, error: error.message });
            await this.bot.sendMessage(chatId, config.ERROR_MESSAGES.SYSTEM_ERROR);
        }
    }

    async cancelDeposit(query, data) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;
        const transactionId = data.replace('cancel_deposit_', '');

        try {
            await this.paymentHandler.cancelPayment(transactionId);

            try {
                await this.bot.deleteMessage(chatId, messageId);
            } catch (e) {
                // Ignore
            }

            const timeInfo = this.getIndonesianTime();
            
            await this.bot.sendMessage(chatId,
                `╔═══════════════════════╗\n` +
                `║  ✅ *DEPOSIT DIBATALKAN* ║\n` +
                `╚═══════════════════════╝\n\n` +
                `🆔 *ID Transaksi:* \`${transactionId}\`\n` +
                `📅 *Waktu:* ${timeInfo.date}\n` +
                `🕐 *Jam:* ${timeInfo.time} WIB\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `💡 Anda dapat membuat deposit baru\n` +
                `   kapan saja melalui menu Topup.`,
                { parse_mode: 'Markdown' }
            );

            await this.db.logUserActivity(userId, {
                action: 'DEPOSIT_CANCELLED',
                details: { transactionId }
            });

        } catch (error) {
            Logger.error('Cancel deposit error', { userId, transactionId, error: error.message });
        }
    }

    async showManualPaymentInfo(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;

        const keyboard = {
            inline_keyboard: [
                [{ text: '🔙 Kembali ke Menu Topup', callback_data: 'topup_menu' }],
                [{ text: '🏠 Menu Utama', callback_data: 'back_main' }]
            ]
        };

        let text = `╔═══════════════════════╗\n` +
            `║  📸 *TRANSFER MANUAL*   ║\n` +
            `╚═══════════════════════╝\n\n`;

        const manualPayments = [];
        if (config.MANUAL_PAYMENT.DANA.enabled) manualPayments.push('DANA');
        if (config.MANUAL_PAYMENT.OVO.enabled) manualPayments.push('OVO');
        if (config.MANUAL_PAYMENT.GOPAY.enabled) manualPayments.push('GOPAY');
        if (config.MANUAL_PAYMENT.BCA.enabled) manualPayments.push('BCA');

        if (manualPayments.length === 0) {
            text += `⚠️ *Pembayaran manual sedang tidak tersedia.*\n\n` +
                `Gunakan metode QRIS Otomatis untuk\n` +
                `proses yang lebih cepat dan mudah.\n\n`;
        } else {
            text += `┏━━━ *📱 REKENING TERSEDIA* ━━━┓\n`;

            if (config.MANUAL_PAYMENT.DANA.enabled) {
                text += `┃ 💳 *DANA*\n` +
                    `┃    ${config.MANUAL_PAYMENT.DANA.number}\n` +
                    `┃    a/n ${config.MANUAL_PAYMENT.DANA.name}\n┃\n`;
            }

            if (config.MANUAL_PAYMENT.OVO.enabled) {
                text += `┃ 💳 *OVO*\n` +
                    `┃    ${config.MANUAL_PAYMENT.OVO.number}\n` +
                    `┃    a/n ${config.MANUAL_PAYMENT.OVO.name}\n┃\n`;
            }

            if (config.MANUAL_PAYMENT.GOPAY.enabled) {
                text += `┃ 💳 *GOPAY*\n` +
                    `┃    ${config.MANUAL_PAYMENT.GOPAY.number}\n` +
                    `┃    a/n ${config.MANUAL_PAYMENT.GOPAY.name}\n┃\n`;
            }

            if (config.MANUAL_PAYMENT.BCA.enabled) {
                text += `┃ 🏦 *BCA*\n` +
                    `┃    ${config.MANUAL_PAYMENT.BCA.account_number}\n` +
                    `┃    a/n ${config.MANUAL_PAYMENT.BCA.account_name}\n┃\n`;
            }

            text += `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━ *📝 CARA TRANSFER* ━━━┓\n` +
                `┃ 1️⃣ Transfer ke rekening di atas\n` +
                `┃ 2️⃣ Screenshot bukti transfer\n` +
                `┃ 3️⃣ Kirim ke admin: @Jeeyhosting\n` +
                `┃ 4️⃣ Tunggu konfirmasi (5-30 menit)\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `⚠️ *PENTING:*\n` +
                `• Minimal transfer: Rp 10.000\n` +
                `• Sertakan User ID Anda: \`${query.from.id}\`\n` +
                `• Admin aktif 24/7\n\n`;
        }

        text += `━━━━━━━━━━━━━━━━━━━━━━\n` +
            `💡 *Rekomendasi:* Gunakan QRIS Otomatis\n` +
            `untuk proses instant!`;

        await this.editPhotoCaption(chatId, messageId, text, keyboard);
    }

    // ============================================
    // 🛍️ PRODUCT DISPLAY & PURCHASE
    // ============================================

    async showProdukDigital(query, page = 0) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        try {
            const products = await this.db.getAllProducts();
            const availableProducts = products.filter(p => p.stock > 0);

            const ITEMS_PER_PAGE = config.PRODUCTS_PER_PAGE;
            const totalPages = Math.ceil(availableProducts.length / ITEMS_PER_PAGE);
            const startIndex = page * ITEMS_PER_PAGE;
            const endIndex = startIndex + ITEMS_PER_PAGE;
            const productsOnPage = availableProducts.slice(startIndex, endIndex);

            const keyboard = { inline_keyboard: [] };

            if (availableProducts.length === 0) {
                const emptyText = `╔═══════════════════════╗\n` +
                    `║  🛍️ *PRODUK DIGITAL*   ║\n` +
                    `╚═══════════════════════╝\n\n` +
                    `📦 *Belum ada produk tersedia.*\n\n` +
                    `Tunggu update dari admin!\n` +
                    `Produk akan segera ditambahkan.`;

                keyboard.inline_keyboard.push([{ text: '🔙 Menu Utama', callback_data: 'back_main' }]);

                await this.editPhotoCaption(chatId, messageId, emptyText, keyboard);
                return;
            }

            let produkText = `╔═══════════════════════╗\n` +
                `║  🛍️ *PRODUK DIGITAL*   ║\n` +
                `╚═══════════════════════╝\n\n` +
                `📄 *Halaman ${page + 1} dari ${totalPages}*\n` +
                `📦 *Total ${availableProducts.length} produk tersedia*\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n\n`;

            productsOnPage.forEach((prod, index) => {
                const number = startIndex + index + 1;
                const shortDesc = prod.description.length > 50 ? 
                    prod.description.substring(0, 50) + '...' : prod.description;
                
                produkText += `*${number}. ${prod.name}*\n`;
                produkText += `   💰 Harga: *Rp ${prod.price.toLocaleString('id-ID')}*\n`;
                produkText += `   📦 Stock: ${prod.stock} tersedia\n`;
                produkText += `   📝 ${shortDesc}\n\n`;

                const shortName = prod.name.length > 25 ? prod.name.substring(0, 25) + '...' : prod.name;
                keyboard.inline_keyboard.push([{
                    text: `🛒 Beli: ${shortName}`,
                    callback_data: `buy_product_${prod.id}`
                }]);
            });

            produkText += `━━━━━━━━━━━━━━━━━━━━━━`;

            const navButtons = [];
            if (page > 0) {
                navButtons.push({ text: '⬅️ Sebelumnya', callback_data: `produk_page_${page - 1}` });
            }
            if (totalPages > 1) {
                navButtons.push({ text: `📄 ${page + 1}/${totalPages}`, callback_data: 'page_info' });
            }
            if (page < totalPages - 1) {
                navButtons.push({ text: 'Selanjutnya ➡️', callback_data: `produk_page_${page + 1}` });
            }
            if (navButtons.length > 0) {
                keyboard.inline_keyboard.push(navButtons);
            }

            keyboard.inline_keyboard.push([{ text: '🔙 Menu Utama', callback_data: 'back_main' }]);

            await this.editPhotoCaption(chatId, messageId, produkText, keyboard);

        } catch (error) {
            Logger.error('Show produk digital error', { userId, error: error.message });
            await this.db.logError(error, { action: 'show_produk_digital', userId });
        }
    }

    async confirmProductPurchase(query, data) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;
        const productId = data.replace('buy_product_', '');

        try {
            const product = await this.db.getProduct(productId);
            if (!product) {
                return this.bot.sendMessage(chatId, config.ERROR_MESSAGES.PRODUCT_NOT_FOUND);
            }

            const inventory = await this.db.getProductInventory(productId);
            if (inventory.stock <= 0) {
                return this.bot.sendMessage(chatId, config.ERROR_MESSAGES.STOCK_EMPTY);
            }

            const user = await this.userManager.getUser(userId);
            const currentSaldo = user ? user.saldo : 0;

            const keyboard = { inline_keyboard: [] };

            if (product.paymentMethod === 'auto' || product.paymentMethod === 'both') {
                keyboard.inline_keyboard.push([
                    { text: '⚡ Bayar QRIS (Instant)', callback_data: `confirm_buy_product_${productId}_auto` }
                ]);
            }

            if (product.paymentMethod === 'manual' || product.paymentMethod === 'both') {
                keyboard.inline_keyboard.push([
                    { text: '📸 Bayar Manual', callback_data: `confirm_buy_product_${productId}_manual` }
                ]);
            }

            if (currentSaldo >= product.price) {
                keyboard.inline_keyboard.push([
                    { text: '💰 Bayar Pakai Saldo', callback_data: `confirm_buy_product_${productId}_saldo` }
                ]);
            } else {
                keyboard.inline_keyboard.push([
                    { text: '💰 Saldo Tidak Cukup (Top Up Dulu)', callback_data: 'topup_menu' }
                ]);
            }

            keyboard.inline_keyboard.push([{ text: '🔙 Kembali ke Produk', callback_data: 'produk_digital' }]);

            const paymentMethodText = product.paymentMethod === 'auto' ? '⚡ QRIS Auto' : 
                                     product.paymentMethod === 'manual' ? '📸 Manual' : '🔄 QRIS & Manual';

            const confirmText = `╔═══════════════════════╗\n` +
                `║  🛍️ *KONFIRMASI BELI*  ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *📦 DETAIL PRODUK* ━━━━┓\n` +
                `┃ 📦 Nama: *${product.name}*\n` +
                `┃ 📝 ${product.description}\n` +
                `┃ 💰 Harga: *Rp ${product.price.toLocaleString('id-ID')}*\n` +
                `┃ 📦 Stock: ${inventory.stock} tersedia\n` +
                `┃ 💳 Metode: ${paymentMethodText}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━━ *💰 SALDO ANDA* ━━━━┓\n` +
                `┃ 💎 Saldo: Rp ${currentSaldo.toLocaleString('id-ID')}\n` +
                `┃ ${currentSaldo >= product.price ? '✅ Saldo mencukupi' : '❌ Saldo tidak cukup'}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `💡 Pilih metode pembayaran:`;

            if (product.imageFileId) {
                try {
                    await this.bot.deleteMessage(chatId, messageId);
                } catch (e) {}
                
                await this.bot.sendPhoto(chatId, product.imageFileId, {
                    caption: confirmText,
                    reply_markup: keyboard,
                    parse_mode: 'Markdown'
                });
            } else {
                await this.editPhotoCaption(chatId, messageId, confirmText, keyboard);
            }

        } catch (error) {
            Logger.error('Confirm product purchase error', { userId, productId, error: error.message });
            await this.db.logError(error, { action: 'confirm_purchase', userId, productId });
        }
    }

    async processProductPurchase(query, data) {
        const chatId = query.message.chat.id;
        const userId = query.from.id;
        const dataParts = data.replace('confirm_buy_product_', '').split('_');
        const productId = dataParts[0];
        const paymentMethod = dataParts[1];

        try {
            if (paymentMethod === 'saldo') {
                const result = await this.productManager.purchaseProduct(userId, productId, 'saldo');
                
                if (!result.success) {
                    return this.bot.sendMessage(chatId, result.error);
                }

                const delivery = await this.productManager.deliverProduct(result.orderId, userId);
                
                if (delivery.success) {
                    await this.sendProductToUser(userId, result.product, result.orderId, delivery.deliveryData, result.newBalance);
                    
                    await this.sendTestimoni(result.product, userId);
                }

                await this.notifyOwnerPurchase(result.orderId, userId, result.product, 'saldo');

            } else if (paymentMethod === 'auto') {
                const product = await this.db.getProduct(productId);
                const payment = await this.paymentHandler.createQRISPayment(userId, product.price);
                
                if (!payment.success) {
                    return this.bot.sendMessage(chatId, payment.error);
                }

                const orderId = `ORD-${Date.now()}`;
                await this.db.saveOrder(orderId, {
                    userId: userId.toString(),
                    productId,
                    productName: product.name,
                    price: product.price,
                    status: 'pending',
                    paymentMethod: 'qris_auto',
                    transactionId: payment.data.id,
                    createdAt: new Date().toISOString()
                });

                const text = `╔═══════════════════════╗\n` +
                    `║  🛍️ *PEMBAYARAN PRODUK* ║\n` +
                    `╚═══════════════════════╝\n\n` +
                    `┏━━━━ *📦 DETAIL ORDER* ━━━━┓\n` +
                    `┃ 📦 Produk: ${product.name}\n` +
                    `┃ 🆔 Order ID: \`${orderId}\`\n` +
                    `┃ 🆔 Trx ID: \`${payment.data.id}\`\n` +
                    `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                    `┏━━━ *💳 DETAIL BAYAR* ━━━┓\n` +
                    `┃ 💰 Harga: Rp ${product.price.toLocaleString("id-ID")}\n` +
                    `┃ 🧾 Admin: Rp ${payment.data.fee.toLocaleString("id-ID")}\n` +
                    `┃ 💸 Total: Rp ${payment.data.nominal.toLocaleString("id-ID")}\n` +
                    `┃ 📅 Expired: ${payment.data.expired_at}\n` +
                    `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                    `📲 *Scan QR dengan e-wallet Anda*\n\n` +
                    `✅ Produk dikirim otomatis setelah\n` +
                    `   pembayaran berhasil!\n\n` +
                    `━━━━━━━━━━━━━━━━━━━━━━`;

                await this.bot.sendPhoto(chatId, payment.qrBuffer, {
                    caption: text,
                    parse_mode: "Markdown",
                    reply_markup: {
                        inline_keyboard: [[
                            { text: "❌ BATALKAN", callback_data: `cancel_deposit_${payment.data.id}` }
                        ]]
                    }
                });

            } else if (paymentMethod === 'manual') {
                await this.bot.sendMessage(chatId,
                    `╔═══════════════════════╗\n` +
                    `║  📸 *BAYAR MANUAL*     ║\n` +
                    `╚═══════════════════════╝\n\n` +
                    `⚠️ Fitur pembayaran manual untuk\n` +
                    `produk sedang dalam pengembangan.\n\n` +
                    `Silakan gunakan metode lain:\n` +
                    `• ⚡ QRIS Otomatis\n` +
                    `• 💰 Saldo Bot\n\n` +
                    `━━━━━━━━━━━━━━━━━━━━━━\n` +
                    `Hubungi: @Jeeyhosting untuk bantuan`,
                    { parse_mode: 'Markdown' }
                );
            }

        } catch (error) {
            Logger.error('Process product purchase error', { userId, productId, error: error.message });
            await this.db.logError(error, { action: 'process_purchase', userId, productId });
            
            await this.bot.sendMessage(chatId, config.ERROR_MESSAGES.SYSTEM_ERROR);
        }
    }

    async sendProductToUser(userId, product, orderId, deliveryData, newBalance) {
        try {
            const timeInfo = this.getIndonesianTime();

            if (deliveryData.contentType === 'file') {
                await this.bot.sendDocument(userId, deliveryData.fileId, {
                    caption: 
                        `╔═══════════════════════╗\n` +
                        `║  ✅ *PEMBELIAN BERHASIL!* ║\n` +
                        `╚═══════════════════════╝\n\n` +
                        `┏━━━━ *📦 INFO ORDER* ━━━━┓\n` +
                        `┃ 🆔 Order ID: \`${orderId}\`\n` +
                        `┃ 📦 Produk: ${product.name}\n` +
                        `┃ 💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n` +
                        `┃ 📅 Waktu: ${timeInfo.full}\n` +
                        `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                        `┏━━━━ *💰 SALDO* ━━━━┓\n` +
                        `┃ 💎 Sisa: Rp ${newBalance.toLocaleString('id-ID')}\n` +
                        `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                        `📄 *File produk terlampir di atas*\n` +
                        `🔐 Checksum: \`${deliveryData.checksum}\`\n\n` +
                        `━━━━━━━━━━━━━━━━━━━━━━\n` +
                        `✨ Terima kasih telah berbelanja!\n` +
                        `💬 Bantuan: @Jeeyhosting`,
                    parse_mode: 'Markdown'
                });
            } else if (deliveryData.contentType === 'text') {
                await this.bot.sendMessage(userId,
                    `╔═══════════════════════╗\n` +
                    `║  ✅ *PEMBELIAN BERHASIL!* ║\n` +
                    `╚═══════════════════════╝\n\n` +
                    `┏━━━━ *📦 INFO ORDER* ━━━━┓\n` +
                    `┃ 🆔 Order ID: \`${orderId}\`\n` +
                    `┃ 📦 Produk: ${product.name}\n` +
                    `┃ 💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n` +
                    `┃ 📅 Waktu: ${timeInfo.full}\n` +
                    `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                    `┏━━━━ *💰 SALDO* ━━━━┓\n` +
                    `┃ 💎 Sisa: Rp ${newBalance.toLocaleString('id-ID')}\n` +
                    `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                    `┏━━━━ *📄 DATA PRODUK* ━━━━┓\n` +
                    `\`\`\`\n${deliveryData.content}\n\`\`\`\n` +
                    `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                    `🔐 Checksum: \`${deliveryData.checksum}\`\n\n` +
                    `━━━━━━━━━━━━━━━━━━━━━━\n` +
                    `✨ Terima kasih telah berbelanja!\n` +
                    `💬 Bantuan: @Jeeyhosting`,
                    { parse_mode: 'Markdown' }
                );
            }
        } catch (error) {
            Logger.error('Send product to user error', { userId, orderId, error: error.message });
        }
    }

    async sendTestimoni(product, userId) {
        try {
            const timeInfo = this.getIndonesianTime();
            const username = await this.getUsernameDisplay(userId);

            const text = `╔═══════════════════════╗\n` +
                `║  🎉 *TRANSAKSI BERHASIL* ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *📦 DETAIL* ━━━━┓\n` +
                `┃ 👤 Customer: @${username}\n` +
                `┃ 📦 Produk: ${product.name}\n` +
                `┃ 💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n` +
                `┃ ⚡ Status: Sukses Instan\n` +
                `┃ 📅 Waktu: ${timeInfo.full}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━ *🤖 DIGITAL STORE* ━━━┓\n` +
                `┃ ✅ Proses Cepat & Aman\n` +
                `┃ ✅ Pengiriman Otomatis\n` +
                `┃ ✅ Produk Berkualitas\n` +
                `┃ ✅ Support 24/7\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `📞 *Order Sekarang Juga!*`;

            if (product.imageFileId) {
                await this.bot.sendPhoto(config.TESTIMONI_CHANNEL, product.imageFileId, {
                    caption: text,
                    parse_mode: 'Markdown'
                });
            } else {
                await this.bot.sendMessage(config.TESTIMONI_CHANNEL, text, {
                    parse_mode: 'Markdown'
                });
            }

            const testifyLog = await this.db.fileManager.atomicRead(this.db.paths.channel.testify, []);
            testifyLog.push({
                timestamp: new Date().toISOString(),
                userId: userId.toString(),
                productId: product.id,
                success: true
            });
            await this.db.fileManager.atomicWrite(this.db.paths.channel.testify, testifyLog);

        } catch (error) {
            Logger.error('Send testimoni error', { error: error.message });
            
            const failedLog = await this.db.fileManager.atomicRead(this.db.paths.channel.failedSend, []);
            failedLog.push({
                timestamp: new Date().toISOString(),
                userId: userId.toString(),
                productId: product.id,
                error: error.message
            });
            await this.db.fileManager.atomicWrite(this.db.paths.channel.failedSend, failedLog);
        }
    }

    async notifyOwnerPurchase(orderId, userId, product, method) {
        try {
            const timeInfo = this.getIndonesianTime();
            const username = await this.getUsernameDisplay(userId);

            await this.bot.sendMessage(config.OWNER_ID,
                `╔═══════════════════════╗\n` +
                `║  🛍️ *PEMBELIAN BARU!*  ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *📦 INFO ORDER* ━━━━┓\n` +
                `┃ 🆔 Order ID: \`${orderId}\`\n` +
                `┃ 👤 User ID: \`${userId}\`\n` +
                `┃ 📱 Username: @${username}\n` +
                `┃ 📦 Produk: ${product.name}\n` +
                `┃ 💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n` +
                `┃ 💳 Metode: ${method.toUpperCase()}\n` +
                `┃ 📅 Waktu: ${timeInfo.full}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `✅ *Produk telah dikirim otomatis!*\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━`,
                { parse_mode: 'Markdown' }
            );
        } catch (error) {
            Logger.error('Notify owner purchase error', { error: error.message });
        }
    }

    // ============================================
    // 📊 USER INFO DISPLAYS
    // ============================================

    async showBalance(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        try {
            const user = await this.userManager.getUser(userId);
            const saldo = user ? user.saldo : 0;
            const stats = await this.db.getUserStats(userId);

            const keyboard = {
                inline_keyboard: [
                    [{ text: '💳 Top Up Saldo', callback_data: 'topup_menu' }],
                    [{ text: '🛍️ Belanja Produk', callback_data: 'produk_digital' }],
                    [{ text: '🔙 Menu Utama', callback_data: 'back_main' }]
                ]
            };

            const timeInfo = this.getIndonesianTime();

            const text = `╔═══════════════════════╗\n` +
                `║   💰 *CEK SALDO*       ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *👤 INFO AKUN* ━━━━┓\n` +
                `┃ 👤 User ID: \`${userId}\`\n` +
                `┃ 💎 Saldo: *Rp ${saldo.toLocaleString('id-ID')}*\n` +
                `┃ 📅 Tanggal: ${timeInfo.date}\n` +
                `┃ 🕐 Waktu: ${timeInfo.time} WIB\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━━ *📊 STATISTIK* ━━━━┓\n` +
                `┃ 🛒 Total Pembelian: ${stats.totalPurchases || 0}\n` +
                `┃ 💸 Total Pengeluaran: Rp ${(stats.totalSpent || 0).toLocaleString('id-ID')}\n` +
                `┃ 💳 Total Deposit: ${stats.totalDeposits || 0}x\n` +
                `┃ 💰 Total Deposited: Rp ${(stats.totalDeposited || 0).toLocaleString('id-ID')}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `💡 *Saldo dapat digunakan untuk:*\n` +
                `• Membeli produk digital\n` +
                `• Proses pembelian instant\n` +
                `• Tanpa biaya tambahan`;

            await this.editPhotoCaption(chatId, messageId, text, keyboard);

        } catch (error) {
            Logger.error('Show balance error', { userId, error: error.message });
        }
    }

    async showOrderHistory(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        try {
            const allOrders = await this.db.getOrdersByStatus('completed');
            const userOrders = allOrders.filter(o => parseInt(o.userId) === userId);

            const keyboard = {
                inline_keyboard: [
                    [{ text: '🛍️ Belanja Lagi', callback_data: 'produk_digital' }],
                    [{ text: '🔙 Menu Utama', callback_data: 'back_main' }]
                ]
            };

            let text = `╔═══════════════════════╗\n` +
                `║  📜 *RIWAYAT ORDER*    ║\n` +
                `╚═══════════════════════╝\n\n`;

            if (userOrders.length === 0) {
                text += `📄 *Belum ada riwayat order.*\n\n` +
                    `Anda belum pernah melakukan\n` +
                    `pembelian produk.\n\n` +
                    `━━━━━━━━━━━━━━━━━━━━━━\n` +
                    `🛍️ Mulai belanja di menu\n` +
                    `   Produk Digital!`;
            } else {
                const recent = userOrders.slice(-10).reverse();
                
                text += `📊 *Total Order: ${userOrders.length}*\n` +
                    `📄 *Menampilkan ${Math.min(10, userOrders.length)} terakhir*\n\n` +
                    `━━━━━━━━━━━━━━━━━━━━━━\n\n`;

                recent.forEach((order, index) => {
                    const date = new Date(order.completedAt).toLocaleDateString('id-ID');
                    text += `*${index + 1}. ${order.productName}*\n`;
                    text += `   💰 Rp ${order.price.toLocaleString('id-ID')}\n`;
                    text += `   🆔 \`${order.orderId}\`\n`;
                    text += `   📅 ${date}\n\n`;
                });

                if (userOrders.length > 10) {
                    text += `━━━━━━━━━━━━━━━━━━━━━━\n` +
                        `... dan ${userOrders.length - 10} order lainnya\n\n`;
                }

                const totalSpent = userOrders.reduce((sum, o) => sum + o.price, 0);
                text += `━━━━━━━━━━━━━━━━━━━━━━\n` +
                    `💰 *Total Pengeluaran:*\n` +
                    `   Rp ${totalSpent.toLocaleString('id-ID')}`;
            }

            await this.editPhotoCaption(chatId, messageId, text, keyboard);

        } catch (error) {
            Logger.error('Show order history error', { userId, error: error.message });
        }
    }

    async showHelp(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;

        try {
            const keyboard = {
                inline_keyboard: [
                    [{ text: '💳 Top Up', callback_data: 'topup_menu' }],
                    [{ text: '🛍️ Belanja', callback_data: 'produk_digital' }],
                    [{ text: '🔙 Menu Utama', callback_data: 'back_main' }]
                ]
            };

            const text = `╔═══════════════════════╗\n` +
                `║   ℹ️ *BANTUAN & HELP*  ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━ *📝 CARA GUNAKAN BOT* ━━━┓\n` +
                `┃\n` +
                `┃ *1️⃣ TOP UP SALDO*\n` +
                `┃ • Klik menu "Top Up Saldo"\n` +
                `┃ • Pilih metode QRIS/Manual\n` +
                `┃ • Pilih/input nominal\n` +
                `┃ • Scan QR & bayar\n` +
                `┃ • Saldo masuk otomatis!\n` +
                `┃\n` +
                `┃ *2️⃣ BELI PRODUK*\n` +
                `┃ • Klik "Produk Digital"\n` +
                `┃ • Pilih produk yang diinginkan\n` +
                `┃ • Pilih metode pembayaran\n` +
                `┃ • Bayar dengan saldo/QRIS\n` +
                `┃ • Produk dikirim otomatis!\n` +
                `┃\n` +
                `┃ *3️⃣ CEK SALDO & RIWAYAT*\n` +
                `┃ • Klik "Cek Saldo"\n` +
                `┃ • Klik "Riwayat Order"\n` +
                `┃ • Lihat semua transaksi Anda\n` +
                `┃\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━ *💡 TIPS & TRIK* ━━━┓\n` +
                `┃ • Gunakan QRIS untuk instan\n` +
                `┃ • Top up sesuai kebutuhan\n` +
                `┃ • Screenshot order ID\n` +
                `┃ • Simpan file produk\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━ *❓ BUTUH BANTUAN?* ━━━┓\n` +
                `┃ 💬 Admin: @Jeeyhosting\n` +
                `┃ ⚡ Bot: Aktif 24/7\n` +
                `┃ 🔐 Aman & Terpercaya\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━`;

            await this.editPhotoCaption(chatId, messageId, text, keyboard);

        } catch (error) {
            Logger.error('Show help error', { error: error.message });
        }
    }

    async showRules(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;

        try {
            const keyboard = {
                inline_keyboard: [[{ text: '🔙 Menu Utama', callback_data: 'back_main' }]]
            };

            const text = `╔═══════════════════════╗\n` +
                `║ 📖 *SYARAT & KETENTUAN* ║\n` +
                `╚═══════════════════════╝\n\n` +
                `⚠️ *HARAP DIBACA DENGAN TELITI*\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n\n` +
                `*1️⃣ TENTANG SALDO*\n` +
                `• Saldo TIDAK BISA di-refund\n` +
                `• Top up sesuai kebutuhan saja\n` +
                `• Saldo hanya untuk transaksi bot\n` +
                `• Tidak bisa ditarik/dicairkan\n\n` +
                `*2️⃣ TENTANG PRODUK*\n` +
                `• Pastikan pilih produk yang benar\n` +
                `• Produk dikirim otomatis\n` +
                `• Tidak ada refund setelah kirim\n` +
                `• Screenshot/simpan file produk\n\n` +
                `*3️⃣ TENTANG PEMBAYARAN*\n` +
                `• QRIS: saldo masuk otomatis\n` +
                `• Bayar sesuai nominal yang tertera\n` +
                `• Jangan transfer kurang/lebih\n` +
                `• Expired QR tidak bisa dipakai\n\n` +
                `*4️⃣ LARANGAN*\n` +
                `🚫 Spam atau flood bot\n` +
                `🚫 Penggunaan ilegal\n` +
                `🚫 Chargeback setelah transaksi\n` +
                `🚫 Menyalahgunakan sistem\n` +
                `🚫 Berbagi akun dengan orang lain\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n\n` +
                `⚠️ *SANKSI PELANGGARAN:*\n` +
                `• Suspend akun sementara\n` +
                `• Ban permanen tanpa refund\n` +
                `• Dilaporkan ke pihak berwenang\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n\n` +
                `✅ Dengan menggunakan bot ini,\n` +
                `   Anda menyetujui semua ketentuan\n` +
                `   yang berlaku.\n\n` +
                `📞 *Support:* @Jeeyhosting\n` +
                `🤖 *Bot:* Digital Store Premium`;

            await this.editPhotoCaption(chatId, messageId, text, keyboard);

        } catch (error) {
            Logger.error('Show rules error', { error: error.message });
        }
    }

    async showMainMenu(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        try {
            const user = await this.userManager.getUser(userId);
            const products = await this.db.getAllProducts();
            const allUsers = await this.db.fileManager.atomicRead(this.db.paths.users.index, []);
            const broadcastUsers = await this.db.getBroadcastUsers();

            const keyboard = {
                inline_keyboard: [
                    [
                        { text: '🛍️ Produk Digital', callback_data: 'produk_digital' },
                        { text: '💰 Cek Saldo', callback_data: 'check_balance' }
                    ],
                    [
                        { text: '📜 Riwayat Order', callback_data: 'order_history' },
                        { text: '💳 Top Up Saldo', callback_data: 'topup_menu' }
                    ],
                    [
                        { text: '📖 Syarat & Ketentuan', callback_data: 'rules' },
                        { text: 'ℹ️ Bantuan', callback_data: 'help' }
                    ]
                ]
            };

            if (userId === config.OWNER_ID) {
                keyboard.inline_keyboard.push([
                    { text: '👑 Owner Panel', callback_data: 'owner_panel' }
                ]);
            }

            const timeInfo = this.getIndonesianTime();
            const saldo = user ? user.saldo : 0;

            const text = `╔═══════════════════════╗\n` +
                `║   🏠 *MENU UTAMA*      ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *👤 INFO AKUN* ━━━━┓\n` +
                `┃ 👤 User ID: \`${userId}\`\n` +
                `┃ 💰 Saldo: *Rp ${saldo.toLocaleString('id-ID')}*\n` +
                `┃ 📅 ${timeInfo.date}\n` +
                `┃ 🕐 ${timeInfo.time} WIB\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━━ *📊 STATISTIK* ━━━━┓\n` +
                `┃ 👥 Total User: ${allUsers.length}\n` +
                `┃ 💳 User Aktif: ${broadcastUsers.length}\n` +
                `┃ 📦 Total Produk: ${products.length}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `Pilih menu di bawah:`;

            await this.editPhotoCaption(chatId, messageId, text, keyboard);

        } catch (error) {
            Logger.error('Show main menu error', { userId, error: error.message });
        }
    }

    // ============================================
    // 👑 OWNER PANEL - FULL BUTTON BASED
    // ============================================

    async showOwnerPanel(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) {
            return this.bot.sendMessage(chatId, config.ERROR_MESSAGES.ACCESS_DENIED);
        }

        try {
            const allUsers = await this.db.fileManager.atomicRead(this.db.paths.users.index, []);
            const products = await this.db.getAllProducts();
            const pendingOrders = await this.db.getOrdersByStatus('pending');
            const broadcastUsers = await this.db.getBroadcastUsers();

            let totalSaldo = 0;
            for (const uid of allUsers) {
                const profile = await this.db.getUserProfile(uid);
                if (profile) totalSaldo += profile.saldo || 0;
            }

            const keyboard = {
                inline_keyboard: [
                    [
                        { text: '📊 Statistik Bot', callback_data: 'owner_stats' },
                        { text: '👥 Manage Users', callback_data: 'owner_manage_users' }
                    ],
                    [
                        { text: '💰 Manage Saldo', callback_data: 'owner_manage_saldo' },
                        { text: '📦 Manage Produk', callback_data: 'owner_manage_products' }
                    ],
                    [
                        { text: '📡 Broadcast', callback_data: 'owner_broadcast' },
                        { text: '⚙️ Settings', callback_data: 'owner_settings' }
                    ],
                    [{ text: '🔙 Menu Utama', callback_data: 'back_main' }]
                ]
            };

            const timeInfo = this.getIndonesianTime();

            const text = `╔═══════════════════════╗\n` +
                `║  👑 *OWNER PANEL*      ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *📊 STATISTIK* ━━━━┓\n` +
                `┃ 👥 Total Users: ${allUsers.length}\n` +
                `┃ 📡 Broadcast Users: ${broadcastUsers.length}\n` +
                `┃ 💰 Total Saldo: Rp ${totalSaldo.toLocaleString('id-ID')}\n` +
                `┃ 🛍️ Total Products: ${products.length}\n` +
                `┃ 📦 Pending Orders: ${pendingOrders.length}\n` +
                `┃ 📅 ${timeInfo.date}\n` +
                `┃ 🕐 ${timeInfo.time} WIB\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `💡 *Pilih menu manajemen:*`;

            await this.editPhotoCaption(chatId, messageId, text, keyboard);

        } catch (error) {
            Logger.error('Show owner panel error', { error: error.message });
        }
    }

    async showOwnerStats(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) return;

        try {
            const allUsers = await this.db.fileManager.atomicRead(this.db.paths.users.index, []);
            const products = await this.db.getAllProducts();
            const completedOrders = await this.db.getOrdersByStatus('completed');
            const bannedUsers = await this.db.getBannedUsers();

            let totalRevenue = 0;
            let totalSaldo = 0;
            for (const order of completedOrders) {
                totalRevenue += order.price;
            }
            for (const uid of allUsers) {
                const profile = await this.db.getUserProfile(uid);
                if (profile) totalSaldo += profile.saldo || 0;
            }

            const keyboard = {
                inline_keyboard: [
                    [{ text: '🔄 Refresh', callback_data: 'owner_stats' }],
                    [{ text: '🔙 Owner Panel', callback_data: 'owner_panel' }]
                ]
            };

            const timeInfo = this.getIndonesianTime();

            const text = `╔═══════════════════════╗\n` +
                `║  📊 *BOT STATISTICS*   ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *👥 USERS* ━━━━┓\n` +
                `┃ 👤 Total Users: ${allUsers.length}\n` +
                `┃ 🚫 Banned Users: ${bannedUsers.length}\n` +
                `┃ ✅ Active Users: ${allUsers.length - bannedUsers.length}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━━ *📦 PRODUCTS* ━━━━┓\n` +
                `┃ 🛍️ Total Products: ${products.length}\n` +
                `┃ ✅ Available: ${products.filter(p => p.stock > 0).length}\n` +
                `┃ ❌ Out of Stock: ${products.filter(p => p.stock === 0).length}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━━ *💰 REVENUE* ━━━━┓\n` +
                `┃ 💸 Total Revenue: Rp ${totalRevenue.toLocaleString('id-ID')}\n` +
                `┃ 💎 Total Saldo: Rp ${totalSaldo.toLocaleString('id-ID')}\n` +
                `┃ 🛒 Total Orders: ${completedOrders.length}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━━ *⏰ SYSTEM* ━━━━┓\n` +
                `┃ 📅 ${timeInfo.date}\n` +
                `┃ 🕐 ${timeInfo.time} WIB\n` +
                `┃ ⚡ Uptime: ${Math.floor(process.uptime() / 60)}m\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━`;

            await this.editPhotoCaption(chatId, messageId, text, keyboard);

        } catch (error) {
            Logger.error('Show owner stats error', { error: error.message });
        }
    }

    async showOwnerManageUsers(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) return;

        const keyboard = {
            inline_keyboard: [
                [{ text: '👥 Lihat Semua User', callback_data: 'owner_view_users' }],
                [{ text: '💰 Tambah Saldo User', callback_data: 'owner_add_saldo_menu' }],
                [{ text: '🚫 Ban User', callback_data: 'owner_ban_user_menu' }],
                [{ text: '🗑️ Hapus User', callback_data: 'owner_delete_user_menu' }],
                [{ text: '🔙 Owner Panel', callback_data: 'owner_panel' }]
            ]
        };

        const text = `╔═══════════════════════╗\n` +
            `║  👥 *MANAGE USERS*     ║\n` +
            `╚═══════════════════════╝\n\n` +
            `Pilih aksi manajemen user:\n\n` +
            `┏━━━━ *📋 OPSI TERSEDIA* ━━━━┓\n` +
            `┃ 👥 Lihat semua user\n` +
            `┃ 💰 Tambah saldo user\n` +
            `┃ 🚫 Ban user (button)\n` +
            `┃ 🗑️ Hapus user\n` +
            `┗━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
            `━━━━━━━━━━━━━━━━━━━━━━`;

        await this.editPhotoCaption(chatId, messageId, text, keyboard);
    }

    async showOwnerManageSaldo(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) return;

        const keyboard = {
            inline_keyboard: [
                [{ text: '➕ Tambah Saldo User', callback_data: 'owner_add_saldo_menu' }],
                [{ text: '🔙 Owner Panel', callback_data: 'owner_panel' }]
            ]
        };

        const text = `╔═══════════════════════╗\n` +
            `║  💰 *MANAGE SALDO*     ║\n` +
            `╚═══════════════════════╝\n\n` +
            `Pilih aksi manajemen saldo:\n\n` +
            `┏━━━━ *📋 FITUR* ━━━━┓\n` +
            `┃ ➕ Tambah saldo user\n` +
            `┃    (Via button wizard)\n` +
            `┗━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
            `💡 *Cara tambah saldo:*\n` +
            `1. Klik "Tambah Saldo User"\n` +
            `2. Input User ID\n` +
            `3. Input nominal\n` +
            `4. Konfirmasi\n\n` +
            `━━━━━━━━━━━━━━━━━━━━━━`;

        await this.editPhotoCaption(chatId, messageId, text, keyboard);
    }

    async startAddSaldoWizard(query) {
        const chatId = query.message.chat.id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) return;

        this.addSaldoWizardStates.set(userId, {
            step: 'waiting_user_id',
            chatId
        });

        await this.bot.sendMessage(chatId,
            `╔═══════════════════════╗\n` +
            `║  💰 *TAMBAH SALDO*     ║\n` +
            `╚═══════════════════════╝\n\n` +
            `*Step 1/2: Input User ID*\n\n` +
            `Ketik User ID target:\n\n` +
            `📌 *Contoh:* 123456789\n` +
            `💡 User ID adalah angka unik user\n\n` +
            `━━━━━━━━━━━━━━━━━━━━━━\n` +
            `Ketik User ID sekarang:`,
            { parse_mode: 'Markdown' }
        );
    }

    async startBanUserWizard(query) {
        const chatId = query.message.chat.id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) return;

        this.banUserWizardStates.set(userId, {
            step: 'waiting_user_id',
            chatId
        });

        await this.bot.sendMessage(chatId,
            `╔═══════════════════════╗\n` +
            `║  🚫 *BAN USER*         ║\n` +
            `╚═══════════════════════╝\n\n` +
            `*Step 1/2: Input User ID*\n\n` +
            `Ketik User ID yang akan di-ban:\n\n` +
            `📌 *Contoh:* 123456789\n` +
            `⚠️ *Peringatan:* User akan diblokir!\n\n` +
            `━━━━━━━━━━━━━━━━━━━━━━\n` +
            `Ketik User ID sekarang:`,
            { parse_mode: 'Markdown' }
        );
    }

    async showAllUsers(query, page = 0) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) return;

        try {
            const allUsers = await this.db.fileManager.atomicRead(this.db.paths.users.index, []);
            
            const ITEMS_PER_PAGE = 10;
            const totalPages = Math.ceil(allUsers.length / ITEMS_PER_PAGE);
            const startIndex = page * ITEMS_PER_PAGE;
            const endIndex = startIndex + ITEMS_PER_PAGE;
            const usersOnPage = allUsers.slice(startIndex, endIndex);

            const keyboard = { inline_keyboard: [] };

            let text = `╔═══════════════════════╗\n` +
                `║  👥 *DAFTAR USERS*     ║\n` +
                `╚═══════════════════════╝\n\n` +
                `📄 *Halaman ${page + 1}/${totalPages}*\n` +
                `👤 *Total: ${allUsers.length} users*\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n\n`;

            for (let i = 0; i < usersOnPage.length; i++) {
                const uid = usersOnPage[i];
                const profile = await this.db.getUserProfile(uid);
                const banStatus = await this.db.isUserBanned(uid);
                
                const num = startIndex + i + 1;
                const saldo = profile ? profile.saldo : 0;
                const status = banStatus.banned ? '🚫 BANNED' : '✅ Active';
                
                text += `*${num}. User ID: \`${uid}\`*\n`;
                text += `   💰 Saldo: Rp ${saldo.toLocaleString('id-ID')}\n`;
                text += `   📊 Status: ${status}\n\n`;

                keyboard.inline_keyboard.push([
                    { text: `👁️ View ${uid}`, callback_data: `owner_view_user_${uid}` }
                ]);
            }

            const navButtons = [];
            if (page > 0) {
                navButtons.push({ text: '⬅️ Prev', callback_data: `owner_users_page_${page - 1}` });
            }
            if (totalPages > 1) {
                navButtons.push({ text: `${page + 1}/${totalPages}`, callback_data: 'page_info' });
            }
            if (page < totalPages - 1) {
                navButtons.push({ text: 'Next ➡️', callback_data: `owner_users_page_${page + 1}` });
            }
            if (navButtons.length > 0) {
                keyboard.inline_keyboard.push(navButtons);
            }

            keyboard.inline_keyboard.push([{ text: '🔙 Back', callback_data: 'owner_manage_users' }]);

            await this.editPhotoCaption(chatId, messageId, text, keyboard);

        } catch (error) {
            Logger.error('Show all users error', { error: error.message });
        }
    }

    async showUserDetail(query, data) {
        const chatId = query.message.chat.id;
        const userId = query.from.id;
        const targetUserId = parseInt(data.replace('owner_view_user_', ''));

        if (userId !== config.OWNER_ID) return;

        try {
            const profile = await this.db.getUserProfile(targetUserId);
            if (!profile) {
                return this.bot.sendMessage(chatId, '❌ User tidak ditemukan.');
            }

            const stats = await this.db.getUserStats(targetUserId);
            const banStatus = await this.db.isUserBanned(targetUserId);
            const fraudScore = this.security.getFraudScore(targetUserId);

            const keyboard = {
                inline_keyboard: []
            };

            if (banStatus.banned) {
                keyboard.inline_keyboard.push([
                    { text: '✅ Unban User', callback_data: `owner_unban_user_${targetUserId}` }
                ]);
            }

            keyboard.inline_keyboard.push([{ text: '🔙 Back', callback_data: 'owner_view_users' }]);

            let text = `╔═══════════════════════╗\n` +
                `║  👤 *USER DETAIL*      ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *📋 INFO* ━━━━┓\n` +
                `┃ 🆔 ID: \`${targetUserId}\`\n` +
                `┃ 💰 Saldo: Rp ${(profile.saldo || 0).toLocaleString('id-ID')}\n` +
                `┃ 📅 Registered: ${profile.registeredAt}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `┏━━━━ *📊 STATS* ━━━━┓\n` +
                `┃ 🛒 Total Orders: ${stats.totalPurchases || 0}\n` +
                `┃ 💸 Total Spent: Rp ${(stats.totalSpent || 0).toLocaleString('id-ID')}\n` +
                `┃ 💳 Total Deposits: ${stats.totalDeposits || 0}\n` +
                `┃ 🕐 Last Active: ${stats.lastActivity || 'Never'}\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n`;

            if (banStatus.banned) {
                text += `┏━━━━ *🚫 BAN INFO* ━━━━┓\n` +
                    `┃ Status: BANNED\n` +
                    `┃ Reason: ${banStatus.reason}\n` +
                    `┃ Unban At: ${banStatus.unbanAt || 'Never'}\n` +
                    `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n`;
            }

            text += `⚠️ *Fraud Score:* ${fraudScore}/3\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━`;

            await this.bot.sendMessage(chatId, text, {
                reply_markup: keyboard,
                parse_mode: 'Markdown'
            });

        } catch (error) {
            Logger.error('Show user detail error', { error: error.message });
        }
    }

    async processUnbanUser(query, data) {
        const chatId = query.message.chat.id;
        const userId = query.from.id;
        const targetUserId = parseInt(data.replace('owner_unban_user_', ''));

        if (userId !== config.OWNER_ID) return;

        try {
            await this.db.unbanUser(targetUserId);

            await this.db.logAdminAction({
                adminId: userId,
                action: 'UNBAN_USER',
                targetUserId: targetUserId.toString()
            });

            await this.bot.sendMessage(chatId,
                `✅ *USER UNBANNED*\n\n` +
                `👤 User ID: \`${targetUserId}\`\n\n` +
                `User dapat mengakses bot kembali.`,
                { parse_mode: 'Markdown' }
            );

            try {
                await this.bot.sendMessage(targetUserId,
                    `✅ *AKUN TELAH DIBUKA*\n\n` +
                    `Akun Anda telah di-unban.\n` +
                    `Ketik /start untuk menggunakan bot.`,
                    { parse_mode: 'Markdown' }
                );
            } catch (e) {
                Logger.warn('Could not notify unbanned user', { targetUserId });
            }

        } catch (error) {
            Logger.error('Process unban user error', { error: error.message });
        }
    }

    async showOwnerManageProducts(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) return;

        const keyboard = {
            inline_keyboard: [
                [{ text: '➕ Tambah Produk', callback_data: 'owner_add_product' }],
                [{ text: '📦 Lihat Semua Produk', callback_data: 'owner_list_products' }],
                [{ text: '📊 Manage Stock', callback_data: 'owner_manage_stock' }],
                [{ text: '🔙 Owner Panel', callback_data: 'owner_panel' }]
            ]
        };

        const text = `╔═══════════════════════╗\n` +
            `║  📦 *MANAGE PRODUCTS*  ║\n` +
            `╚═══════════════════════╝\n\n` +
            `Pilih aksi manajemen produk:\n\n` +
            `┏━━━━ *📋 OPSI* ━━━━┓\n` +
            `┃ ➕ Tambah produk baru\n` +
            `┃ 📦 Lihat semua produk\n` +
            `┃ 📊 Manage stock produk\n` +
            `┃ 🗑️ Hapus produk\n` +
            `┗━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
            `━━━━━━━━━━━━━━━━━━━━━━`;

        await this.editPhotoCaption(chatId, messageId, text, keyboard);
    }

    async startProductAddWizard(query) {
        const chatId = query.message.chat.id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) return;

        this.productAddWizardStates.set(userId, {
            step: 'name',
            data: {},
            chatId
        });

        await this.bot.sendMessage(chatId,
            `╔═══════════════════════╗\n` +
            `║  ➕ *TAMBAH PRODUK*    ║\n` +
            `╚═══════════════════════╝\n\n` +
            `*Step 1/6: Nama Produk*\n\n` +
            `Ketik nama produk:\n\n` +
            `📌 *Contoh:* Ebook Premium\n` +
            `📌 *Min:* 3 karakter\n` +
            `📌 *Max:* 200 karakter\n\n` +
            `━━━━━━━━━━━━━━━━━━━━━━\n` +
            `Ketik nama produk sekarang:`,
            { parse_mode: 'Markdown' }
        );
    }

    async showOwnerProductList(query) {
        const chatId = query.message.chat.id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) return;

        try {
            const products = await this.db.getAllProducts();

            if (products.length === 0) {
                return this.bot.sendMessage(chatId, 
                    '📦 *Belum ada produk.*\n\n' +
                    'Tambah produk lewat menu Owner Panel.', 
                    { parse_mode: 'Markdown' }
                );
            }

            let text = `╔═══════════════════════╗\n` +
                `║  📦 *DAFTAR PRODUK*    ║\n` +
                `╚═══════════════════════╝\n\n` +
                `📊 *Total: ${products.length} produk*\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n\n`;

            const keyboard = { inline_keyboard: [] };

            for (let i = 0; i < products.length; i++) {
                const prod = products[i];
                
                text += `*${i + 1}. ${prod.name}*\n`;
                text += `   💰 Rp ${prod.price.toLocaleString('id-ID')}\n`;
                text += `   📦 Stock: ${prod.stock}\n`;
                text += `   🆔 \`${prod.id}\`\n\n`;

                keyboard.inline_keyboard.push([
                    { text: `🗑️ Hapus: ${prod.name.substring(0, 20)}...`, callback_data: `owner_del_product_${prod.id}` }
                ]);
            }

            keyboard.inline_keyboard.push([{ text: '🔙 Back', callback_data: 'owner_manage_products' }]);

            await this.bot.sendMessage(chatId, text, {
                reply_markup: keyboard,
                parse_mode: 'Markdown'
            });

        } catch (error) {
            Logger.error('Show owner product list error', { error: error.message });
        }
    }

    async confirmDeleteProduct(query, data) {
        const chatId = query.message.chat.id;
        const userId = query.from.id;
        const productId = data.replace('owner_del_product_', '');

        if (userId !== config.OWNER_ID) return;

        try {
            const product = await this.db.getProduct(productId);
            if (!product) {
                return this.bot.sendMessage(chatId, '❌ Produk tidak ditemukan.');
            }

            const keyboard = {
                inline_keyboard: [
                    [
                        { text: '✅ Ya, Hapus', callback_data: `confirm_del_product_${productId}` },
                        { text: '❌ Batal', callback_data: 'owner_list_products' }
                    ]
                ]
            };

            await this.bot.sendMessage(chatId,
                `⚠️ *KONFIRMASI HAPUS PRODUK*\n\n` +
                `Yakin ingin hapus produk ini?\n\n` +
                `📦 *Nama:* ${product.name}\n` +
                `💰 *Harga:* Rp ${product.price.toLocaleString('id-ID')}\n` +
                `📦 *Stock:* ${product.stock}\n` +
                `🆔 *ID:* \`${productId}\`\n\n` +
                `⚠️ *Tindakan ini tidak bisa dibatalkan!*`,
                {
                    reply_markup: keyboard,
                    parse_mode: 'Markdown'
                }
            );

        } catch (error) {
            Logger.error('Confirm delete product error', { error: error.message });
        }
    }

    async processDeleteProduct(query, data) {
        const chatId = query.message.chat.id;
        const userId = query.from.id;
        const productId = data.replace('confirm_del_product_', '');

        if (userId !== config.OWNER_ID) return;

        try {
            const product = await this.db.getProduct(productId);
            if (!product) {
                return this.bot.sendMessage(chatId, '❌ Produk tidak ditemukan.');
            }

            await this.db.deleteProduct(productId);

            await this.db.logAdminAction({
                adminId: userId,
                action: 'DELETE_PRODUCT',
                productId,
                productName: product.name
            });

            await this.bot.sendMessage(chatId,
                `✅ *PRODUK DIHAPUS!*\n\n` +
                `📦 Nama: ${product.name}\n` +
                `🆔 ID: \`${productId}\`\n\n` +
                `Produk dan semua data terkait\n` +
                `telah dihapus dari sistem.`,
                { parse_mode: 'Markdown' }
            );

        } catch (error) {
            Logger.error('Process delete product error', { error: error.message });
        }
    }

    async startBroadcastWizard(query) {
        const chatId = query.message.chat.id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) return;

        this.broadcastWizardStates.set(userId, {
            step: 'waiting_message',
            chatId
        });

        await this.bot.sendMessage(chatId,
            `╔═══════════════════════╗\n` +
            `║  📡 *BROADCAST*        ║\n` +
            `╚═══════════════════════╝\n\n` +
            `*Kirim pesan broadcast:*\n\n` +
            `💡 *Anda bisa kirim:*\n` +
            `• Text biasa\n` +
            `• Text dengan foto\n` +
            `• Markdown formatting\n\n` +
            `📌 *Tips:*\n` +
            `• Gunakan *bold* untuk tebal\n` +
            `• Gunakan _italic_ untuk miring\n` +
            `• Gunakan \`code\` untuk code\n\n` +
            `━━━━━━━━━━━━━━━━━━━━━━\n` +
            `Ketik atau kirim foto+caption:`,
            { parse_mode: 'Markdown' }
        );
    }

    async showOwnerSettings(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const userId = query.from.id;

        if (userId !== config.OWNER_ID) return;

        const keyboard = {
            inline_keyboard: [
                [{ text: '🔙 Owner Panel', callback_data: 'owner_panel' }]
            ]
        };

        const text = `╔═══════════════════════╗\n` +
            `║  ⚙️ *BOT SETTINGS*     ║\n` +
            `╚═══════════════════════╝\n\n` +
            `┏━━━━ *🔧 KONFIGURASI* ━━━━┓\n` +
            `┃ 🤖 Bot: @${(await this.bot.getMe()).username}\n` +
            `┃ 👑 Owner: \`${config.OWNER_ID}\`\n` +
            `┃ 📢 Channel: ${config.TESTIMONI_CHANNEL}\n` +
            `┃ 🌍 Timezone: ${config.TIMEZONE}\n` +
            `┗━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
            `┏━━━━ *🔐 SECURITY* ━━━━┓\n` +
            `┃ ✅ Rate Limiting: ${config.FEATURES.RATE_LIMITING_ENABLED ? 'ON' : 'OFF'}\n` +
            `┃ ✅ Fraud Detection: ${config.FEATURES.FRAUD_DETECTION_ENABLED ? 'ON' : 'OFF'}\n` +
            `┃ ✅ Encryption: ${config.FEATURES.ENCRYPTION_ENABLED ? 'ON' : 'OFF'}\n` +
            `┗━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
            `┏━━━━ *💾 DATABASE* ━━━━┓\n` +
            `┃ ✅ Auto Backup: ${config.BACKUP_ENABLED ? 'ON' : 'OFF'}\n` +
            `┃ ✅ Cache: ${config.CACHE_ENABLED ? 'ON' : 'OFF'}\n` +
            `┗━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
            `━━━━━━━━━━━━━━━━━━━━━━\n` +
            `⚙️ Untuk mengubah setting,\n` +
            `edit file config.js`;

        await this.editPhotoCaption(chatId, messageId, text, keyboard);
    }

    // ============================================
    // 📝 MESSAGE HANDLERS (untuk wizard input)
    // ============================================

    async handleMessage(msg) {
        const userId = msg.from.id;
        const chatId = msg.chat.id;
        const text = msg.text;

        if (!text || text.startsWith('/')) return;

        // ✅ Handle deposit wizard
        const depositState = this.depositWizardStates?.get(userId);
        if (depositState?.step === 'waiting_amount') {
            const amount = parseInt(text);
            const validation = InputValidator.validateAmount(amount);
            
            if (!validation.valid) {
                return this.bot.sendMessage(chatId, `❌ ${validation.error}`);
            }

            this.depositWizardStates.delete(userId);
            await this.processDeposit(userId, chatId, amount);
            return;
        }

        // ✅ Handle add saldo wizard
        const addSaldoState = this.addSaldoWizardStates?.get(userId);
        if (addSaldoState) {
            if (addSaldoState.step === 'waiting_user_id') {
                const targetUserId = parseInt(text);
                const validation = InputValidator.validateUserId(targetUserId);
                
                if (!validation.valid) {
                    return this.bot.sendMessage(chatId, `❌ ${validation.error}`);
                }

                const targetUser = await this.db.getUserProfile(targetUserId);
                if (!targetUser) {
                    return this.bot.sendMessage(chatId, '❌ User tidak ditemukan.');
                }

                addSaldoState.step = 'waiting_amount';
                addSaldoState.targetUserId = targetUserId;
                this.addSaldoWizardStates.set(userId, addSaldoState);

                await this.bot.sendMessage(chatId,
                    `✅ *User Found!*\n\n` +
                    `👤 User ID: \`${targetUserId}\`\n` +
                    `💰 Saldo saat ini: Rp ${(targetUser.saldo || 0).toLocaleString('id-ID')}\n\n` +
                    `*Step 2/2: Input Nominal*\n\n` +
                    `Ketik nominal yang akan ditambahkan:\n\n` +
                    `📌 *Contoh:* 50000\n` +
                    `📌 *Minimal:* 100\n\n` +
                    `━━━━━━━━━━━━━━━━━━━━━━\n` +
                    `Ketik nominal sekarang:`,
                    { parse_mode: 'Markdown' }
                );
                return;
            }
            else if (addSaldoState.step === 'waiting_amount') {
                const amount = parseInt(text);
                const validation = InputValidator.validateAmount(amount);
                
                if (!validation.valid) {
                    return this.bot.sendMessage(chatId, `❌ ${validation.error}`);
                }

                const result = await this.userManager.updateUserBalance(addSaldoState.targetUserId, amount, 'add');

                if (!result.success) {
                    this.addSaldoWizardStates.delete(userId);
                    return this.bot.sendMessage(chatId, result.error);
                }

                await this.db.logAdminAction({
                    adminId: userId,
                    action: 'ADD_SALDO',
                    targetUserId: addSaldoState.targetUserId.toString(),
                    amount,
                    newBalance: result.newBalance
                });

                this.addSaldoWizardStates.delete(userId);

                await this.bot.sendMessage(chatId,
                    `✅ *SALDO BERHASIL DITAMBAHKAN!*\n\n` +
                    `👤 User ID: \`${addSaldoState.targetUserId}\`\n` +
                    `💰 Jumlah: +Rp ${amount.toLocaleString('id-ID')}\n` +
                    `💎 Saldo baru: Rp ${result.newBalance.toLocaleString('id-ID')}\n\n` +
                    `━━━━━━━━━━━━━━━━━━━━━━\n` +
                    `✨ User akan mendapat notifikasi!`,
                    { parse_mode: 'Markdown' }
                );

                // Notify user
                try {
                    await this.bot.sendMessage(addSaldoState.targetUserId,
                        `✅ *SALDO DITAMBAHKAN!*\n\n` +
                        `💰 +Rp ${amount.toLocaleString('id-ID')}\n` +
                        `💎 Saldo baru: Rp ${result.newBalance.toLocaleString('id-ID')}\n\n` +
                        `Terima kasih! 🎉`,
                        { parse_mode: 'Markdown' }
                    );
                } catch (e) {
                    Logger.warn('Could not notify user', { targetUserId: addSaldoState.targetUserId });
                }
                return;
            }
        }

        // ✅ Handle ban user wizard
        const banUserState = this.banUserWizardStates?.get(userId);
        if (banUserState) {
            if (banUserState.step === 'waiting_user_id') {
                const targetUserId = parseInt(text);
                const validation = InputValidator.validateUserId(targetUserId);
                
                if (!validation.valid) {
                    return this.bot.sendMessage(chatId, `❌ ${validation.error}`);
                }

                const targetUser = await this.db.getUserProfile(targetUserId);
                if (!targetUser) {
                    return this.bot.sendMessage(chatId, '❌ User tidak ditemukan.');
                }

                banUserState.step = 'waiting_reason';
                banUserState.targetUserId = targetUserId;
                this.banUserWizardStates.set(userId, banUserState);

                await this.bot.sendMessage(chatId,
                    `✅ *User Found!*\n\n` +
                    `👤 User ID: \`${targetUserId}\`\n` +
                    `💰 Saldo: Rp ${(targetUser.saldo || 0).toLocaleString('id-ID')}\n\n` +
                    `*Step 2/2: Alasan Ban*\n\n` +
                    `Ketik alasan ban:\n\n` +
                    `📌 *Contoh:* Spam berlebihan\n` +
                    `📌 *Min:* 5 karakter\n\n` +
                    `━━━━━━━━━━━━━━━━━━━━━━\n` +
                    `Ketik alasan sekarang:`,
                    { parse_mode: 'Markdown' }
                );
                return;
            }
            else if (banUserState.step === 'waiting_reason') {
                if (text.length < 5) {
                    return this.bot.sendMessage(chatId, '❌ Alasan minimal 5 karakter.');
                }

                await this.db.banUser(banUserState.targetUserId, text, config.BAN_DURATION, userId);

                await this.db.logAdminAction({
                    adminId: userId,
                    action: 'BAN_USER',
                    targetUserId: banUserState.targetUserId.toString(),
                    reason: text
                });

                this.banUserWizardStates.delete(userId);

                await this.bot.sendMessage(chatId,
                    `✅ *USER BERHASIL DI-BAN!*\n\n` +
                    `👤 User ID: \`${banUserState.targetUserId}\`\n` +
                    `📝 Alasan: ${text}\n` +
                    `⏰ Durasi: ${config.BAN_DURATION / 1000 / 60 / 60} jam\n\n` +
                    `━━━━━━━━━━━━━━━━━━━━━━\n` +
                    `🚫 User tidak bisa akses bot!`,
                    { parse_mode: 'Markdown' }
                );

                // Notify user
                try {
                    await this.bot.sendMessage(banUserState.targetUserId,
                        `🚫 *AKUN ANDA DI-BAN!*\n\n` +
                        `Alasan: ${text}\n\n` +
                        `Hubungi admin untuk info lebih lanjut:\n` +
                        `@Jeeyhosting`,
                        { parse_mode: 'Markdown' }
                    );
                } catch (e) {
                    Logger.warn('Could not notify banned user', { targetUserId: banUserState.targetUserId });
                }
                return;
            }
        }

        // ✅ Handle product add wizard
        const productState = this.productAddWizardStates?.get(userId);
        if (productState) {
            await this.handleProductAddStep(msg, productState);
            return;
        }

        // ✅ Handle broadcast wizard
        const broadcastState = this.broadcastWizardStates?.get(userId);
        if (broadcastState?.step === 'waiting_message') {
            await this.processBroadcast(userId, chatId, text);
            this.broadcastWizardStates.delete(userId);
            return;
        }
    }

    async handleProductAddStep(msg, state) {
        const userId = msg.from.id;
        const chatId = msg.chat.id;
        const text = msg.text;

        try {
            switch (state.step) {
                case 'name':
                    if (text.length < 3 || text.length > 200) {
                        return this.bot.sendMessage(chatId, '❌ Nama produk harus 3-200 karakter.');
                    }
                    state.data.name = text;
                    state.step = 'description';
                    this.productAddWizardStates.set(userId, state);
                    
                    await this.bot.sendMessage(chatId,
                        `✅ *Nama:* ${text}\n\n` +
                        `*Step 2/6: Deskripsi*\n\n` +
                        `Ketik deskripsi produk:\n\n` +
                        `📌 *Contoh:* Ebook lengkap 100+ halaman\n` +
                        `📌 *Min:* 10 karakter\n` +
                        `📌 *Max:* 1000 karakter\n\n` +
                        `━━━━━━━━━━━━━━━━━━━━━━\n` +
                        `Ketik deskripsi sekarang:`,
                        { parse_mode: 'Markdown' }
                    );
                    break;

                case 'description':
                    if (text.length < 10 || text.length > 1000) {
                        return this.bot.sendMessage(chatId, '❌ Deskripsi harus 10-1000 karakter.');
                    }
                    state.data.description = text;
                    state.step = 'price';
                    this.productAddWizardStates.set(userId, state);
                    
                    await this.bot.sendMessage(chatId,
                        `✅ *Deskripsi tersimpan*\n\n` +
                        `*Step 3/6: Harga*\n\n` +
                        `Ketik harga produk (angka saja):\n\n` +
                        `📌 *Contoh:* 50000\n` +
                        `📌 *Minimal:* 100\n\n` +
                        `━━━━━━━━━━━━━━━━━━━━━━\n` +
                        `Ketik harga sekarang:`,
                        { parse_mode: 'Markdown' }
                    );
                    break;

                case 'price':
                    const priceValidation = InputValidator.validateAmount(parseInt(text));
                    if (!priceValidation.valid) {
                        return this.bot.sendMessage(chatId, `❌ ${priceValidation.error}`);
                    }
                    state.data.price = priceValidation.value;
                    state.step = 'stock';
                    this.productAddWizardStates.set(userId, state);
                    
                    await this.bot.sendMessage(chatId,
                        `✅ *Harga:* Rp ${priceValidation.value.toLocaleString('id-ID')}\n\n` +
                        `*Step 4/6: Stock*\n\n` +
                        `Ketik jumlah stock:\n\n` +
                        `📌 *Contoh:* 100\n` +
                        `📌 *Minimal:* 0\n\n` +
                        `━━━━━━━━━━━━━━━━━━━━━━\n` +
                        `Ketik stock sekarang:`,
                        { parse_mode: 'Markdown' }
                    );
                    break;

                case 'stock':
                    const stockValidation = InputValidator.validateNumeric(parseInt(text), 0);
                    if (!stockValidation.valid) {
                        return this.bot.sendMessage(chatId, `❌ ${stockValidation.error}`);
                    }
                    state.data.stock = stockValidation.value;
                    state.step = 'payment_method';
                    this.productAddWizardStates.set(userId, state);
                    
                    const keyboard = {
                        inline_keyboard: [
                            [{ text: '⚡ QRIS Otomatis', callback_data: 'product_method_auto' }],
                            [{ text: '📸 Manual', callback_data: 'product_method_manual' }],
                            [{ text: '🔄 Both (QRIS & Manual)', callback_data: 'product_method_both' }]
                        ]
                    };

                    await this.bot.sendMessage(chatId,
                        `✅ *Stock:* ${stockValidation.value}\n\n` +
                        `*Step 5/6: Metode Pembayaran*\n\n` +
                        `Pilih metode pembayaran produk:\n\n` +
                        `⚡ *QRIS Auto* - Instant payment\n` +
                        `📸 *Manual* - Upload bukti transfer\n` +
                        `🔄 *Both* - User bisa pilih\n\n` +
                        `━━━━━━━━━━━━━━━━━━━━━━\n` +
                        `Klik pilihan di bawah:`,
                        {
                            reply_markup: keyboard,
                            parse_mode: 'Markdown'
                        }
                    );
                    break;

                case 'product_data':
                    // Save product with text data
                    const productId = `PROD-${Date.now()}`;
                    
                    await this.db.saveProduct(productId, {
                        id: productId,
                        name: state.data.name,
                        description: state.data.description,
                        price: state.data.price,
                        paymentMethod: state.data.paymentMethod,
                        imageFileId: state.data.imageFileId || null,
                        productData: {
                            type: 'text',
                            content: text
                        },
                        createdAt: new Date().toISOString(),
                        createdBy: userId
                    });

                    await this.db.updateProductInventory(productId, {
                        stock: state.data.stock,
                        reserved: 0,
                        sold: 0
                    });

                    this.productAddWizardStates.delete(userId);

                    const paymentText = state.data.paymentMethod === 'auto' ? '⚡ QRIS Auto' : 
                                       state.data.paymentMethod === 'manual' ? '📸 Manual' : '🔄 Both';

                    await this.bot.sendMessage(chatId,
                        `╔═══════════════════════╗\n` +
                        `║  ✅ *PRODUK BERHASIL!* ║\n` +
                        `╚═══════════════════════╝\n\n` +
                        `┏━━━━ *📦 INFO PRODUK* ━━━━┓\n` +
                        `┃ 📦 Nama: ${state.data.name}\n` +
                        `┃ 📝 ${state.data.description.substring(0, 30)}...\n` +
                        `┃ 💰 Harga: Rp ${state.data.price.toLocaleString('id-ID')}\n` +
                        `┃ 📦 Stock: ${state.data.stock}\n` +
                        `┃ 💳 Metode: ${paymentText}\n` +
                        `┃ 📄 Data: Text\n` +
                        `┃ 🆔 ID: \`${productId}\`\n` +
                        `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                        `━━━━━━━━━━━━━━━━━━━━━━\n` +
                        `✨ Produk sudah aktif dan bisa dibeli!`,
                        { parse_mode: 'Markdown' }
                    );

                    await this.db.logAdminAction({
                        adminId: userId,
                        action: 'ADD_PRODUCT',
                        productId,
                        productName: state.data.name
                    });
                    break;
            }

        } catch (error) {
            Logger.error('Handle product add step error', { userId, error: error.message });
            this.productAddWizardStates.delete(userId);
            await this.bot.sendMessage(chatId, config.ERROR_MESSAGES.SYSTEM_ERROR);
        }
    }

    async handlePhoto(msg) {
        const userId = msg.from.id;
        const chatId = msg.chat.id;

        // Check if broadcast with photo
        const broadcastState = this.broadcastWizardStates?.get(userId);
        if (broadcastState?.step === 'waiting_message' && msg.caption) {
            await this.processBroadcastWithPhoto(userId, chatId, msg.caption, msg.photo[msg.photo.length - 1].file_id);
            this.broadcastWizardStates.delete(userId);
            return;
        }

        // Check if product add state
        const productState = this.productAddWizardStates?.get(userId);
        if (productState && productState.step === 'image') {
            await this.handleProductImageUpload(msg, productState);
            return;
        }
    }

    async handleProductImageUpload(msg, state) {
        const userId = msg.from.id;
        const chatId = msg.chat.id;

        try {
            const photo = msg.photo[msg.photo.length - 1];
            const fileId = photo.file_id;

            state.data.imageFileId = fileId;
            state.step = 'product_data';
            this.productAddWizardStates.set(userId, state);

            const keyboard = {
                inline_keyboard: [
                    [{ text: '📝 Input Text Data', callback_data: 'product_data_text' }],
                    [{ text: '📄 Upload File Data', callback_data: 'product_data_file' }]
                ]
            };

            await this.bot.sendMessage(chatId,
                `✅ *Gambar tersimpan!*\n\n` +
                `*Step 6/6: Data Produk*\n\n` +
                `Pilih jenis data produk:\n\n` +
                `📝 *Text* - Link, kode, akun, dll\n` +
                `📄 *File* - PDF, ZIP, dokumen, dll\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `💡 Untuk text: ketik langsung\n` +
                `💡 Untuk file: upload file\n\n` +
                `Pilih atau ketik/upload sekarang:`,
                {
                    reply_markup: keyboard,
                    parse_mode: 'Markdown'
                }
            );

        } catch (error) {
            Logger.error('Handle product image upload error', { userId, error: error.message });
            await this.bot.sendMessage(chatId, config.ERROR_MESSAGES.SYSTEM_ERROR);
        }
    }

    async handleDocument(msg) {
        const userId = msg.from.id;
        const chatId = msg.chat.id;

        const productState = this.productAddWizardStates?.get(userId);
        if (!productState || productState.step !== 'product_data') {
            return;
        }

        try {
            const document = msg.document;
            const fileId = document.file_id;
            const fileName = document.file_name;
            const fileSize = document.file_size;

            if (fileSize > config.MAX_PRODUCT_FILE_SIZE) {
                return this.bot.sendMessage(chatId,
                    `❌ ${config.ERROR_MESSAGES.FILE_TOO_LARGE}\n` +
                    `Ukuran: ${(fileSize / 1024 / 1024).toFixed(2)} MB\n` +
                    `Maksimal: ${(config.MAX_PRODUCT_FILE_SIZE / 1024 / 1024).toFixed(0)} MB`,
                    { parse_mode: 'Markdown' }
                );
            }

            const productId = `PROD-${Date.now()}`;
            
            await this.db.saveProduct(productId, {
                id: productId,
                name: productState.data.name,
                description: productState.data.description,
                price: productState.data.price,
                paymentMethod: productState.data.paymentMethod,
                imageFileId: productState.data.imageFileId || null,
                productData: {
                    type: 'file',
                    fileId,
                    fileName,
                    fileSize
                },
                createdAt: new Date().toISOString(),
                createdBy: userId
            });

            await this.db.updateProductInventory(productId, {
                stock: productState.data.stock,
                reserved: 0,
                sold: 0
            });

            this.productAddWizardStates.delete(userId);

            const paymentMethodText = productState.data.paymentMethod === 'auto' ? '⚡ QRIS Auto' : 
                                     productState.data.paymentMethod === 'manual' ? '📸 Manual' : '🔄 Both';

            await this.bot.sendMessage(chatId,
                `╔═══════════════════════╗\n` +
                `║  ✅ *PRODUK BERHASIL!* ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *📦 INFO PRODUK* ━━━━┓\n` +
                `┃ 📦 Nama: ${productState.data.name}\n` +
                `┃ 📝 ${productState.data.description.substring(0, 30)}...\n` +
                `┃ 💰 Harga: Rp ${productState.data.price.toLocaleString('id-ID')}\n` +
                `┃ 📦 Stock: ${productState.data.stock}\n` +
                `┃ 💳 Metode: ${paymentMethodText}\n` +
                `┃ 📄 Data: File (${fileName})\n` +
                `┃ 📊 Size: ${(fileSize / 1024).toFixed(2)} KB\n` +
                `┃ 🆔 ID: \`${productId}\`\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `✨ Produk sudah aktif dan bisa dibeli!`,
                { parse_mode: 'Markdown' }
            );

            await this.db.logAdminAction({
                adminId: userId,
                action: 'ADD_PRODUCT',
                productId,
                productName: productState.data.name
            });

        } catch (error) {
            Logger.error('Handle document upload error', { userId, error: error.message });
            await this.bot.sendMessage(chatId, config.ERROR_MESSAGES.SYSTEM_ERROR);
        }
    }

    async handleCallback(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const data = query.data;
        const userId = query.from.id;
        const callbackKey = `${chatId}_${messageId}_${data}`;

        try {
            const status = await this.userManager.checkUserStatus(userId);
            if (!status.allowed) {
                return this.bot.answerCallbackQuery(query.id, {
                    text: status.message,
                    show_alert: true
                });
            }

            if (this.processingCallbacks.has(callbackKey)) {
                return this.bot.answerCallbackQuery(query.id, {
                    text: "⏳ Sedang diproses...",
                    show_alert: false
                });
            }

            this.processingCallbacks.add(callbackKey);
            await this.bot.answerCallbackQuery(query.id);

            // Handle product payment method selection
            if (data.startsWith('product_method_')) {
                const method = data.replace('product_method_', '');
                const productState = this.productAddWizardStates?.get(userId);
                
                if (productState && productState.step === 'payment_method') {
                    productState.data.paymentMethod = method;
                    productState.step = 'image';
                    this.productAddWizardStates.set(userId, productState);

                    await this.bot.sendMessage(chatId,
                        `✅ *Metode:* ${method.toUpperCase()}\n\n` +
                        `*Step 6/6: Upload Gambar*\n\n` +
                        `Upload gambar produk sekarang:\n\n` +
                        `📌 Format: JPG, PNG, WEBP\n` +
                        `📌 Minimal: ${config.MIN_IMAGE_WIDTH}x${config.MIN_IMAGE_HEIGHT}px\n` +
                        `📌 Maksimal: ${config.MAX_PRODUCT_IMAGE_SIZE / 1024 / 1024}MB\n\n` +
                        `━━━━━━━━━━━━━━━━━━━━━━\n` +
                        `Upload gambar sekarang:`,
                        { parse_mode: 'Markdown' }
                    );
                }
                this.processingCallbacks.delete(callbackKey);
                return;
            }

            await this.routeCallback(query, data);

        } catch (error) {
            Logger.error('Handle callback error', { userId, data, error: error.message });
            await this.db.logError(error, { callback: data, userId });

            await this.bot.sendMessage(chatId, config.ERROR_MESSAGES.SYSTEM_ERROR);

        } finally {
            this.processingCallbacks.delete(callbackKey);
        }
    }

    async processBroadcast(userId, chatId, text) {
        if (userId !== config.OWNER_ID) return;

        try {
            const users = await this.db.getBroadcastUsers();
            const broadcastId = `BC-${Date.now()}`;

            await this.bot.sendMessage(chatId,
                `╔═══════════════════════╗\n` +
                `║  📡 *BROADCAST START*  ║\n` +
                `╚═══════════════════════╝\n\n` +
                `🎯 Target: ${users.length} users\n` +
                `📝 Type: Text\n` +
                `⏳ Status: Processing...\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `Mohon tunggu...`,
                { parse_mode: 'Markdown' }
            );

            let success = 0;
            let failed = 0;

            for (let i = 0; i < users.length; i++) {
                try {
                    await this.bot.sendMessage(users[i], text, { parse_mode: 'Markdown' });
                    success++;
                    
                    if ((i + 1) % config.BROADCAST_BATCH_SIZE === 0) {
                        await new Promise(resolve => setTimeout(resolve, config.BROADCAST_DELAY));
                    }
                } catch (error) {
                    failed++;
                    Logger.warn('Broadcast failed for user', { userId: users[i], error: error.message });
                }
            }

            await this.db.saveBroadcastHistory(broadcastId, {
                broadcastId,
                adminId: userId,
                type: 'text',
                content: text,
                targetCount: users.length,
                successCount: success,
                failedCount: failed,
                timestamp: new Date().toISOString()
            });

            await this.db.logAdminAction({
                adminId: userId,
                action: 'BROADCAST',
                broadcastId,
                success,
                failed,
                total: users.length
            });

            await this.bot.sendMessage(chatId,
                `╔═══════════════════════╗\n` +
                `║  ✅ *BROADCAST SELESAI* ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *📊 HASIL* ━━━━┓\n` +
                `┃ ✅ Sukses: ${success}\n` +
                `┃ ❌ Gagal: ${failed}\n` +
                `┃ 📊 Total: ${users.length}\n` +
                `┃ 🆔 ID: \`${broadcastId}\`\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `✨ Broadcast berhasil dikirim!`,
                { parse_mode: 'Markdown' }
            );

        } catch (error) {
            Logger.error('Process broadcast error', { userId, error: error.message });
            await this.bot.sendMessage(chatId, config.ERROR_MESSAGES.SYSTEM_ERROR);
        }
    }

    async processBroadcastWithPhoto(userId, chatId, caption, photoId) {
        if (userId !== config.OWNER_ID) return;

        try {
            const users = await this.db.getBroadcastUsers();
            const broadcastId = `BC-${Date.now()}`;

            await this.bot.sendMessage(chatId,
                `╔═══════════════════════╗\n` +
                `║  📡 *BROADCAST START*  ║\n` +
                `╚═══════════════════════╝\n\n` +
                `🎯 Target: ${users.length} users\n` +
                `📝 Type: Photo + Caption\n` +
                `⏳ Status: Processing...\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `Mohon tunggu...`,
                { parse_mode: 'Markdown' }
            );

            let success = 0;
            let failed = 0;

            for (let i = 0; i < users.length; i++) {
                try {
                    await this.bot.sendPhoto(users[i], photoId, {
                        caption,
                        parse_mode: 'Markdown'
                    });
                    success++;
                    
                    if ((i + 1) % config.BROADCAST_BATCH_SIZE === 0) {
                        await new Promise(resolve => setTimeout(resolve, config.BROADCAST_DELAY));
                    }
                } catch (error) {
                    failed++;
                }
            }

            await this.db.saveBroadcastHistory(broadcastId, {
                broadcastId,
                adminId: userId,
                type: 'photo',
                photoId,
                caption,
                targetCount: users.length,
                successCount: success,
                failedCount: failed,
                timestamp: new Date().toISOString()
            });

            await this.bot.sendMessage(chatId,
                `╔═══════════════════════╗\n` +
                `║  ✅ *BROADCAST SELESAI* ║\n` +
                `╚═══════════════════════╝\n\n` +
                `┏━━━━ *📊 HASIL* ━━━━┓\n` +
                `┃ ✅ Sukses: ${success}\n` +
                `┃ ❌ Gagal: ${failed}\n` +
                `┃ 📊 Total: ${users.length}\n` +
                `┃ 🆔 ID: \`${broadcastId}\`\n` +
                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `✨ Broadcast berhasil dikirim!`,
                { parse_mode: 'Markdown' }
            );

        } catch (error) {
            Logger.error('Process broadcast with photo error', { userId, error: error.message });
            await this.bot.sendMessage(chatId, config.ERROR_MESSAGES.SYSTEM_ERROR);
        }
    }

    // ============================================
    // 🔄 WORKERS & MONITORING
    // ============================================

    startDepositMonitoring() {
        setInterval(async () => {
            try {
                const pendingPayments = this.paymentHandler.getPendingPayments();

                for (const payment of pendingPayments) {
                    const elapsed = Date.now() - payment.startTime;

                    if (elapsed > config.AUTO_CANCEL_DEPOSIT_TIMEOUT) {
                        await this.paymentHandler.cancelPayment(payment.transactionId);
                        this.paymentHandler.removePendingPayment(payment.transactionId);
                        
                        Logger.info('Auto-cancelled deposit', { transactionId: payment.transactionId });
                        continue;
                    }

                    const statusResult = await this.paymentHandler.checkPaymentStatus(payment.transactionId);
                    
                    if (statusResult.status === 'success') {
                        const result = await this.paymentHandler.processSuccessfulPayment(
                            payment.transactionId,
                            payment.userId,
                            payment.amount,
                            'deposit'
                        );

                        if (result.success) {
                            this.paymentHandler.removePendingPayment(payment.transactionId);

                            const timeInfo = this.getIndonesianTime();
                            await this.bot.sendMessage(payment.userId,
                                `╔═══════════════════════╗\n` +
                                `║  ✅ *DEPOSIT BERHASIL!* ║\n` +
                                `╚═══════════════════════╝\n\n` +
                                `┏━━━━ *💰 INFO* ━━━━┓\n` +
                                `┃ 💰 +Rp ${payment.amount.toLocaleString('id-ID')}\n` +
                                `┃ 💎 Saldo: Rp ${result.newBalance.toLocaleString('id-ID')}\n` +
                                `┃ 🆔 ID: \`${payment.transactionId}\`\n` +
                                `┃ 📅 ${timeInfo.date}\n` +
                                `┃ 🕐 ${timeInfo.time} WIB\n` +
                                `┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n` +
                                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                                `✨ Saldo sudah masuk!\n` +
                                `🛍️ Selamat berbelanja!`,
                                { parse_mode: 'Markdown' }
                            );

                            Logger.info('Deposit processed successfully', { 
                                transactionId: payment.transactionId,
                                userId: payment.userId
                            });
                        }
                    } else if (['expired', 'failed', 'cancel'].includes(statusResult.status)) {
                        this.paymentHandler.removePendingPayment(payment.transactionId);
                        Logger.info('Deposit expired/failed', { transactionId: payment.transactionId });
                    }
                }

            } catch (error) {
                Logger.error('Deposit monitoring error', { error: error.message });
            }
        }, config.DEPOSIT_MONITORING_INTERVAL);

        Logger.info('Deposit monitoring started');
    }

    startCleanupWorker() {
        setInterval(() => {
            try {
                this.security.cleanup();

                const now = Date.now();
                for (const key of this.processingCallbacks) {
                    if (now - (this.processingCallbackTimes?.get(key) || 0) > 5 * 60 * 1000) {
                        this.processingCallbacks.delete(key);
                    }
                }

                Logger.info('Cleanup worker completed');

            } catch (error) {
                Logger.error('Cleanup worker error', { error: error.message });
            }
        }, config.CLEANUP_WORKER_INTERVAL);

        setInterval(async () => {
            const now = new Date();
            if (now.getHours() === 2 && now.getMinutes() < 1) {
                await this.db.cleanup();
            }
        }, 60 * 1000);

        if (config.BACKUP_ENABLED) {
            setInterval(async () => {
                await this.db.backup();
            }, config.AUTO_BACKUP_INTERVAL);
        }

        Logger.info('Cleanup worker started');
    }

    startHealthMonitoring() {
        setInterval(async () => {
            try {
                const health = {
                    uptime: process.uptime(),
                    memoryUsage: process.memoryUsage(),
                    pendingPayments: this.paymentHandler.getPendingPayments().length,
                    processingCallbacks: this.processingCallbacks.size,
                    cacheSize: this.db.cache.size,
                    timestamp: new Date().toISOString()
                };

                await this.db.updateSystemHealth(health);

            } catch (error) {
                Logger.error('Health monitoring error', { error: error.message });
            }
        }, 60 * 1000);

        Logger.info('Health monitoring started');
    }

    // ============================================
    // 🛑 GRACEFUL SHUTDOWN
    // ============================================

    setupGracefulShutdown() {
        const shutdown = async (signal) => {
            Logger.info(`Received ${signal}, starting graceful shutdown...`);

            try {
                await this.bot.stopPolling();

                await new Promise(resolve => setTimeout(resolve, 2000));

                const pendingPayments = this.paymentHandler.getPendingPayments();
                for (const payment of pendingPayments) {
                    await this.paymentHandler.cancelPayment(payment.transactionId);
                }

                if (config.BACKUP_ENABLED) {
                    await this.db.backup();
                }

                Logger.info('Graceful shutdown completed');
                process.exit(0);

            } catch (error) {
                Logger.error('Graceful shutdown error', { error: error.message });
                process.exit(1);
            }
        };

        process.on('SIGTERM', () => shutdown('SIGTERM'));
        process.on('SIGINT', () => shutdown('SIGINT'));
    }

    // ============================================
    // 🛠️ UTILITY METHODS
    // ============================================

    async editPhotoCaption(chatId, messageId, text, keyboard) {
        try {
            return await this.bot.editMessageCaption(text, {
                chat_id: chatId,
                message_id: messageId,
                reply_markup: keyboard,
                parse_mode: 'Markdown'
            });
        } catch (error) {
            if (error.response?.body?.description?.includes("can't be edited") || 
                error.response?.body?.description?.includes("message is not modified")) {
                try {
                    await this.bot.deleteMessage(chatId, messageId);
                } catch (e) {}
                
                return await this.bot.sendPhoto(chatId, config.BOT_LOGO, {
                    caption: text,
                    reply_markup: keyboard,
                    parse_mode: 'Markdown'
                });
            }
            throw error;
        }
    }

    async getUsernameDisplay(userId) {
        try {
            const chatMember = await this.bot.getChatMember(userId, userId);
            return chatMember.user.username || chatMember.user.first_name || 'User';
        } catch (error) {
            return 'User';
        }
    }

    getIndonesianTime() {
        const now = new Date();
        const options = { timeZone: config.TIMEZONE };
        const dateStr = now.toLocaleDateString('id-ID', { 
            ...options, 
            day: '2-digit', 
            month: '2-digit', 
            year: 'numeric' 
        });
        const timeStr = now.toLocaleTimeString('id-ID', { 
            ...options, 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit' 
        });
        return {
            date: dateStr,
            time: timeStr,
            full: `${dateStr} ${timeStr}`
        };
    }
}

// ============================================
// 🚀 START BOT
// ============================================

(async () => {
    try {
        Logger.info('╔═══════════════════════════════════╗');
        Logger.info('║  🚀 DIGITAL PRODUCT BOT          ║');
        Logger.info('║  📱 FULL BUTTON-BASED VERSION    ║');
        Logger.info('║  🔐 PRODUCTION READY             ║');
        Logger.info('╚═══════════════════════════════════╝');
        Logger.info('');
        Logger.info('Starting bot initialization...');
        
        const bot = new DigitalProductBot();
        await bot.initPromise;
        
        Logger.info('');
        Logger.info('╔═══════════════════════════════════╗');
        Logger.info('║  ✅ BOT RUNNING SUCCESSFULLY!    ║');
        Logger.info('║  💡 ALL FEATURES BUTTON-BASED    ║');
        Logger.info('║  🔒 SECURITY ENABLED             ║');
        Logger.info('║  📊 MONITORING ACTIVE            ║');
        Logger.info('╚═══════════════════════════════════╝');
        Logger.info('');
        Logger.info('Press Ctrl+C to shutdown gracefully');
        Logger.info('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    } catch (error) {
        Logger.error('❌ FATAL ERROR STARTING BOT', { error: error.message, stack: error.stack });
        process.exit(1);
    }
})();
