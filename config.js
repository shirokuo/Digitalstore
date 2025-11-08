// config.js - PRODUCTION READY

require('dotenv').config();

module.exports = {
    // ============================================
    // 🤖 BOT CONFIGURATION
    // ============================================
    BOT_TOKEN: process.env.BOT_TOKEN || '8374179615:AAH_nIQYYaYLCHqT-P-nI9PDqq9QmFD8F6E',
    OWNER_ID: parseInt(process.env.OWNER_ID || '7804463533'),
    BOT_LOGO: process.env.BOT_LOGO || 'https://files.catbox.moe/9pivb2.jpg',
    
    // ============================================
    // 💳 MANUAL PAYMENT CONFIGURATION
    // ============================================
    MANUAL_PAYMENT: {
        QRIS: {
            enabled: true,
            image_url: 'https://files.catbox.moe/tlofe0.jpg',
            name: 'QRIS Payment'
        },
        DANA: {
            enabled: true,
            number: '083834186945',
            name: 'Mohxxxx'
        },
        OVO: {
            enabled: true,
            number: '083122028438',
            name: 'jeeyxxx'
        },
        GOPAY: {
            enabled: false,
            number: '083122028438',
            name: 'jeeyxxx'
        },
        BCA: {
            enabled: false,
            account_number: '1234567890',
            account_name: 'John Doe'
        }
    },

    // ============================================
    // ⚡ CIAATOPUP API CONFIGURATION
    // ============================================
    CIAATOPUP_API_KEY: process.env.CIAATOPUP_API_KEY || 'CiaaTopUp_nlf8lgf3pbj10ohe',
    CIAATOPUP_BASE_URL: 'https://ciaatopup.my.id',
    CIAATOPUP_CREATE_URL: 'https://ciaatopup.my.id/h2h/deposit/create',
    CIAATOPUP_STATUS_URL: 'https://ciaatopup.my.id/h2h/deposit/status',
    CIAATOPUP_CANCEL_URL: 'https://ciaatopup.my.id/h2h/deposit/cancel',
    CIAATOPUP_TIMEOUT: 10000,
    
    // ============================================
    // 📢 CHANNEL CONFIGURATION
    // ============================================
    TESTIMONI_CHANNEL: process.env.TESTIMONI_CHANNEL || '@MarketplaceclCretatorID',
    
    // ============================================
    // 📦 PRODUCT SETTINGS
    // ============================================
    MAX_PRODUCT_IMAGE_SIZE: 20 * 1024 * 1024, // 20MB
    MAX_PRODUCT_FILE_SIZE: 5 * 1024 * 1024 * 1024, // 5GB
    ALLOWED_IMAGE_TYPES: ['image/jpeg', 'image/png', 'image/jpg', 'image/webp'],
    ALLOWED_FILE_EXTENSIONS: ['.pdf', '.txt', '.zip', '.rar', '.doc', '.docx', '.xls', '.xlsx'],
    PRODUCTS_PER_PAGE: 6,
    MIN_IMAGE_WIDTH: 100,
    MIN_IMAGE_HEIGHT: 100,
    
    // ============================================
    // 🔐 SECURITY SETTINGS
    // ============================================
    ENCRYPTION_KEY: process.env.ENCRYPTION_KEY || 'CHANGE_THIS_32_CHAR_SECRET_KEY!',
    ENCRYPTION_ALGORITHM: 'aes-256-cbc',
    HASH_ALGORITHM: 'sha256',
    
    SESSION_TIMEOUT: 30 * 60 * 1000,
    SESSION_CLEANUP_INTERVAL: 5 * 60 * 1000,
    
    MAX_LOGIN_ATTEMPTS: 3,
    LOGIN_BAN_DURATION: 60 * 60 * 1000,
    
    // ============================================
    // 🚦 RATE LIMITING
    // ============================================
    MAX_REQUESTS_PER_MINUTE: 20,
    RATE_LIMIT_WINDOW: 60000,
    RATE_LIMIT_BAN_THRESHOLD: 3,
    RATE_LIMIT_BAN_DURATION: 60 * 60 * 1000,
    
    // ============================================
    // 🛡️ FRAUD DETECTION
    // ============================================
    FRAUD_DETECTION: {
        RAPID_TRANSACTION_LIMIT: 5,
        RAPID_TRANSACTION_WINDOW: 5 * 60 * 1000,
        AMOUNT_SPIKE_MULTIPLIER: 10,
        FAILED_ATTEMPT_LIMIT: 5,
        FAILED_ATTEMPT_WINDOW: 60 * 60 * 1000,
        FRAUD_SCORE_THRESHOLD: 3,
        FRAUD_SCORE_WINDOW: 24 * 60 * 60 * 1000,
        AUTO_BAN_DURATION: 24 * 60 * 60 * 1000
    },
    
    // ============================================
    // 🚫 BAN SYSTEM
    // ============================================
    BAN_TRIGGERS: {
        FAILED_LOGIN: 10,
        FRAUD_SCORE: 3,
        RATE_LIMIT_EXCEED: 3,
        SUSPICIOUS_ACTIVITY: 5
    },
    BAN_DURATION: 24 * 60 * 60 * 1000,
    PERMANENT_BAN_DURATION: 365 * 24 * 60 * 60 * 1000,
    
    // ============================================
    // 📝 LOGGING CONFIGURATION
    // ============================================
    LOG_RETENTION_DAYS: 90,
    ERROR_LOG_RETENTION_DAYS: 30,
    ACTIVITY_LOG_ENABLED: true,
    SECURITY_LOG_ENABLED: true,
    ADMIN_LOG_ENABLED: true,
    
    // ============================================
    // 💾 DATABASE CONFIGURATION
    // ============================================
    DATABASE_DIR: './database',
    BACKUP_DIR: './backups',
    BACKUP_ENABLED: true,
    BACKUP_RETENTION_DAYS: 7,
    AUTO_BACKUP_INTERVAL: 24 * 60 * 60 * 1000,
    
    CACHE_ENABLED: true,
    CACHE_TTL: {
        PRODUCTS: 5 * 60 * 1000,
        USER_BALANCE: 1 * 60 * 1000,
        BOT_STATS: 5 * 60 * 1000,
        USER_SESSION: 30 * 60 * 1000
    },
    
    // ============================================
    // 🔧 OPERATIONAL SETTINGS
    // ============================================
    GRACEFUL_SHUTDOWN_TIMEOUT: 30000,
    DEPOSIT_MONITORING_INTERVAL: 10000,
    CLEANUP_WORKER_INTERVAL: 60000,
    AUTO_CANCEL_DEPOSIT_TIMEOUT: 10 * 60 * 1000,
    TRANSACTION_CLEANUP_AGE: 5 * 60 * 1000,
    
    // ============================================
    // 📊 PERFORMANCE SETTINGS
    // ============================================
    BROADCAST_BATCH_SIZE: 100,
    BROADCAST_DELAY: 100,
    MAX_CONCURRENT_OPERATIONS: 10,
    FILE_WRITE_QUEUE_SIZE: 50,
    
    // ============================================
    // 🔒 WEBHOOK VALIDATION
    // ============================================
    WEBHOOK_SECRET: process.env.WEBHOOK_SECRET || 'YOUR_WEBHOOK_SECRET_HERE',
    WEBHOOK_TIMESTAMP_TOLERANCE: 5 * 60 * 1000,
    
    // ============================================
    // 🌐 TIMEZONE
    // ============================================
    TIMEZONE: 'Asia/Jakarta',
    
    // ============================================
    // ⚙️ FEATURE FLAGS
    // ============================================
    FEATURES: {
        AUTO_PAYMENT_ENABLED: true,
        MANUAL_PAYMENT_ENABLED: true,
        FRAUD_DETECTION_ENABLED: true,
        RATE_LIMITING_ENABLED: true,
        SESSION_MANAGEMENT_ENABLED: true,
        ENCRYPTION_ENABLED: true,
        BACKUP_ENABLED: true,
        HEALTH_CHECK_ENABLED: true,
        DEVICE_FINGERPRINTING_ENABLED: false,
        HONEYPOT_ENABLED: false
    },
    
    // ============================================
    // 🚨 ERROR MESSAGES (User-Friendly)
    // ============================================
    ERROR_MESSAGES: {
        BANNED: '🚫 Akun Anda telah diblokir. Hubungi admin untuk info lebih lanjut.',
        RATE_LIMIT: '⚠️ Terlalu banyak permintaan. Tunggu sebentar dan coba lagi.',
        INSUFFICIENT_BALANCE: '❌ Saldo tidak cukup. Silakan top up terlebih dahulu.',
        PRODUCT_NOT_FOUND: '❌ Produk tidak ditemukan atau sudah tidak tersedia.',
        STOCK_EMPTY: '❌ Maaf, stock produk habis.',
        PAYMENT_FAILED: '❌ Pembayaran gagal. Silakan coba lagi atau hubungi admin.',
        SYSTEM_ERROR: '❌ Terjadi kesalahan sistem. Tim kami sedang memperbaikinya.',
        INVALID_INPUT: '❌ Input tidak valid. Periksa kembali data Anda.',
        SESSION_EXPIRED: '⏰ Sesi Anda telah berakhir. Silakan /start ulang.',
        ACCESS_DENIED: '🚫 Anda tidak memiliki akses untuk fitur ini.',
        TRANSACTION_EXISTS: '⚠️ Transaksi sudah diproses sebelumnya.',
        FILE_TOO_LARGE: '❌ Ukuran file terlalu besar.',
        INVALID_FILE_TYPE: '❌ Tipe file tidak didukung.'
    },
    
    // ============================================
    // ✅ SUCCESS MESSAGES
    // ============================================
    SUCCESS_MESSAGES: {
        DEPOSIT_SUCCESS: '✅ Deposit berhasil! Saldo Anda telah ditambahkan.',
        PURCHASE_SUCCESS: '✅ Pembelian berhasil! Produk telah dikirim.',
        PAYMENT_APPROVED: '✅ Pembayaran Anda telah disetujui.',
        PRODUCT_ADDED: '✅ Produk berhasil ditambahkan.',
        BROADCAST_SENT: '✅ Broadcast berhasil dikirim ke semua user.'
    }
};
