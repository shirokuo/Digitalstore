// config.js - PRODUCTION READY

require('dotenv').config();

module.exports = {
    // ============================================
    // 🤖 BOT CONFIGURATION
    // ============================================
    BOT_TOKEN: process.env.BOT_TOKEN || '8374179615:AAH_nIQYYaYLCHqT-P-nI9PDqq9QmFD8F6E',
    OWNER_ID: parseInt(process.env.OWNER_ID || '7804463533'),
    BOT_LOGO: process.env.BOT_LOGO || 'https://files.catbox.moe/4uuyfl.jpg',
    
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
    CIAATOPUP_API_KEY: process.env.CIAATOPUP_API_KEY || 'CiaaTopUp_qe51shcak0xrxuqt',
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
    MAX_PRODUCT_FILE_SIZE: 5 * 1024 * 1024 * 1024, // 5GB (bukan 5TB, unrealistic)
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
    
    // Session Management
    SESSION_TIMEOUT: 30 * 60 * 1000, // 30 menit
    SESSION_CLEANUP_INTERVAL: 5 * 60 * 1000, // 5 menit
    
    // Login & Authentication
    MAX_LOGIN_ATTEMPTS: 3,
    LOGIN_BAN_DURATION: 60 * 60 * 1000, // 1 jam
    
    // ============================================
    // 🚦 RATE LIMITING
    // ============================================
    MAX_REQUESTS_PER_MINUTE: 20,
    RATE_LIMIT_WINDOW: 60000, // 1 menit
    RATE_LIMIT_BAN_THRESHOLD: 3, // Ban setelah 3x hit limit
    RATE_LIMIT_BAN_DURATION: 60 * 60 * 1000, // 1 jam
    
    // ============================================
    // 🛡️ FRAUD DETECTION
    // ============================================
    FRAUD_DETECTION: {
        RAPID_TRANSACTION_LIMIT: 5, // Max 5 transaksi
        RAPID_TRANSACTION_WINDOW: 5 * 60 * 1000, // dalam 5 menit
        AMOUNT_SPIKE_MULTIPLIER: 10, // 10x dari usual
        FAILED_ATTEMPT_LIMIT: 5, // Max 5 failed attempts
        FAILED_ATTEMPT_WINDOW: 60 * 60 * 1000, // dalam 1 jam
        FRAUD_SCORE_THRESHOLD: 3, // Ban jika score >= 3
        FRAUD_SCORE_WINDOW: 24 * 60 * 60 * 1000, // dalam 24 jam
        AUTO_BAN_DURATION: 24 * 60 * 60 * 1000 // 24 jam
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
    BAN_DURATION: 24 * 60 * 60 * 1000, // 24 jam default
    PERMANENT_BAN_DURATION: 365 * 24 * 60 * 60 * 1000, // 1 tahun
    
    // ============================================
    // 📝 LOGGING CONFIGURATION
    // ============================================
    LOG_RETENTION_DAYS: 90, // 90 hari
    ERROR_LOG_RETENTION_DAYS: 30, // 30 hari
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
    AUTO_BACKUP_INTERVAL: 24 * 60 * 60 * 1000, // Setiap 24 jam
    
    // Cache Settings
    CACHE_ENABLED: true,
    CACHE_TTL: {
        PRODUCTS: 5 * 60 * 1000, // 5 menit
        USER_BALANCE: 1 * 60 * 1000, // 1 menit
        BOT_STATS: 5 * 60 * 1000, // 5 menit
        USER_SESSION: 30 * 60 * 1000 // 30 menit
    },
    
    // ============================================
    // 🔧 OPERATIONAL SETTINGS
    // ============================================
    GRACEFUL_SHUTDOWN_TIMEOUT: 30000, // 30 detik
    DEPOSIT_MONITORING_INTERVAL: 10000, // 10 detik
    CLEANUP_WORKER_INTERVAL: 60000, // 60 detik
    AUTO_CANCEL_DEPOSIT_TIMEOUT: 10 * 60 * 1000, // 10 menit
    TRANSACTION_CLEANUP_AGE: 5 * 60 * 1000, // 5 menit untuk done transactions
    
    // ============================================
    // 📊 PERFORMANCE SETTINGS
    // ============================================
    BROADCAST_BATCH_SIZE: 100,
    BROADCAST_DELAY: 100, // ms per batch
    MAX_CONCURRENT_OPERATIONS: 10,
    FILE_WRITE_QUEUE_SIZE: 50,
    
    // ============================================
    // 🔒 WEBHOOK VALIDATION
    // ============================================
    WEBHOOK_SECRET: process.env.WEBHOOK_SECRET || 'YOUR_WEBHOOK_SECRET_HERE',
    WEBHOOK_TIMESTAMP_TOLERANCE: 5 * 60 * 1000, // 5 menit
    
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
        DEVICE_FINGERPRINTING_ENABLED: false, // Optional feature
        HONEYPOT_ENABLED: false // Optional feature
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
