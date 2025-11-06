module.exports = {
    BOT_TOKEN: '8558137456:AAEahrcQvA5xQSUDoFbr1XKtXeSEZpso3Zc',
    OWNER_ID: 7804463533,
    BOT_LOGO: 'https://files.catbox.moe/8tv8rb.jpeg',
    
    // ✅ MANUAL PAYMENT CONFIG
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

    // ✅ CIAATOPUP PAYMENT GATEWAY (QRIS OTOMATIS)
    CIAATOPUP_API_KEY: 'CiaaTopUp_qe51shcak0xrxuqt',
    CIAATOPUP_BASE_URL: 'https://ciaatopup.my.id',
    CIAATOPUP_CREATE_URL: 'https://ciaatopup.my.id/h2h/deposit/create',
    CIAATOPUP_STATUS_URL: 'https://ciaatopup.my.id/h2h/deposit/status',
    CIAATOPUP_CANCEL_URL: 'https://ciaatopup.my.id/h2h/deposit/cancel',
    
    TESTIMONI_CHANNEL: '@MarketplaceclCretatorID',
    
    // ✅ PRODUCT SETTINGS
    MAX_PRODUCT_IMAGE_SIZE: 20 * 1024 * 1024, // 20MB per gambar
    MAX_PRODUCT_FILE_SIZE: 5 * 1024 * 1024 * 1024 * 1024, // 5TB per file
    ALLOWED_IMAGE_TYPES: ['image/jpeg', 'image/png', 'image/jpg', 'image/webp'],
    PRODUCTS_PER_PAGE: 6,
    
    // ✅ SECURITY SETTINGS
    MAX_LOGIN_ATTEMPTS: 3,
    SESSION_TIMEOUT: 30 * 60 * 1000, // 30 menit
    ENCRYPTION_KEY: 'YOUR_32_CHAR_ENCRYPTION_KEY_HERE',
    
    // ✅ RATE LIMITING
    MAX_REQUESTS_PER_MINUTE: 20,
    BAN_DURATION: 60 * 60 * 1000 // 1 jam
};