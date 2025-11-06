const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const fs = require('fs').promises;
const fse = require('fs-extra');
const path = require('path');
const QRCode = require('qrcode');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const config = require('./config.js');

// ============================================
// 🔐 SECURITY & ENCRYPTION UTILITIES
// ============================================
class SecurityManager {
    constructor(encryptionKey) {
        this.algorithm = 'aes-256-cbc';
        this.key = crypto.scryptSync(encryptionKey, 'salt', 32);
        this.rateLimits = new Map();
        this.bannedUsers = new Map();
        this.suspiciousActivity = new Map();
    }

    encrypt(text) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    }

    decrypt(encryptedText) {
        try {
            const parts = encryptedText.split(':');
            const iv = Buffer.from(parts[0], 'hex');
            const encrypted = parts[1];
            const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            return null;
        }
    }

    hashData(data) {
        return crypto.createHash('sha256').update(data).digest('hex');
    }

    checkRateLimit(userId) {
        const now = Date.now();
        const userRequests = this.rateLimits.get(userId) || [];
        
        const recentRequests = userRequests.filter(time => now - time < 60000);
        
        if (recentRequests.length >= config.MAX_REQUESTS_PER_MINUTE) {
            this.logSuspiciousActivity(userId, 'RATE_LIMIT_EXCEEDED');
            return false;
        }
        
        recentRequests.push(now);
        this.rateLimits.set(userId, recentRequests);
        return true;
    }

    banUser(userId, reason, duration = config.BAN_DURATION) {
        this.bannedUsers.set(userId, {
            bannedAt: Date.now(),
            duration: duration,
            reason: reason
        });
        console.log(`🚫 User ${userId} banned: ${reason}`);
    }

    isUserBanned(userId) {
        const banInfo = this.bannedUsers.get(userId);
        if (!banInfo) return false;
        
        const elapsed = Date.now() - banInfo.bannedAt;
        if (elapsed > banInfo.duration) {
            this.bannedUsers.delete(userId);
            return false;
        }
        return true;
    }

    logSuspiciousActivity(userId, type) {
        const userActivity = this.suspiciousActivity.get(userId) || [];
        userActivity.push({ type, timestamp: Date.now() });
        this.suspiciousActivity.set(userId, userActivity);
        
        if (userActivity.length > 5) {
            this.banUser(userId, 'SUSPICIOUS_ACTIVITY_DETECTED', config.BAN_DURATION * 2);
        }
    }

    validateFileIntegrity(fileData, expectedHash) {
        const actualHash = this.hashData(fileData);
        return actualHash === expectedHash;
    }
}

// ============================================
// 💾 ATOMIC FILE MANAGER
// ============================================
class AtomicFileManager {
    constructor() {
        this.writeQueue = new Map();
        this.locks = new Map();
        this.backupEnabled = true;
    }

    async acquireLock(filePath) {
        const lockKey = path.resolve(filePath);
        while (this.locks.has(lockKey)) {
            await new Promise(resolve => setTimeout(resolve, 10));
        }
        this.locks.set(lockKey, true);
        return lockKey;
    }

    async releaseLock(lockKey) {
        this.locks.delete(lockKey);
    }

    async atomicWrite(filePath, data) {
        const lockKey = await this.acquireLock(filePath);
        try {
            if (this.backupEnabled && await fse.pathExists(filePath)) {
                await fse.copy(filePath, `${filePath}.backup`);
            }
            
            const tempFile = `${filePath}.${Date.now()}.tmp`;
            await fs.writeFile(tempFile, JSON.stringify(data, null, 2));
            
            const writtenData = await fs.readFile(tempFile, 'utf8');
            JSON.parse(writtenData);
            
            await fs.rename(tempFile, filePath);
            
            if (this.backupEnabled) {
                await fse.remove(`${filePath}.backup`);
            }
        } catch (error) {
            if (this.backupEnabled && await fse.pathExists(`${filePath}.backup`)) {
                await fse.copy(`${filePath}.backup`, filePath);
            }
            throw error;
        } finally {
            await this.releaseLock(lockKey);
        }
    }

    async atomicRead(filePath, defaultValue = null) {
        const lockKey = await this.acquireLock(filePath);
        try {
            if (!await fse.pathExists(filePath)) {
                return defaultValue;
            }
            
            const data = await fs.readFile(filePath, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            if (error.code === 'ENOENT') {
                return defaultValue;
            }
            
            if (this.backupEnabled && await fse.pathExists(`${filePath}.backup`)) {
                const backupData = await fs.readFile(`${filePath}.backup`, 'utf8');
                return JSON.parse(backupData);
            }
            
            throw error;
        } finally {
            await this.releaseLock(lockKey);
        }
    }
}

// ============================================
// 🗄️ DATABASE MANAGER
// ============================================
class DatabaseManager {
    constructor(securityManager) {
        this.fileManager = new AtomicFileManager();
        this.security = securityManager;
        this.dataFile = 'data.json';
        this.productsFile = 'products.json';
        this.productOrdersFile = 'productOrders.json';
        this.userFile = 'user.json';
        this.pendingManualDepositsFile = 'pendingManualDeposits.json';
        this.productImagesDir = 'product_images';
        this.productFilesDir = 'product_files';
        this.cache = new Map();
        this.cacheTimeout = 5000;
    }

    async initialize() {
        const fsSync = require('fs');
        const files = [
            { path: this.dataFile, default: [] },
            { path: this.productsFile, default: [] },
            { path: this.productOrdersFile, default: [] },
            { path: this.userFile, default: [] },
            { path: this.pendingManualDepositsFile, default: [] }
        ];

        for (const file of files) {
            try {
                if (!fsSync.existsSync(file.path)) {
                    await fs.writeFile(file.path, JSON.stringify(file.default, null, 2));
                    console.log(`✅ Created ${file.path}`);
                }
            } catch (error) {
                console.error(`❌ Error creating ${file.path}:`, error);
                throw error;
            }
        }

       
        await fse.ensureDir(this.productFilesDir);
        console.log(`✅ Ensured directories: ${this.productImagesDir}, ${this.productFilesDir}`);
    }

    async loadWithCache(filePath, defaultValue = null) {
        const cacheKey = filePath;
        const cached = this.cache.get(cacheKey);
        
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached.data;
        }
        
        const data = await this.fileManager.atomicRead(filePath, defaultValue);
        this.cache.set(cacheKey, { data, timestamp: Date.now() });
        return data;
    }

    async saveWithCache(filePath, data) {
        await this.fileManager.atomicWrite(filePath, data);
        this.cache.set(filePath, { data, timestamp: Date.now() });
    }

    async loadUsers() {
        return await this.loadWithCache(this.dataFile, []);
    }

    async saveUsers(users) {
        await this.saveWithCache(this.dataFile, users);
    }

    async loadProducts() {
        return await this.loadWithCache(this.productsFile, []);
    }

    async saveProducts(products) {
        await this.saveWithCache(this.productsFile, products);
    }

    async loadProductOrders() {
        const data = await this.loadWithCache(this.productOrdersFile, []);
        return Array.isArray(data) ? data : [];
    }

    async saveProductOrders(orders) {
        await this.saveWithCache(this.productOrdersFile, orders);
    }

    async loadBroadcastUsers() {
        return await this.loadWithCache(this.userFile, []);
    }

    async saveBroadcastUsers(users) {
        await this.saveWithCache(this.userFile, users);
    }

    async loadPendingManualDeposits() {
        return await this.loadWithCache(this.pendingManualDepositsFile, []);
    }

    async savePendingManualDeposits(deposits) {
        await this.saveWithCache(this.pendingManualDepositsFile, deposits);
    }

    async saveProductImage(productId, imageBuffer) {
    const imagePath = path.join(this.productImagesDir, `${productId}.jpg`);
    await fse.writeFile(imagePath, imageBuffer);
    return imagePath;
}

    async getProductImage(productId) {
        const imagePath = path.join(this.productImagesDir, `${productId}.jpg`);
        if (await fse.pathExists(imagePath)) {
            return imagePath;
        }
        return null;
    }

    async saveProductFile(productId, fileBuffer, fileName) {
        const fileDir = path.join(this.productFilesDir, productId);
        await fse.ensureDir(fileDir);
        
        const filePath = path.join(fileDir, fileName);
        await fse.writeFile(filePath, fileBuffer);
        
        const hash = this.security.hashData(fileBuffer.toString('base64'));
        
        return { filePath, hash, size: fileBuffer.length };
    }

    async getProductFile(productId, fileName) {
        const filePath = path.join(this.productFilesDir, productId, fileName);
        if (await fse.pathExists(filePath)) {
            return filePath;
        }
        return null;
    }

    async deleteProduct(productId) {
        const imagePath = path.join(this.productImagesDir, `${productId}.jpg`);
        const fileDir = path.join(this.productFilesDir, productId);
        
        if (await fse.pathExists(imagePath)) {
            await fse.remove(imagePath);
        }
        
        if (await fse.pathExists(fileDir)) {
            await fse.remove(fileDir);
        }
    }
}

// ============================================
// 🎨 MESSAGE EDITOR UTILITY
// ============================================
async function editPhotoCaption(bot, chatId, msgId, photoUrl, text, keyboard) {
    try {
        const validKeyboard = keyboard && keyboard.inline_keyboard && keyboard.inline_keyboard.length > 0 
            ? keyboard 
            : { inline_keyboard: [[{ text: '🏠 Menu Utama', callback_data: 'back_main' }]] };
        
        return await bot.editMessageCaption(text, {
            chat_id: chatId,
            message_id: msgId,
            reply_markup: validKeyboard,
            parse_mode: 'Markdown'
        });
    } catch (e) {
        if (e.response?.body?.description?.includes("can't be edited") || 
            e.response?.body?.description?.includes("message is not modified")) {
            try { await bot.deleteMessage(chatId, msgId); } catch (_) {}
            
            const validKeyboard = keyboard && keyboard.inline_keyboard && keyboard.inline_keyboard.length > 0 
                ? keyboard 
                : { inline_keyboard: [[{ text: '🏠 Menu Utama', callback_data: 'back_main' }]] };
            
            return await bot.sendPhoto(chatId, photoUrl, {
                caption: text,
                reply_markup: validKeyboard,
                parse_mode: 'Markdown'
            });
        }
        throw e;
    }
}

// ============================================
// 🤖 MAIN BOT CLASS
// ============================================
class DigitalProductBot {
    constructor() {
        this.config = config;
        this.bot = new TelegramBot(this.config.BOT_TOKEN, { 
    polling: {
        interval: 300,
        autoStart: true,
        params: {
            timeout: 10
        }
    },
    filepath: false
});
        
        this.bot.on('polling_error', (error) => {
    console.error('Polling error:', error.code, error.message);
    // Ignore EFATAL, let it retry automatically
});
        
        this.security = new SecurityManager(this.config.ENCRYPTION_KEY);
        this.db = new DatabaseManager(this.security);
        this.botLogo = config.BOT_LOGO;
        
        this.processingCallbacks = new Set();
        this.productAddStates = new Map();
        this.paymentProofStates = new Map();
        this.autoPending = [];
        
        this.initPromise = this.initializeBot();
        this.setupHandlers();
        this.startDepositMonitoring();
        this.startCleanupWorker();

        console.log('🤖 Digital Product Bot started!');
    }

    async initializeBot() {
        try {
            await this.db.initialize();
            console.log('✅ Database initialized');
        } catch (error) {
            console.error('❌ Database initialization failed:', error);
            process.exit(1);
        }
    }

    setupHandlers() {
        this.bot.onText(/\/start/, (msg) => this.handleStart(msg));
        this.bot.onText(/\/deposit(?: (\d+))?/, (msg, match) => this.handleDeposit(msg, match));
        this.bot.onText(/\/deposit_manual (\d+)/, (msg, match) => this.handleDepositManual(msg, match));
        this.bot.onText(/\/reff (\d+) (\d+)/, (msg, match) => this.handleReffCommand(msg, match));
        this.bot.onText(/\/bc (.+)/s, (msg, match) => this.handleBroadcast(msg, match));
        this.bot.onText(/\/produk_add/, (msg) => this.handleProdukAdd(msg));
        this.bot.onText(/\/produk_list/, (msg) => this.handleProdukList(msg));
        this.bot.onText(/\/delproduk (.+)/, (msg, match) => this.handleDelProduk(msg, match));
        this.bot.onText(/\/del (\d+)/, (msg, match) => this.handleDelete(msg, match));
        this.bot.onText(/\/info (\d+)/, (msg, match) => this.handleInfo(msg, match));
        
        this.bot.on('callback_query', (query) => this.handleCallback(query));
        
        this.bot.on('photo', (msg) => {
            if (msg.caption && msg.caption.startsWith('/bc ')) {
                this.handlePhotoBroadcast(msg);
            } else {
                this.handlePhotoUpload(msg);
            }
        });

        this.bot.on('document', (msg) => {
            this.handleDocumentUpload(msg);
        });

        this.bot.on('message', (msg) => {
            const userId = msg.from.id;
            const state = this.productAddStates.get(userId);
            
            if (state && msg.text && !msg.text.startsWith('/')) {
                this.handleProductAddStep(msg, state);
            }
        });
    }

    async handleStart(msg) {
        if (msg.chat.type !== 'private') {
            return this.bot.sendMessage(msg.chat.id, "⚠️ Bot ini hanya bekerja di private chat.");
        }
        
        const userId = msg.from.id;
        
        if (this.security.isUserBanned(userId)) {
            return this.bot.sendMessage(msg.chat.id, 
                "🚫 *Akun Anda Diblokir*\n\n" +
                "Hubungi @Jeeyhosting untuk informasi lebih lanjut.",
                { parse_mode: 'Markdown' }
            );
        }
        
        if (!this.security.checkRateLimit(userId)) {
            return this.bot.sendMessage(msg.chat.id, 
                "⚠️ *Terlalu Banyak Request*\n\n" +
                "Tunggu 1 menit sebelum menggunakan bot lagi.",
                { parse_mode: 'Markdown' }
            );
        }
        
        await this.addUserToBroadcastList(userId);
        const user = await this.getUser(userId);
       
        const uniqueUsers = await this.loadUniqueUsers();
        const usersWithBalance = await this.getUsersWithBalance();
        const products = await this.db.loadProducts();

        const keyboard = {
            inline_keyboard: [
                [
                    { text: '🛍️ Produk Digital', callback_data: 'produk_digital' },
                    { text: '💰 Cek Saldo', callback_data: 'check_balance' }
                ],
                [
                    { text: '📜 Riwayat Order', callback_data: 'order_history' },
                    { text: '💳 Top Up', callback_data: 'topup' }
                ],
                [
                    { text: '📜 Syarat & Ketentuan', callback_data: 'rules' },
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
        const saldoDisplay = user ? user.saldo.toLocaleString('id-ID') : '0';
        const sanitizeName = (name) => {
            if (!name) return 'Tidak ada';
            return name.replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&');
        };
        
        const username = msg.from.username ? '@' + sanitizeName(msg.from.username) : 'Tidak ada';
        
        const welcomeText = user ? 
            `👋 *Selamat Datang Kembali!*\n\nHalo ${msg.from.first_name}! Senang melihat Anda lagi.\n\n` :
            `🌟 *Selamat Datang di Digital Product Store!*\n\nHalo ${msg.from.first_name}! Selamat bergabung.\n\n`;
        
        const fullText = welcomeText +
            `👤 *Info Akun:*\n` +
            `Username: ${username}\n` +
            `ID: \`${userId}\`\n` +
            `📅 Tanggal: ${timeInfo.date}\n` +
            `🕐 Jam: ${timeInfo.time}\n\n` +
            `💰 Saldo: *Rp ${saldoDisplay}*\n\n` +
            `📊 *Statistik Bot:*\n` +
            `👥 Total User: ${uniqueUsers.length}\n` +
            `💳 User dengan Saldo: ${usersWithBalance.length}\n` +
            `📦 Total Produk: ${products.length}\n\n` +
            `🤖 *Fitur Otomatis:*\n` +
            `✅ Pembayaran QRIS otomatis\n` +
            `✅ Pengiriman produk instan\n` +
            `✅ Sistem keamanan tinggi\n` +
            `✅ Support 24/7\n\n` +
            `⚠️ *DISCLAIMER:*\n` +
            `• Saldo yang ada di bot TIDAK BISA di-refund\n` +
            `• Pastikan pilih produk dengan benar\n\n` +
            `👨‍💻 *Bot Creator:* @Jeeyhosting\n\n` +
            `Pilih menu di bawah:`;

        await this.bot.sendPhoto(msg.chat.id, this.botLogo, {
            caption: fullText,
            reply_markup: keyboard,
            parse_mode: 'Markdown'
        });
    }

    async handleCallback(query) {
        const chatId = query.message.chat.id;
        const messageId = query.message.message_id;
        const data = query.data;
        const userId = query.from.id;
        const callbackKey = `${chatId}_${messageId}_${data}`;

        if (this.security.isUserBanned(userId)) {
            return this.bot.answerCallbackQuery(query.id, {
                text: "🚫 Akun Anda diblokir",
                show_alert: true
            });
        }

        if (!this.security.checkRateLimit(userId)) {
            return this.bot.answerCallbackQuery(query.id, {
                text: "⚠️ Terlalu banyak request, tunggu sebentar",
                show_alert: false
            });
        }

        if (this.processingCallbacks.has(callbackKey)) {
            await this.bot.answerCallbackQuery(query.id, {
                text: "Sedang memproses, tunggu...",
                show_alert: false
            });
            return;
        }

        this.processingCallbacks.add(callbackKey);
        await this.bot.answerCallbackQuery(query.id);

        try {
            const handlers = {
                'check_balance': () => this.checkBalance(chatId, messageId, userId),
                'order_history': () => this.showOrderHistory(chatId, messageId, userId),
                'topup': () => this.showTopup(chatId, messageId),
                'help': () => this.showHelp(chatId, messageId),
                'rules': () => this.showRules(chatId, messageId),
                'owner_panel': () => this.showOwnerPanel(chatId, messageId, userId),
                'owner_stats': () => this.showOwnerStats(chatId, messageId, userId),
                'owner_saldo': () => this.showOwnerSaldo(chatId, messageId, userId),
                'owner_manual_deposits': () => this.showOwnerManualDeposits(chatId, messageId, userId),
                'owner_products': () => this.showOwnerProducts(chatId, messageId, userId),
                'owner_product_orders': () => this.showOwnerProductOrders(chatId, messageId, userId),
                'add_product_start': () => this.handleAddProductStart(chatId, messageId, userId),
                'back_main': () => this.showMainMenu(chatId, messageId, userId),
                'produk_digital': () => this.showProdukDigital(chatId, messageId, userId)
            };

            if (data.startsWith('produk_page_')) {
                const page = parseInt(data.replace('produk_page_', ''));
                await this.showProdukDigital(chatId, messageId, userId, page);
            } else if (data.startsWith('buy_product_')) {
                await this.confirmProductPurchase(chatId, messageId, data, userId);
            } else if (data.startsWith('confirm_buy_product_')) {
                await this.processProductPurchase(chatId, messageId, data, userId, query);
            } else if (data.startsWith('approve_product_payment_') || data.startsWith('appr_prod_')) {
                await this.approveProductPayment(chatId, messageId, data, userId, query);
            } else if (data.startsWith('reject_product_payment_') || data.startsWith('rej_prod_')) {
                await this.rejectProductPayment(chatId, messageId, data, userId, query);
            } else if (data.startsWith('product_payment_')) {
                await this.handleProductPaymentMethod(chatId, messageId, data, userId, query);
            } else if (data.startsWith('manual_pay_')) {
                await this.handleManualPaymentSelection(chatId, messageId, data, userId, query);
            } else if (data.startsWith('cancel_deposit_')) {
                await this.cancelDeposit(query);
            } else if (data.startsWith('approve_manual_') || data.startsWith('appr_man_')) {
                await this.approveManualDeposit(chatId, messageId, data, userId, query);
            } else if (data.startsWith('reject_manual_') || data.startsWith('rej_man_')) {
                await this.rejectManualDeposit(chatId, messageId, data, userId, query);
            } else if (data.startsWith('delete_product_') || data.startsWith('del_prod_')) {
                await this.deleteProduct(chatId, messageId, data, userId);
            } else if (handlers[data]) {
                await handlers[data]();
                } else if (data === 'page_info') {
                return;
            } else {
                console.log(`Unknown callback data: ${data}`);
                await this.bot.sendMessage(chatId, `❌ Command tidak dikenal: "${data}"\nSilakan /start ulang.`);
            }
        } catch (error) {
            console.error(`Callback error for data "${data}":`, error);
            await this.bot.sendMessage(chatId, 
                `❌ *Terjadi Masalah Sistem*\n\nSilakan ketik /start untuk memulai ulang.`,
                { parse_mode: 'Markdown' }
            );
        } finally {
            this.processingCallbacks.delete(callbackKey);
        }
    }

    async handleProdukAdd(msg) {
        const senderId = msg.from.id;
        const chatId = msg.chat.id;

        if (senderId !== this.config.OWNER_ID) {
            return this.bot.sendMessage(chatId, 
                "❌ *Access Denied*\n\nCommand ini hanya untuk owner bot.", 
                { parse_mode: 'Markdown' }
            );
        }

        this.productAddStates.set(senderId, {
            step: 'name',
            data: {}
        });

        await this.bot.sendMessage(chatId,
            `➕ *TAMBAH PRODUK BARU*\n\n` +
            `📝 *Step 1/6:* Masukkan nama produk\n\n` +
            `Contoh: Ebook Premium - Cara Sukses\n\n` +
            `Ketik /cancel untuk membatalkan.`,
            { parse_mode: 'Markdown' }
        );
    }

    async handleProductAddStep(msg, state) {
        const userId = msg.from.id;
        const chatId = msg.chat.id;
        const text = msg.text.trim();

        if (text === '/cancel') {
            this.productAddStates.delete(userId);
            return this.bot.sendMessage(chatId, '❌ Proses tambah produk dibatalkan.');
        }

        try {
            switch (state.step) {
                case 'name':
                    if (text.length < 3 || text.length > 200) {
                        return this.bot.sendMessage(chatId, '❌ Nama produk harus 3-200 karakter. Coba lagi:');
                    }
                    state.data.name = text;
                    state.step = 'description';
                    await this.bot.sendMessage(chatId,
                        `✅ Nama produk: ${text}\n\n` +
                        `📝 *Step 2/6:* Masukkan deskripsi produk\n\n` +
                        `Contoh: Ebook lengkap berisi 100+ tips sukses berbisnis online`,
                        { parse_mode: 'Markdown' }
                    );
                    break;

                case 'description':
                    if (text.length < 10 || text.length > 1000) {
                        return this.bot.sendMessage(chatId, '❌ Deskripsi harus 10-1000 karakter. Coba lagi:');
                    }
                    state.data.description = text;
                    state.step = 'price';
                    await this.bot.sendMessage(chatId,
                        `✅ Deskripsi tersimpan\n\n` +
                        `📝 *Step 3/6:* Masukkan harga produk (angka saja)\n\n` +
                        `Contoh: 50000`,
                        { parse_mode: 'Markdown' }
                    );
                    break;

                case 'price':
                    const price = parseInt(text);
                    if (isNaN(price) || price < 100) {
                        return this.bot.sendMessage(chatId, '❌ Harga tidak valid. Minimal Rp 100. Coba lagi:');
                    }
                    state.data.price = price;
                    state.step = 'stock';
                    await this.bot.sendMessage(chatId,
                        `✅ Harga: Rp ${price.toLocaleString('id-ID')}\n\n` +
                        `📝 *Step 4/6:* Masukkan jumlah stock (angka saja)\n\n` +
                        `Contoh: 100`,
                        { parse_mode: 'Markdown' }
                    );
                    break;

                case 'stock':
                    const stock = parseInt(text);
                    if (isNaN(stock) || stock < 0) {
                        return this.bot.sendMessage(chatId, '❌ Stock tidak valid. Minimal 0. Coba lagi:');
                    }
                    state.data.stock = stock;
                    state.step = 'payment_method';
                    
                    const keyboard = {
                        inline_keyboard: [
                            [{ text: '⚡ QRIS Otomatis', callback_data: 'product_payment_auto' }],
                            [{ text: '📸 Manual (Upload Bukti)', callback_data: 'product_payment_manual' }],
                            [{ text: '🔄 Kedua-duanya', callback_data: 'product_payment_both' }]
                        ]
                    };

                    await this.bot.sendMessage(chatId,
                        `✅ Stock: ${stock}\n\n` +
                        `📝 *Step 5/6:* Pilih metode pembayaran\n\n` +
                        `⚡ *QRIS Otomatis* - User langsung bayar via QRIS\n` +
                        `📸 *Manual* - User upload bukti transfer\n` +
                        `🔄 *Kedua-duanya* - User bisa pilih`,
                        { 
                            parse_mode: 'Markdown',
                            reply_markup: keyboard
                        }
                    );
                    break;

                case 'image':
                    return this.bot.sendMessage(chatId,
                        `⚠️ Silakan upload GAMBAR produk, bukan text!\n\n` +
                        `Upload foto produk untuk step ini.`
                    );
                    break;

                case 'product_data':
                    const products = await this.db.loadProducts();
                    const productId = `PROD-${Date.now()}`;
                    
                    const paymentMethodText = state.data.paymentMethod === 'auto' ? '⚡ QRIS Otomatis' : 
                                             state.data.paymentMethod === 'manual' ? '📸 Manual' : '🔄 Kedua-duanya';

                    const newProduct = {
                        id: productId,
                        name: state.data.name,
                        description: state.data.description,
                        price: state.data.price,
                        stock: state.data.stock,
                        paymentMethod: state.data.paymentMethod,
                        imageFileId: state.data.imageFileId || null,
                        productData: {
                            type: 'text',
                            content: text
                        },
                        createdAt: this.getIndonesianTimestamp(),
                        createdBy: userId,
                        hash: this.security.hashData(text)
                    };

                    products.push(newProduct);
                    await this.db.saveProducts(products);

                    this.productAddStates.delete(userId);

                    await this.bot.sendMessage(chatId,
                        `✅ *PRODUK BERHASIL DITAMBAHKAN!*\n\n` +
                        `📦 Nama: ${newProduct.name}\n` +
                        `📝 Deskripsi: ${newProduct.description}\n` +
                        `💰 Harga: Rp ${newProduct.price.toLocaleString('id-ID')}\n` +
                        `📦 Stock: ${newProduct.stock}\n` +
                        `💳 Metode: ${paymentMethodText}\n` +
                        `📄 Data: Text\n` +
                        `🆔 ID: \`${productId}\`\n\n` +
                        `Produk sudah aktif dan bisa dibeli user!`,
                        { parse_mode: 'Markdown' }
                    );
                    break;
            }

            this.productAddStates.set(userId, state);

        } catch (error) {
            console.error('Product add step error:', error);
            this.productAddStates.delete(userId);
            await this.bot.sendMessage(chatId, '❌ Terjadi kesalahan. Silakan mulai lagi dengan /produk_add');
        }
    }

    async handleProductPaymentMethod(chatId, messageId, data, userId, query) {
        const state = this.productAddStates.get(userId);

        if (!state || state.step !== 'payment_method') {
            await this.bot.answerCallbackQuery(query.id, {
                text: "❌ Session expired. Mulai lagi dengan /produk_add",
                show_alert: true
            });
            return;
        }

        const paymentType = data.replace('product_payment_', '');
        state.data.paymentMethod = paymentType;
        state.step = 'image';
        this.productAddStates.set(userId, state);

        await this.bot.editMessageText(
            `✅ *Metode Pembayaran Dipilih*\n\n` +
            `Metode: ${paymentType === 'auto' ? '⚡ QRIS Otomatis' : paymentType === 'manual' ? '📸 Manual' : '🔄 Kedua-duanya'}\n\n` +
            `📝 *Step 6/6: Upload GAMBAR Produk*\n\n` +
            `Silakan upload gambar/foto produk:\n\n` +
            `📸 *Format yang diterima:*\n` +
            `• JPG, PNG, WEBP\n` +
            `• Maksimal 20MB\n` +
            `• Akan otomatis dioptimasi\n\n` +
            `💡 *Setelah upload gambar, ketik/upload data produk*\n\n` +
            `Upload gambar sekarang:`,
            {
                chat_id: chatId,
                message_id: messageId,
                parse_mode: 'Markdown'
            }
        );
    }

    async handlePhotoUpload(msg) {
        const userId = msg.from.id;
        const chatId = msg.chat.id;

        const paymentState = this.paymentProofStates.get(userId);
        
        if (paymentState) {
            return await this.handlePaymentProof(msg, paymentState);
        }

        const state = this.productAddStates.get(userId);
        
        if (state && state.step === 'image') {
            return await this.handleProductImageUpload(msg, state);
        }
    }

    async handleProductImageUpload(msg, state) {
        const userId = msg.from.id;
        const chatId = msg.chat.id;

        try {
            const photo = msg.photo[msg.photo.length - 1];
            const fileId = photo.file_id;
            const fileSize = photo.file_size;

            if (fileSize > config.MAX_PRODUCT_IMAGE_SIZE) {
                return this.bot.sendMessage(chatId,
                    `❌ Gambar terlalu besar! Max 20MB.\n` +
                    `Ukuran gambar Anda: ${(fileSize / 1024 / 1024).toFixed(2)} MB`,
                    { parse_mode: 'Markdown' }
                );
            }

            state.data.imageFileId = fileId;
            state.step = 'product_data';
            this.productAddStates.set(userId, state);

            await this.bot.sendMessage(chatId,
                `✅ *Gambar Produk Tersimpan!*\n\n` +
                `📝 *STEP TERAKHIR: Upload Data Produk*\n\n` +
                `Silakan upload data produk yang akan dikirim ke pembeli:\n\n` +
                `📝 *Format yang diterima:*\n` +
                `1️⃣ **Text** - ketik langsung (link, kode, dll)\n` +
                `2️⃣ **File** - upload file (.txt, .pdf, .zip, dll)\n\n` +
                `💡 *Contoh Text:*\n` +
                `\`https://drive.google.com/file/d/xxx\`\n` +
                `atau\n` +
                `\`email@gmail.com:password123\`\n\n` +
                `Ketik atau upload sekarang:`,
                { parse_mode: 'Markdown' }
            );

        } catch (error) {
            console.error('Handle product image upload error:', error);
            await this.bot.sendMessage(chatId,
                `❌ Gagal upload gambar. Coba lagi.`,
                { parse_mode: 'Markdown' }
            );
        }
    }

    async handlePaymentProof(msg, paymentState) {
        const userId = msg.from.id;
        const chatId = msg.chat.id;

        try {
            const photo = msg.photo[msg.photo.length - 1];
            const fileId = photo.file_id;

            paymentState.proofFileId = fileId;
            paymentState.proofUploadedAt = this.getIndonesianTimestamp();
            this.paymentProofStates.set(userId, paymentState);

            await this.bot.sendMessage(chatId,
                `✅ *Bukti Pembayaran Diterima!*\n\n` +
                `📸 Foto bukti telah diterima.\n` +
                `⏰ Menunggu verifikasi dari owner...\n\n` +
                `🔔 Anda akan mendapat notifikasi setelah owner memverifikasi.\n` +
                `⏱️ Proses verifikasi: 5-30 menit (tergantung owner online)`,
                { parse_mode: 'Markdown' }
            );

            const productOrders = await this.db.loadProductOrders();
            const order = productOrders.find(o => o.orderId === paymentState.orderId);

            if (order) {
                const products = await this.db.loadProducts();
                const product = products.find(p => p.id === order.productId);

                const approvalKeyboard = {
                    inline_keyboard: [
                        [
                            { text: '✅ APPROVE', callback_data: `appr_prod_${paymentState.orderId}` },
                            { text: '❌ REJECT', callback_data: `rej_prod_${paymentState.orderId}` }
                        ]
                    ]
                };

                await this.bot.sendPhoto(this.config.OWNER_ID, fileId, {
                    caption: 
                        `📸 *BUKTI PEMBAYARAN BARU*\n\n` +
                        `🆔 Order ID: \`${order.orderId}\`\n` +
                        `👤 User ID: \`${userId}\`\n` +
                        `📱 Username: @${order.username}\n` +
                        `📦 Produk: ${product ? product.name : 'N/A'}\n` +
                        `💰 Harga: Rp ${order.price.toLocaleString('id-ID')}\n` +
                        `📅 Upload: ${paymentState.proofUploadedAt}\n\n` +
                        `⬆️ *Bukti pembayaran di atas*\n\n` +
                        `Approve atau Reject?`,
                    parse_mode: 'Markdown',
                    reply_markup: approvalKeyboard
                });

                this.paymentProofStates.delete(userId);
                console.log(`✅ Payment proof forwarded to owner for order ${order.orderId}`);
            }

        } catch (error) {
            console.error('Handle payment proof error:', error);
            await this.bot.sendMessage(chatId,
                `❌ *Gagal Upload Bukti*\n\n` +
                `Terjadi kesalahan saat upload. Silakan coba lagi atau hubungi admin.`,
                { parse_mode: 'Markdown' }
            );
        }
    }

    async handleDocumentUpload(msg) {
        const userId = msg.from.id;
        const chatId = msg.chat.id;

        const state = this.productAddStates.get(userId);
        
        if (!state || state.step !== 'product_data') {
            return;
        }

        try {
            const document = msg.document;
            const fileId = document.file_id;
            const fileName = document.file_name;
            const fileSize = document.file_size;

            if (fileSize > config.MAX_PRODUCT_FILE_SIZE) {
                return this.bot.sendMessage(chatId,
                    `❌ File terlalu besar! Max 5TB.\n` +
                    `Ukuran file Anda: ${(fileSize / 1024 / 1024 / 1024).toFixed(2)} GB`,
                    { parse_mode: 'Markdown' }
                );
            }

            const products = await this.db.loadProducts();
            const productId = `PROD-${Date.now()}`;
            
            const paymentMethodText = state.data.paymentMethod === 'auto' ? '⚡ QRIS Otomatis' : 
                                     state.data.paymentMethod === 'manual' ? '📸 Manual' : '🔄 Kedua-duanya';

            const newProduct = {
                id: productId,
                name: state.data.name,
                description: state.data.description,
                price: state.data.price,
                stock: state.data.stock,
                paymentMethod: state.data.paymentMethod,
                imageFileId: state.data.imageFileId || null,
                productData: {
                    type: 'file',
                    fileId: fileId,
                    fileName: fileName,
                    fileSize: fileSize
                },
                createdAt: this.getIndonesianTimestamp(),
                createdBy: userId,
                hash: this.security.hashData(fileId + fileName)
            };

            products.push(newProduct);
            await this.db.saveProducts(products);

            this.productAddStates.delete(userId);

            await this.bot.sendMessage(chatId,
                `✅ *PRODUK BERHASIL DITAMBAHKAN!*\n\n` +
                `📦 Nama: ${newProduct.name}\n` +
                `📝 Deskripsi: ${newProduct.description}\n` +
                `💰 Harga: Rp ${newProduct.price.toLocaleString('id-ID')}\n` +
                `📦 Stock: ${newProduct.stock}\n` +
                `💳 Metode: ${paymentMethodText}\n` +
                `📄 Data: File (${fileName})\n` +
                `🆔 ID: \`${productId}\`\n\n` +
                `Produk sudah aktif dan bisa dibeli user!`,
                { parse_mode: 'Markdown' }
            );

        } catch (error) {
            console.error('Handle document upload error:', error);
            await this.bot.sendMessage(chatId,
                `❌ Gagal upload file. Coba lagi atau ketik text manual.`,
                { parse_mode: 'Markdown' }
            );
        }
    }

    async showProdukDigital(chatId, messageId, userId, page = 0) {
        try {
            const products = await this.db.loadProducts();
            const availableProducts = products.filter(p => p.stock > 0);

            const ITEMS_PER_PAGE = config.PRODUCTS_PER_PAGE;
            const totalPages = Math.ceil(availableProducts.length / ITEMS_PER_PAGE);
            const startIndex = page * ITEMS_PER_PAGE;
            const endIndex = startIndex + ITEMS_PER_PAGE;
            const productsOnPage = availableProducts.slice(startIndex, endIndex);

            const keyboard = {
                inline_keyboard: []
            };

            if (availableProducts.length === 0) {
                const emptyText = `🛍️ *PRODUK DIGITAL*\n\n` +
                    `📦 Belum ada produk tersedia.\n\n` +
                    `Tunggu update dari admin!`;

                keyboard.inline_keyboard.push([{ text: '🔙 Menu Utama', callback_data: 'back_main' }]);

                await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, emptyText, keyboard);
                return;
            }

            let produkText = `🛍️ *PRODUK DIGITAL* (Hal ${page + 1}/${totalPages})\n\n`;
            produkText += `Total ${availableProducts.length} produk tersedia.\n\n`;

            productsOnPage.forEach((prod, index) => {
                const number = startIndex + index + 1;
                const shortDesc = prod.description.length > 50 ? 
                    prod.description.substring(0, 50) + '...' : prod.description;
                
                produkText += `${number}. *${prod.name}*\n`;
                produkText += `   💰 Harga: Rp ${prod.price.toLocaleString('id-ID')}\n`;
                produkText += `   📦 Stock: ${prod.stock}\n`;
                produkText += `   📝 ${shortDesc}\n\n`;

                const shortName = prod.name.length > 25 ? prod.name.substring(0, 25) + '...' : prod.name;
                keyboard.inline_keyboard.push([{
                    text: `🛒 ${shortName}`,
                    callback_data: `buy_product_${prod.id}`
                }]);
            });

            const navButtons = [];
            
            if (page > 0) {
                navButtons.push({
                    text: '⬅️ Prev',
                    callback_data: `produk_page_${page - 1}`
                });
            }
            
            if (totalPages > 1) {
                navButtons.push({
                    text: `${page + 1}/${totalPages}`,
                    callback_data: 'page_info'
                });
            }
            
            if (page < totalPages - 1) {
                navButtons.push({
                    text: 'Next ➡️',
                    callback_data: `produk_page_${page + 1}`
                });
            }
            
            if (navButtons.length > 0) {
                keyboard.inline_keyboard.push(navButtons);
            }

            keyboard.inline_keyboard.push([{ text: '🔙 Menu Utama', callback_data: 'back_main' }]);

            await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, produkText, keyboard);

        } catch (error) {
            console.error('Show produk digital error:', error);
            const errorKeyboard = {
                inline_keyboard: [[{ text: '🔙 Menu Utama', callback_data: 'back_main' }]]
            };
            await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, '❌ Error loading products', errorKeyboard);
        }
    }

    async confirmProductPurchase(chatId, messageId, data, userId) {
        const productId = data.replace('buy_product_', '');

        try {
            const products = await this.db.loadProducts();
            const product = products.find(p => p.id === productId);

            if (!product) {
                await editPhotoCaption(
                    this.bot,
                    chatId,
                    messageId,
                    this.botLogo,
                    '❌ Produk tidak ditemukan',
                    { inline_keyboard: [[{ text: '🔙 Kembali', callback_data: 'produk_digital' }]] }
                );
                return;
            }

            if (product.stock <= 0) {
                await editPhotoCaption(
                    this.bot,
                    chatId,
                    messageId,
                    this.botLogo,
                    '❌ *Stock Habis*\n\nMaaf, produk ini sedang habis.',
                    { inline_keyboard: [[{ text: '🔙 Kembali', callback_data: 'produk_digital' }]] }
                );
                return;
            }

            const user = await this.getUser(userId);
            const currentSaldo = user ? user.saldo : 0;

            const keyboard = {
                inline_keyboard: []
            };

            if (product.paymentMethod === 'auto' || product.paymentMethod === 'both') {
                keyboard.inline_keyboard.push([
                    { text: '⚡ Bayar QRIS Otomatis', callback_data: `confirm_buy_product_${productId}_auto` }
                ]);
            }

            if (product.paymentMethod === 'manual' || product.paymentMethod === 'both') {
                keyboard.inline_keyboard.push([
                    { text: '📸 Bayar Manual (Upload Bukti)', callback_data: `confirm_buy_product_${productId}_manual` }
                ]);
            }

            if (currentSaldo >= product.price) {
                keyboard.inline_keyboard.push([
                    { text: '💰 Bayar Pakai Saldo', callback_data: `confirm_buy_product_${productId}_saldo` }
                ]);
            }

            keyboard.inline_keyboard.push([{ text: '🔙 Kembali', callback_data: 'produk_digital' }]);

            const confirmText = `🛍️ *KONFIRMASI PEMBELIAN*\n\n` +
                `📦 Produk: *${product.name}*\n` +
                `📝 Deskripsi: ${product.description}\n` +
                `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n` +
                `📦 Stock: ${product.stock}\n\n` +
                `💳 Saldo Anda: Rp ${currentSaldo.toLocaleString('id-ID')}\n\n` +
                `Pilih metode pembayaran:`;

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
                await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, confirmText, keyboard);
            }

        } catch (error) {
            console.error('Confirm product purchase error:', error);
            await this.bot.sendMessage(chatId, '❌ Error loading product');
        }
    }

    async processProductPurchase(chatId, messageId, data, userId, query) {
        const dataParts = data.replace('confirm_buy_product_', '').split('_');
        const productId = dataParts[0];
        const paymentMethod = dataParts[1];

        try {
            const products = await this.db.loadProducts();
            const productIndex = products.findIndex(p => p.id === productId);

            if (productIndex === -1) {
                await this.bot.sendMessage(chatId, '❌ Produk tidak ditemukan');
                return;
            }

            const product = products[productIndex];

            if (product.stock <= 0) {
                await this.bot.sendMessage(chatId, '❌ *Stock Habis*\n\nMaaf, produk habis saat Anda checkout.', { parse_mode: 'Markdown' });
                return;
            }

            if (paymentMethod === 'saldo') {
                await this.processProductPurchaseSaldo(chatId, messageId, userId, product, productIndex, products, query);
            } else if (paymentMethod === 'auto') {
                await this.processProductPurchaseAuto(chatId, messageId, userId, product, query);
            } else if (paymentMethod === 'manual') {
                await this.showManualPaymentMethods(chatId, messageId, productId, product, userId, query);
            }

        } catch (error) {
            console.error('Process product purchase error:', error);
            await this.bot.sendMessage(chatId, '❌ Error processing purchase');
        }
    }

    async processProductPurchaseSaldo(chatId, messageId, userId, product, productIndex, products, query) {
        const user = await this.getUser(userId);
        
        if (!user || user.saldo < product.price) {
            await this.bot.sendMessage(chatId,
                `❌ *Saldo Tidak Cukup*\n\nSaldo Anda: Rp ${(user ? user.saldo : 0).toLocaleString('id-ID')}\n` +
                `Dibutuhkan: Rp ${product.price.toLocaleString('id-ID')}`,
                { parse_mode: 'Markdown' }
            );
            return;
        }

        const result = await this.updateUserSaldo(userId, product.price, 'subtract');

        if (!result.success) {
            await this.bot.sendMessage(chatId, '❌ Gagal memotong saldo');
            return;
        }

        products[productIndex].stock -= 1;
        await this.db.saveProducts(products);

        const timeInfo = this.getIndonesianTime();
        const orderId = `ORD-${Date.now()}`;

        await this.sendProductToUser(userId, product, orderId, timeInfo, result.newSaldo);

        const productOrders = await this.db.loadProductOrders();
        const username = await this.getUsernameDisplay(userId);
        const fullName = query.from.first_name + (query.from.last_name ? ' ' + query.from.last_name : '');
        
        productOrders.push({
            orderId: orderId,
            userId: userId.toString(),
            username: username,
            fullName: fullName,
            productId: product.id,
            productName: product.name,
            price: product.price,
            status: 'completed',
            paymentMethod: 'saldo',
            completedAt: this.getIndonesianTimestamp(),
            timeInfo: timeInfo
        });
        await this.db.saveProductOrders(productOrders);

        await this.sendTestimoniProduk(product, username, timeInfo);

        try {
            await this.bot.sendMessage(this.config.OWNER_ID,
                `🛍️ *PEMBELIAN PRODUK BARU*\n\n` +
                `🆔 Order ID: \`${orderId}\`\n` +
                `👤 User ID: \`${userId}\`\n` +
                `📱 Username: @${username}\n` +
                `📦 Produk: ${product.name}\n` +
                `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n` +
                `💳 Metode: Saldo\n` +
                `📅 Waktu: ${timeInfo.date} ${timeInfo.time}\n\n` +
                `✅ Data produk sudah dikirim otomatis ke customer!`,
                { parse_mode: 'Markdown' }
            );
        } catch (notifError) {
            console.log('Failed to notify owner:', notifError.message);
        }
    }

    async processProductPurchaseAuto(chatId, messageId, userId, product, query) {
        const reff_id = `prod-${userId}-${Date.now()}`;

        try {
            const params = new URLSearchParams({
                nominal: product.price.toString(),
                metode: 'QRISFAST'
            });

            const res = await axios.get(`${this.config.CIAATOPUP_CREATE_URL}?${params}`, {
                headers: { 
                    'X-APIKEY': this.config.CIAATOPUP_API_KEY,
                    'Content-Type': 'application/json'
                },
                timeout: 10000
            });

            if (!res.data || res.data.success !== true || !res.data.data || !res.data.data.qr_string) {
                await this.bot.sendMessage(chatId, "❌ Gagal membuat pembayaran.");
                return;
            }

            const qrData = res.data.data;
            const qrBuffer = await QRCode.toBuffer(qrData.qr_string);

            const teks = `🛍️ *PEMBAYARAN PRODUK*\n\n` +
                `📦 Produk: ${product.name}\n` +
                `🆔 Transaksi ID: \`${qrData.id}\`\n` +
                `💰 Harga: Rp ${product.price.toLocaleString("id-ID")}\n` +
                `🧾 Biaya Admin: Rp ${qrData.fee.toLocaleString("id-ID")}\n` +
                `💸 Total Bayar: Rp ${qrData.nominal.toLocaleString("id-ID")}\n` +
                `📅 Expired: ${qrData.expired_at}\n\n` +
                `📲 Scan QR dengan DANA/OVO/GoPay/ShopeePay\n\n` +
                `📦 Data produk akan dikirim otomatis setelah pembayaran.`;

            const sent = await this.bot.sendPhoto(chatId, qrBuffer, {
                caption: teks,
                parse_mode: "Markdown",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "❌ BATAL", callback_data: `cancel_deposit_${qrData.id}` }]
                    ]
                }
            });

            this.autoPending.push({
                id: chatId,
                trx_id: qrData.id,
                get_balance: qrData.get_balance,
                user_name: query.from.first_name,
                done: false,
                msgId: sent.message_id,
                startTime: Date.now(),
                productId: product.id,
                isProduct: true
            });

        } catch (err) {
            console.log("❌ ERROR PRODUCT PAYMENT:", err.message);
            this.bot.sendMessage(chatId, "❌ Terjadi kesalahan saat membuat pembayaran.");
        }
    }

    async showManualPaymentMethods(chatId, messageId, productId, product, userId, query) {
        try {
            const manualPayment = this.config.MANUAL_PAYMENT;
            const keyboard = {
                inline_keyboard: []
            };

            if (manualPayment.QRIS && manualPayment.QRIS.enabled) {
                keyboard.inline_keyboard.push([{
                    text: '📱 QRIS',
                    callback_data: `manual_pay_${productId}_qris`
                }]);
            }
            if (manualPayment.DANA && manualPayment.DANA.enabled) {
                keyboard.inline_keyboard.push([{
                    text: '💳 DANA',
                    callback_data: `manual_pay_${productId}_dana`
                }]);
            }
            if (manualPayment.OVO && manualPayment.OVO.enabled) {
                keyboard.inline_keyboard.push([{
                    text: '💳 OVO',
                    callback_data: `manual_pay_${productId}_ovo`
                }]);
            }
            if (manualPayment.GOPAY && manualPayment.GOPAY.enabled) {
                keyboard.inline_keyboard.push([{
                    text: '💳 GOPAY',
                    callback_data: `manual_pay_${productId}_gopay`
                }]);
            }
            if (manualPayment.BCA && manualPayment.BCA.enabled) {
                keyboard.inline_keyboard.push([{
                    text: '🏦 BCA',
                    callback_data: `manual_pay_${productId}_bca`
                }]);
            }

            keyboard.inline_keyboard.push([{ text: '🔙 Kembali', callback_data: 'produk_digital' }]);

            await this.bot.sendMessage(chatId,
                `📸 *PILIH METODE PEMBAYARAN MANUAL*\n\n` +
                `📦 Produk: ${product.name}\n` +
                `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n\n` +
                `Pilih metode pembayaran yang tersedia:`,
                { 
                    parse_mode: 'Markdown',
                    reply_markup: keyboard
                }
            );
        } catch (error) {
            console.error('Show manual payment methods error:', error);
            await this.bot.sendMessage(chatId, '❌ Error showing payment methods');
        }
    }

    async handleManualPaymentSelection(chatId, messageId, data, userId, query) {
        try {
            const dataParts = data.replace('manual_pay_', '').split('_');
            const productId = dataParts[0];
            const paymentMethod = dataParts[1];

            const products = await this.db.loadProducts();
            const product = products.find(p => p.id === productId);

            if (!product) {
                await this.bot.sendMessage(chatId, '❌ Produk tidak ditemukan');
                return;
            }

            const orderId = `ORD-${Date.now()}`;
            const username = await this.getUsernameDisplay(userId);
            const fullName = query.from.first_name + (query.from.last_name ? ' ' + query.from.last_name : '');
            const timeInfo = this.getIndonesianTime();

            const productOrders = await this.db.loadProductOrders();
            productOrders.push({
                orderId: orderId,
                userId: userId.toString(),
                username: username,
                fullName: fullName,
                productId: productId,
                productName: product.name,
                price: product.price,
                status: 'pending',
                paymentType: 'manual',
                paymentMethod: paymentMethod.toUpperCase(),
                createdAt: this.getIndonesianTimestamp(),
                timeInfo: timeInfo
            });
            await this.db.saveProductOrders(productOrders);

            this.paymentProofStates.set(userId, {
                orderId: orderId,
                productId: productId,
                productName: product.name,
                price: product.price,
                paymentMethod: paymentMethod,
                createdAt: timeInfo
            });

            const manualPayment = this.config.MANUAL_PAYMENT;
            let paymentText = '';
            let paymentPhoto = null;

            if (paymentMethod === 'qris' && manualPayment.QRIS) {
                paymentPhoto = manualPayment.QRIS.image_url;
                paymentText = `📱 *PEMBAYARAN VIA QRIS*\n\n` +
                    `🆔 Order ID: \`${orderId}\`\n` +
                    `📦 Produk: ${product.name}\n` +
                    `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n\n` +
                    `📲 *Cara Bayar:*\n` +
                    `1. Scan QR Code di atas\n` +
                    `2. Bayar sejumlah Rp ${product.price.toLocaleString('id-ID')}\n` +
                    `3. Screenshot bukti pembayaran\n` +
                    `4. Upload bukti ke chat ini\n\n` +
                    `⏳ Menunggu bukti pembayaran...`;
            } else if (paymentMethod === 'dana' && manualPayment.DANA) {
                paymentText = `💳 *PEMBAYARAN VIA DANA*\n\n` +
                    `🆔 Order ID: \`${orderId}\`\n` +
                    `📦 Produk: ${product.name}\n` +
                    `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n\n` +
                    `📱 *Nomor DANA:*\n` +
                    `\`${manualPayment.DANA.number}\`\n` +
                    `📛 A.n: ${manualPayment.DANA.name}\n\n` +
                    `📲 *Cara Bayar:*\n` +
                    `1. Buka aplikasi DANA\n` +
                    `2. Transfer ke nomor di atas\n` +
                    `3. Nominal: Rp ${product.price.toLocaleString('id-ID')}\n` +
                    `4. Screenshot bukti transfer\n` +
                    `5. Upload bukti ke chat ini\n\n` +
                    `⏳ Menunggu bukti pembayaran...`;
            } else if (paymentMethod === 'ovo' && manualPayment.OVO) {
                paymentText = `💳 *PEMBAYARAN VIA OVO*\n\n` +
                    `🆔 Order ID: \`${orderId}\`\n` +
                    `📦 Produk: ${product.name}\n` +
                    `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n\n` +
                    `📱 *Nomor OVO:*\n` +
                    `\`${manualPayment.OVO.number}\`\n` +
                    `📛 A.n: ${manualPayment.OVO.name}\n\n` +
                    `📲 *Cara Bayar:*\n` +
                    `1. Buka aplikasi OVO\n` +
                    `2. Transfer ke nomor di atas\n` +
                    `3. Nominal: Rp ${product.price.toLocaleString('id-ID')}\n` +
                    `4. Screenshot bukti transfer\n` +
                    `5. Upload bukti ke chat ini\n\n` +
                    `⏳ Menunggu bukti pembayaran...`;
            } else if (paymentMethod === 'gopay' && manualPayment.GOPAY) {
                paymentText = `💳 *PEMBAYARAN VIA GOPAY*\n\n` +
                    `🆔 Order ID: \`${orderId}\`\n` +
                    `📦 Produk: ${product.name}\n` +
                    `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n\n` +
                    `📱 *Nomor GOPAY:*\n` +
                    `\`${manualPayment.GOPAY.number}\`\n` +
                    `📛 A.n: ${manualPayment.GOPAY.name}\n\n` +
                    `📲 *Cara Bayar:*\n` +
                    `1. Buka aplikasi Gojek\n` +
                    `2. Transfer ke nomor di atas\n` +
                    `3. Nominal: Rp ${product.price.toLocaleString('id-ID')}\n` +
                    `4. Screenshot bukti transfer\n` +
                    `5. Upload bukti ke chat ini\n\n` +
                    `⏳ Menunggu bukti pembayaran...`;
            } else if (paymentMethod === 'bca' && manualPayment.BCA) {
                paymentText = `🏦 *PEMBAYARAN VIA BCA*\n\n` +
                    `🆔 Order ID: \`${orderId}\`\n` +
                    `📦 Produk: ${product.name}\n` +
                    `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n\n` +
                    `🏦 *Rekening BCA:*\n` +
                    `\`${manualPayment.BCA.account_number}\`\n` +
                    `📛 A.n: ${manualPayment.BCA.account_name}\n\n` +
                    `📲 *Cara Bayar:*\n` +
                    `1. Transfer via Mobile/Internet Banking\n` +
                    `2. Ke rekening BCA di atas\n` +
                    `3. Nominal: Rp ${product.price.toLocaleString('id-ID')}\n` +
                    `4. Screenshot bukti transfer\n` +
                    `5. Upload bukti ke chat ini\n\n` +
                    `⏳ Menunggu bukti pembayaran...`;
            }

            if (paymentMethod === 'qris' && paymentPhoto) {
                await this.bot.sendPhoto(chatId, paymentPhoto, {
                    caption: paymentText,
                    parse_mode: 'Markdown',
                    reply_markup: {
                        inline_keyboard: [[{ text: '🔙 Kembali', callback_data: 'produk_digital' }]]
                    }
                });
            } else {
                await this.bot.sendMessage(chatId, paymentText, {
                    parse_mode: 'Markdown',
                    reply_markup: {
                        inline_keyboard: [[{ text: '🔙 Kembali', callback_data: 'produk_digital' }]]
                    }
                });
            }

            try {
                await this.bot.sendMessage(this.config.OWNER_ID,
                    `📦 *ORDER PRODUK MANUAL BARU*\n\n` +
                    `🆔 Order ID: \`${orderId}\`\n` +
                    `👤 User ID: \`${userId}\`\n` +
                    `📛 Nama: ${fullName}\n` +
                    `📱 Username: @${username}\n` +
                    `📦 Produk: ${product.name}\n` +
                    `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n` +
                    `💳 Metode: ${paymentMethod.toUpperCase()}\n` +
                    `📅 Waktu: ${timeInfo.date} ${timeInfo.time}\n\n` +
                    `⏳ Tunggu user upload bukti transfer.`,
                    { parse_mode: 'Markdown' }
                );
            } catch (notifError) {
                console.log('Failed to notify owner:', notifError.message);
            }

        } catch (error) {
            console.error('Handle manual payment selection error:', error);
            await this.bot.sendMessage(chatId, '❌ Error processing payment method');
        }
    }

    async sendProductToUser(userId, product, orderId, timeInfo, newSaldo) {
        const productData = product.productData;
        
        if (productData) {
            if (productData.type === 'file') {
                await this.bot.sendDocument(userId, productData.fileId, {
                    caption: 
                        `✅ *PEMBELIAN BERHASIL!*\n\n` +
                        `🆔 Order ID: \`${orderId}\`\n` +
                        `📦 Produk: ${product.name}\n` +
                        `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n` +
                        `💳 Saldo tersisa: Rp ${newSaldo.toLocaleString('id-ID')}\n` +
                        `📅 Tanggal: ${timeInfo.date}\n` +
                        `🕐 Jam: ${timeInfo.time}\n\n` +
                        `📄 Data produk di atas.\n\n` +
                        `Terima kasih!`,
                    parse_mode: 'Markdown'
                });
            } else if (productData.type === 'text') {
                await this.bot.sendMessage(userId,
                    `✅ *PEMBELIAN BERHASIL!*\n\n` +
                    `🆔 Order ID: \`${orderId}\`\n` +
                    `📦 Produk: ${product.name}\n` +
                    `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n` +
                    `💳 Saldo tersisa: Rp ${newSaldo.toLocaleString('id-ID')}\n` +
                    `📅 Tanggal: ${timeInfo.date}\n` +
                    `🕐 Jam: ${timeInfo.time}\n\n` +
                    `📄 *Data Produk:*\n` +
                    `\`\`\`\n${productData.content}\n\`\`\`\n\n` +
                    `Terima kasih!`,
                    { parse_mode: 'Markdown' }
                );
            }
        }
    }

    async sendTestimoniProduk(product, username, timeInfo) {
        try {
            const testimoniText = `🎉 *TRANSAKSI BERHASIL* 🎉\n\n` +
                `👤 Customer: @${username}\n` +
                `📦 Produk: ${product.name}\n` +
                `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n` +
                `⚡ Status: Sukses Instan\n` +
                `📅 Waktu: ${timeInfo.date} ${timeInfo.time}\n\n` +
                `🤖 *Digital Product Store 24/7*\n` +
                `✅ Proses cepat & aman\n` +
                `✅ Pengiriman otomatis\n` +
                `✅ Produk original\n\n` +
                `📞 Order sekarang juga!`;

            if (product.imageFileId) {
                await this.bot.sendPhoto(this.config.TESTIMONI_CHANNEL, product.imageFileId, {
                    caption: testimoniText,
                    parse_mode: 'Markdown'
                });
            } else {
                await this.bot.sendMessage(this.config.TESTIMONI_CHANNEL, testimoniText, {
                    parse_mode: 'Markdown'
                });
            }

        } catch (error) {
            console.error('Error sending testimoni to channel:', error.message);
        }
    }

    async handleDeposit(msg, match) {
        const chatId = msg.chat.id;
        const userId = msg.from.id;
        const nominalAsli = parseInt(match[1]);

        if (!nominalAsli || nominalAsli < 1000) {
            return this.bot.sendMessage(chatId, "❌ Minimal deposit Rp 1,000\nContoh: `/deposit 5000`", {
                parse_mode: 'Markdown'
            });
        }

        const activeDeposit = this.autoPending.find(trx => 
            trx.id === chatId && !trx.done && !trx.cancelled
        );

        if (activeDeposit) {
            const elapsedTime = Date.now() - activeDeposit.startTime;
            const elapsedMinutes = Math.floor(elapsedTime / 60000);
            const elapsedSeconds = Math.floor((elapsedTime % 60000) / 1000);
            
            const timeText = elapsedMinutes > 0 
                ? `${elapsedMinutes} menit ${elapsedSeconds} detik`
                : `${elapsedSeconds} detik`;

            const keyboard = {
                inline_keyboard: [
                    [{ text: "❌ Cancel Deposit Aktif", callback_data: `cancel_deposit_${activeDeposit.trx_id}` }]
                ]
            };

            return this.bot.sendMessage(chatId, 
                `⚠️ *DEPOSIT MASIH AKTIF*\n\n` +
                `🆔 ID: \`${activeDeposit.trx_id}\`\n` +
                `💰 Nominal: Rp ${activeDeposit.get_balance.toLocaleString('id-ID')}\n` +
                `⏰ Dibuat: ${timeText} yang lalu\n\n` +
                `❌ Anda harus **cancel** terlebih dahulu sebelum membuat deposit baru.\n\n` +
                `💡 Klik tombol di bawah untuk cancel:`,
                { 
                    parse_mode: 'Markdown',
                    reply_markup: keyboard
                }
            );
        }

        const reff_id = `reff-${chatId}-${Date.now()}`;

        try {
            const params = new URLSearchParams({
                nominal: nominalAsli.toString(),
                metode: 'QRISFAST'
            });

            const res = await axios.get(`${this.config.CIAATOPUP_CREATE_URL}?${params}`, {
                headers: { 
                    'X-APIKEY': this.config.CIAATOPUP_API_KEY,
                    'Content-Type': 'application/json'
                },
                timeout: 10000
            });

            if (!res.data || res.data.success !== true || !res.data.data || !res.data.data.qr_string) {
                return this.bot.sendMessage(chatId, "❌ Gagal membuat deposit.\n\n📎 Respon: " + JSON.stringify(res.data));
            }

            const data = res.data.data;
            
            const qrBuffer = await QRCode.toBuffer(data.qr_string);

            const teks = `💳 *PEMBAYARAN VIA QRIS*\n` +
                `🆔 *ID Transaksi:* \`${data.id}\`\n` +
                `💰 Nominal: Rp ${nominalAsli.toLocaleString("id-ID")}\n` +
                `🧾 Biaya Admin: Rp ${data.fee.toLocaleString("id-ID")}\n` +
                `💸 Total Bayar: Rp ${data.nominal.toLocaleString("id-ID")}\n` +
                `💎 Saldo Diterima: Rp ${data.get_balance.toLocaleString("id-ID")}\n` +
                `📅 Expired: ${data.expired_at}\n\n` +
                `📲 *Scan QR di bawah pakai:*\n` +
                `DANA / OVO / ShopeePay / GoPay/DLL\n\n` +
                `Saldo akan otomatis masuk setelah pembayaran berhasil.\n\n` +
                `⏰ *PENTING:* Deposit ini akan auto-cancel dalam 10 menit jika tidak dibayar.\n` +
                `⚠️ Segera bayar agar tidak di-cancel otomatis!\n\n` +
                `💬 *Jika sudah transfer dan saldo tidak masuk dalam 5 menit, segera hubungi owner @Jeeyhosting*`;

            const inlineKeyboard = {
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "❌ BATAL", callback_data: `cancel_deposit_${data.id}` }]
                    ]
                }
            };

            const sent = await this.bot.sendPhoto(chatId, qrBuffer, {
                caption: teks,
                parse_mode: "Markdown",
                ...inlineKeyboard
            });

            this.autoPending.push({
                id: chatId,
                trx_id: data.id,
                get_balance: data.get_balance,
                user_name: msg.from.first_name + (msg.from.last_name ? " " + msg.from.last_name : ""),
                done: false,
                msgId: sent.message_id,
                startTime: Date.now()
            });
        } catch (err) {
            console.log("❌ ERROR DEPOSIT:", err.message);
            this.bot.sendMessage(chatId, "❌ Terjadi kesalahan saat membuat deposit.");
        }
    }

    async cancelDeposit(query) {
        const msg = query.message;
        const data = query.data;
        const chatId = msg.chat.id;
        const trxId = data.replace('cancel_deposit_', '');

        console.log(`Cancel deposit request for transaction: ${trxId}`);

        try {
            const pendingIndex = this.autoPending.findIndex(trx => trx.trx_id === trxId && !trx.done);
            
            if (pendingIndex === -1) {
                await this.bot.answerCallbackQuery(query.id, {
                    text: "❌ Transaksi tidak ditemukan atau sudah selesai",
                    show_alert: true
                });
                return;
            }

            this.autoPending[pendingIndex].done = true;
            this.autoPending[pendingIndex].cancelled = true;

            try {
                await this.bot.deleteMessage(chatId, msg.message_id);
                console.log(`✅ QRIS message deleted for ${trxId}`);
            } catch (deleteError) {
                console.log(`⚠️ Cannot delete QRIS message: ${deleteError.message}`);
            }

            try {
                const params = new URLSearchParams({
                    id: trxId
                });

                await axios.get(`${this.config.CIAATOPUP_CANCEL_URL}?${params}`, {
                    headers: { 
                        'X-APIKEY': this.config.CIAATOPUP_API_KEY,
                        'Content-Type': 'application/json'
                    },
                    timeout: 3000
                });
            } catch (ciaatopupError) {
                console.log(`CiaaTopUp cancel timeout/error: ${ciaatopupError.message}`);
            }

            const timeInfo = this.getIndonesianTime();
            const nominal = this.autoPending[pendingIndex].get_balance;
            
            const successText = `✅ *DEPOSIT DIBATALKAN*\n\n` +
                `🆔 ID: \`${trxId}\`\n` +
                `💰 Nominal: Rp ${nominal.toLocaleString('id-ID')}\n` +
                `📊 Status: Berhasil dibatalkan\n` +
                `📅 Tanggal: ${timeInfo.date}\n` +
                `🕐 Jam: ${timeInfo.time}\n\n` +
                `💡 Silakan buat deposit baru jika diperlukan.\n` +
                `Ketik /start Untuk Ke Menu Utama`;

            await this.bot.sendMessage(chatId, successText, {
                parse_mode: "Markdown"
            });

            await this.bot.answerCallbackQuery(query.id, {
                text: "✅ Transaksi berhasil dibatalkan"
            });

            console.log(`✅ Cancel deposit completed for ${trxId}`);

        } catch (err) {
            console.error(`❌ CRITICAL ERROR cancelDeposit ${trxId}:`, err.message);
            
            try {
                await this.bot.sendMessage(chatId, 
                    `❌ DEPOSIT DIBATALKAN (ERROR SISTEM)\n\n` +
                    `ID: ${trxId}\n` +
                    `Status: Dibatalkan meskipun ada error\n` +
                    `Hubungi admin jika ada masalah: @Jeeyhosting`
                );

                await this.bot.answerCallbackQuery(query.id, {
                    text: "⚠️ Dibatalkan tapi ada error sistem"
                });

            } catch (emergencyError) {
                console.error(`❌ EMERGENCY FALLBACK FAILED:`, emergencyError.message);
            }
        }
    }

    startDepositMonitoring() {
        setInterval(async () => {
            try {
                for (let i = 0; i < this.autoPending.length; i++) {
                    const trx = this.autoPending[i];
                    if (trx.done || trx.cancelled) continue;

                    if (!trx.startTime) {
                        trx.startTime = Date.now();
                    }

                    const elapsedTime = Date.now() - trx.startTime;
                    const maxMonitoringTime = 10 * 60 * 1000;

                    if (elapsedTime > maxMonitoringTime && !trx.done) {
                        console.log(`⏰ Auto-cancelling deposit ${trx.trx_id} after 10 minutes`);
                        trx.done = true;
                        
                        try {
                            const params = new URLSearchParams({
                                id: trx.trx_id
                            });
                            
                            await axios.get(`${this.config.CIAATOPUP_CANCEL_URL}?${params}`, {
                                headers: { 
                                    'X-APIKEY': this.config.CIAATOPUP_API_KEY,
                                    'Content-Type': 'application/json'
                                },
                                timeout: 3000
                            });
                        } catch (cancelErr) {
                            console.log(`⚠️ Failed to cancel at CiaaTopUp: ${cancelErr.message}`);
                        }
                        
                        await this.cleanupDeposit(trx.id, trx.msgId, trx.trx_id, trx.get_balance, 'expired');
                        continue;
                    }

                    const params = new URLSearchParams({
                        id: trx.trx_id
                    });

                    try {
                        const res = await axios.get(`${this.config.CIAATOPUP_STATUS_URL}?${params}`, {
                            headers: { 
                                'X-APIKEY': this.config.CIAATOPUP_API_KEY,
                                'Content-Type': 'application/json'
                            },
                            timeout: 5000
                        });
                        
                        const status = res.data?.data?.status;

                        if (status === "success") {
                            if (trx.isProduct) {
                                await this.processProductAutoPayment(trx);
                            } else {
                                const users = await this.db.loadUsers();
                                const userIndex = users.findIndex(user => user.id === trx.id.toString());

                                if (userIndex !== -1) {
                                    users[userIndex].saldo += trx.get_balance;
                                    users[userIndex].date = this.getIndonesianTimestamp();
                                } else {
                                    users.push({
                                        id: trx.id.toString(),
                                        saldo: trx.get_balance,
                                        date: this.getIndonesianTimestamp()
                                    });
                                }

                                await this.db.saveUsers(users);
                            }

                            trx.done = true;
                            trx.completedAt = Date.now();
                            await this.cleanupDeposit(trx.id, trx.msgId, trx.trx_id, trx.get_balance, 'success');

                        } else if (["expired", "failed", "cancel"].includes(status)) {
                            trx.done = true;
                            trx.completedAt = Date.now();
                            await this.cleanupDeposit(trx.id, trx.msgId, trx.trx_id, trx.get_balance, 'expired');
                        }

                    } catch (err) {
                        console.log(`[AUTO-CEK] Gagal cek ${trx.trx_id}:`, err.message);
                    }
                }
            } catch (error) {
                console.error('Deposit monitoring error:', error);
            }
        }, 10 * 1000);
    }

    async processProductAutoPayment(trx) {
        const products = await this.db.loadProducts();
        const productIndex = products.findIndex(p => p.id === trx.productId);

        if (productIndex !== -1) {
            products[productIndex].stock -= 1;
            await this.db.saveProducts(products);

            const product = products[productIndex];
            const timeInfo = this.getIndonesianTime();
            const orderId = `ORD-${Date.now()}`;

            await this.sendProductToUser(trx.id, product, orderId, timeInfo, 0);

            const username = await this.getUsernameDisplay(trx.id);

            const productOrders = await this.db.loadProductOrders();
            productOrders.push({
                orderId: orderId,
                userId: trx.id.toString(),
                username: username,
                fullName: trx.user_name,
                productId: product.id,
                productName: product.name,
                price: product.price,
                status: 'completed',
                paymentMethod: 'qris_auto',
                completedAt: this.getIndonesianTimestamp(),
                timeInfo: timeInfo
            });
            await this.db.saveProductOrders(productOrders);

            await this.sendTestimoniProduk(product, username, timeInfo);

            try {
                await this.bot.sendMessage(this.config.OWNER_ID,
                    `🛍️ *PEMBELIAN PRODUK BARU*\n\n` +
                    `🆔 Order ID: \`${orderId}\`\n` +
                    `👤 User ID: \`${trx.id}\`\n` +
                    `📱 Username: @${username}\n` +
                    `📦 Produk: ${product.name}\n` +
                    `💰 Harga: Rp ${product.price.toLocaleString('id-ID')}\n` +
                    `💳 Metode: QRIS Otomatis\n` +
                    `📅 Waktu: ${timeInfo.date} ${timeInfo.time}\n\n` +
                    `✅ Data produk sudah dikirim otomatis ke customer!`,
                    { parse_mode: 'Markdown' }
                );
            } catch (notifError) {
                console.log('Failed to notify owner:', notifError.message);
            }
        }
    }

    async cleanupDeposit(chatId, msgId, trxId, nominal, status) {
        try { await this.bot.deleteMessage(chatId, msgId); } catch {}
        const time = this.getIndonesianTime();
        const text = status === 'success'
            ? `✅ Deposit sukses Rp ${nominal.toLocaleString('id-ID')}`
            : `⏰ Deposit expired Rp ${nominal.toLocaleString('id-ID')}`;
        await this.bot.sendMessage(chatId, `${text}\n🆔 ${trxId} | 🕐 ${time.full}`, { parse_mode: 'Markdown' });
    }

    startCleanupWorker() {
        setInterval(() => {
            const now = Date.now();
            
            this.autoPending = this.autoPending.filter(trx => {
                if (trx.done || trx.cancelled) {
                    const timeSinceDone = now - (trx.completedAt || trx.startTime || 0);
                    if (timeSinceDone > 5 * 60 * 1000) {
                        console.log(`🗑️ Removing completed transaction ${trx.trx_id} from memory`);
                        return false;
                    }
                }
                return true;
            });
            
            this.security.rateLimits.forEach((requests, userId) => {
                const filtered = requests.filter(time => now - time < 60000);
                if (filtered.length === 0) {
                    this.security.rateLimits.delete(userId);
                } else {
                    this.security.rateLimits.set(userId, filtered);
                }
            });
            
        }, 60000);
    }

    // ===== OWNER PANEL METHODS =====

    async showOwnerPanel(chatId, messageId, userId) {
        if (userId !== this.config.OWNER_ID) {
            await this.bot.editMessageText('❌ Access Denied', {
                chat_id: chatId,
                message_id: messageId
            });
            return;
        }

        const users = await this.db.loadUsers();
        const products = await this.db.loadProducts();
        const productOrders = await this.db.loadProductOrders();
        const pendingDeposits = await this.db.loadPendingManualDeposits();
        const broadcastUsers = await this.db.loadBroadcastUsers();
        
        const totalUsers = users.length;
        const totalBroadcastUsers = broadcastUsers.length;
        const totalSaldo = users.reduce((sum, user) => sum + user.saldo, 0);
        const pendingManualDeposits = pendingDeposits.filter(d => d.status === 'pending').length;
        const totalProducts = products.length;
        const pendingProductOrders = productOrders.filter(o => o.status === 'pending').length;

        const keyboard = {
            inline_keyboard: [
                [{ text: '📊 User Statistics', callback_data: 'owner_stats' }],
                [{ text: '💰 Saldo Management', callback_data: 'owner_saldo' }],
                [{ text: '💳 Manual Deposits', callback_data: 'owner_manual_deposits' }],
                [{ text: '🛍️ Manage Products', callback_data: 'owner_products' }],
                [{ text: '📦 Product Orders', callback_data: 'owner_product_orders' }],
                [{ text: '🔙 Main Menu', callback_data: 'back_main' }]
            ]
        };

        const timeInfo = this.getIndonesianTime();

        const ownerText = `👑 *OWNER PANEL*\n\n` +
            `📊 *Bot Statistics:*\n` +
            `👥 Total Users: ${totalUsers}\n` +
            `📡 Broadcast Users: ${totalBroadcastUsers}\n` +
            `💰 Total Saldo: Rp ${totalSaldo.toLocaleString('id-ID')}\n` +
            `💳 Pending Manual Deposits: ${pendingManualDeposits}\n` +
            `🛍️ Total Products: ${totalProducts}\n` +
            `📦 Pending Product Orders: ${pendingProductOrders}\n` +
            `📅 Tanggal: ${timeInfo.date}\n` +
            `🕐 Jam: ${timeInfo.time}\n\n` +
            `📝 *Owner Commands:*\n` +
            `\`/reff USER_ID AMOUNT\` - Add saldo to user\n` +
            `\`/bc TEXT\` - Broadcast text only\n` +
            `\`/produk_add\` - Tambah produk baru\n` +
            `\`/produk_list\` - Lihat daftar produk\n` +
            `\`/delproduk PRODUCT_ID\` - Hapus produk\n` +
            `\`/del USER_ID\` - Delete user\n` +
            `\`/info USER_ID\` - User info\n` +
            `Upload foto + \`/bc CAPTION\` - Broadcast foto`;

        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, ownerText, keyboard);
    }

    async showOwnerStats(chatId, messageId, userId) {
        if (userId !== this.config.OWNER_ID) return;

        const users = await this.db.loadUsers();
        const broadcastUsers = await this.db.loadBroadcastUsers();
        const products = await this.db.loadProducts();
        
        const totalUsers = users.length;
        const usersWithBalance = users.filter(u => u.saldo > 0).length;
        const totalSaldo = users.reduce((sum, user) => sum + user.saldo, 0);
        const avgSaldo = totalUsers > 0 ? Math.round(totalSaldo / totalUsers) : 0;

        const keyboard = {
            inline_keyboard: [
                [{ text: '🔄 Refresh', callback_data: 'owner_stats' }],
                [{ text: '🔙 Owner Panel', callback_data: 'owner_panel' }]
            ]
        };

        const timeInfo = this.getIndonesianTime();

        const statsText = `📊 *USER STATISTICS*\n\n` +
            `👥 *Total Users:* ${totalUsers}\n` +
            `📡 *Broadcast List:* ${broadcastUsers.length}\n` +
            `💰 *Users with Balance:* ${usersWithBalance}\n` +
            `💎 *Total Saldo:* Rp ${totalSaldo.toLocaleString('id-ID')}\n` +
            `📈 *Average Saldo:* Rp ${avgSaldo.toLocaleString('id-ID')}\n` +
            `🛍️ *Total Produk:* ${products.length}\n\n` +
            `📅 Tanggal: ${timeInfo.date}\n` +
            `🕐 Jam: ${timeInfo.time}`;

        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, statsText, keyboard);
    }

    async showOwnerSaldo(chatId, messageId, userId) {
        if (userId !== this.config.OWNER_ID) return;

        const users = await this.db.loadUsers();
        
        const topUsers = users
            .filter(u => u.saldo > 0)
            .sort((a, b) => b.saldo - a.saldo)
            .slice(0, 10);

        const keyboard = {
            inline_keyboard: [
                [{ text: '🔄 Refresh', callback_data: 'owner_saldo' }],
                [{ text: '🔙 Owner Panel', callback_data: 'owner_panel' }]
            ]
        };

        let saldoText = `💰 *SALDO MANAGEMENT*\n\n`;
        
        if (topUsers.length > 0) {
            saldoText += `💎 *Top ${topUsers.length} Users by Balance:*\n\n`;
            topUsers.forEach((user, index) => {
                saldoText += `${index + 1}. ID: \`${user.id}\` - Rp ${user.saldo.toLocaleString('id-ID')}\n`;
            });
        } else {
            saldoText += `📄 *No users with balance found.*\n`;
        }
        
        saldoText += `\n📝 *Commands:*\n`;
        saldoText += `\`/reff USER_ID AMOUNT\` - Add saldo\n\n`;
        
        const timeInfo = this.getIndonesianTime();
        saldoText += `📅 Tanggal: ${timeInfo.date}\n🕐 Jam: ${timeInfo.time}`;
        
        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, saldoText, keyboard);
    }

    async showOwnerManualDeposits(chatId, messageId, userId) {
        if (userId !== this.config.OWNER_ID) return;

        const pendingDeposits = await this.db.loadPendingManualDeposits();
        const pending = pendingDeposits.filter(d => d.status === 'pending');

        const keyboard = {
            inline_keyboard: []
        };

        let depositsText = `💳 *MANUAL DEPOSITS*\n\n`;
        
        if (pending.length > 0) {
            depositsText += `⏰ *Pending Approvals: ${pending.length}*\n\n`;
            
            const displayPending = pending.slice(0, 3);
            
            displayPending.forEach((dep, index) => {
                depositsText += `${index + 1}. *${dep.fullName}*\n`;
                depositsText += `   🆔 Request: \`${dep.requestId}\`\n`;
                depositsText += `   👤 User ID: \`${dep.userId}\`\n`;
                depositsText += `   📱 Username: @${dep.username}\n`;
                depositsText += `   💰 Nominal: Rp ${dep.nominal.toLocaleString('id-ID')}\n`;
                depositsText += `   📅 Dibuat: ${dep.createdAt}\n\n`;
                
                keyboard.inline_keyboard.push([
                    { text: `✅ #${index + 1}`, callback_data: `appr_man_${dep.requestId}` },
                    { text: `❌ #${index + 1}`, callback_data: `rej_man_${dep.requestId}` }
                ]);
            });
            
            if (pending.length > 3) {
                depositsText += `... dan ${pending.length - 3} request lainnya\n\n`;
            }
        } else {
            depositsText += `✅ *No pending deposits*\n\n`;
        }
        
        const timeInfo = this.getIndonesianTime();
        depositsText += `📅 Update: ${timeInfo.date} ${timeInfo.time}`;
        
        keyboard.inline_keyboard.push(
            [{ text: '🔄 Refresh', callback_data: 'owner_manual_deposits' }],
            [{ text: '🔙 Owner Panel', callback_data: 'owner_panel' }]
        );
        
        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, depositsText, keyboard);
    }

    async showOwnerProducts(chatId, messageId, userId) {
        if (userId !== this.config.OWNER_ID) return;

        const products = await this.db.loadProducts();

        const keyboard = {
            inline_keyboard: []
        };

        let productsText = `🛍️ *PRODUCTS MANAGEMENT*\n\n`;
        
        if (products.length > 0) {
            productsText += `📦 *Total Products: ${products.length}*\n\n`;
            
            const displayProducts = products.slice(0, 3);
            
            displayProducts.forEach((prod, index) => {
                const paymentMethod = prod.paymentMethod === 'auto' ? '⚡ QRIS Auto' : 
                                    prod.paymentMethod === 'manual' ? '📸 Manual' : '🔄 Both';
                
                const dataType = prod.productData ? 
                    (prod.productData.type === 'file' ? `📄 File` : '📝 Text') :
                    '❌ No data';
                
                productsText += `${index + 1}. *${prod.name}*\n`;
                productsText += `   💰 Harga: Rp ${prod.price.toLocaleString('id-ID')}\n`;
                productsText += `   📦 Stock: ${prod.stock}\n`;
                productsText += `   💳 Metode: ${paymentMethod}\n`;
                productsText += `   📄 Data: ${dataType}\n`;
                productsText += `   🆔 ID: \`${prod.id}\`\n\n`;
                
                keyboard.inline_keyboard.push([
                    { text: `🗑️ Del #${index + 1}`, callback_data: `del_prod_${prod.id}` }
                ]);
            });
            
            if (products.length > 3) {
                productsText += `... dan ${products.length - 3} produk lainnya\n\n`;
            }
        } else {
            productsText += `📄 *Belum ada produk*\n\n`;
            productsText += `Gunakan \`/produk_add\` untuk menambah produk.\n\n`;
        }
        
        const timeInfo = this.getIndonesianTime();
        productsText += `📅 Update: ${timeInfo.date} ${timeInfo.time}`;
        
        keyboard.inline_keyboard.push(
            [{ text: '➕ Tambah Produk', callback_data: 'add_product_start' }],
            [{ text: '🔄 Refresh', callback_data: 'owner_products' }],
            [{ text: '🔙 Owner Panel', callback_data: 'owner_panel' }]
        );
        
        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, productsText, keyboard);
    }

    async showOwnerProductOrders(chatId, messageId, userId) {
        if (userId !== this.config.OWNER_ID) return;

        const productOrders = await this.db.loadProductOrders();
        const pending = productOrders.filter(o => o.status === 'pending');
        const approved = productOrders.filter(o => o.status === 'approved' || o.status === 'completed');
        const rejected = productOrders.filter(o => o.status === 'rejected');

        const keyboard = {
            inline_keyboard: []
        };

        let ordersText = `📦 *PRODUCT ORDERS MANAGEMENT*\n\n`;
        ordersText += `⏳ Pending: ${pending.length}\n`;
        ordersText += `✅ Approved: ${approved.length}\n`;
        ordersText += `❌ Rejected: ${rejected.length}\n\n`;
        
        if (pending.length > 0) {
            ordersText += `⏳ *PENDING ORDERS:*\n\n`;
            
            const displayPending = pending.slice(0, 3);
            
            displayPending.forEach((order, index) => {
                ordersText += `${index + 1}. *${order.productName}*\n`;
                ordersText += `   🆔 Order: \`${order.orderId}\`\n`;
                ordersText += `   👤 User ID: \`${order.userId}\`\n`;
                ordersText += `   📱 Username: @${order.username}\n`;
                ordersText += `   💰 Harga: Rp ${order.price.toLocaleString('id-ID')}\n`;
                ordersText += `   📅 Dibuat: ${order.createdAt}\n\n`;
                
                keyboard.inline_keyboard.push([
                    { text: `✅ #${index + 1}`, callback_data: `appr_prod_${order.orderId}` },
                    { text: `❌ #${index + 1}`, callback_data: `rej_prod_${order.orderId}` }
                ]);
            });
            
            if (pending.length > 3) {
                ordersText += `... dan ${pending.length - 3} order lainnya\n\n`;
            }
        } else {
            ordersText += `✅ *No pending product orders*\n\n`;
        }
        
        const timeInfo = this.getIndonesianTime();
        ordersText += `📅 Update: ${timeInfo.date} ${timeInfo.time}`;
        
        keyboard.inline_keyboard.push(
            [{ text: '🔄 Refresh', callback_data: 'owner_product_orders' }],
            [{ text: '🔙 Owner Panel', callback_data: 'owner_panel' }]
        );
        
        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, ordersText, keyboard);
    }

    async approveProductPayment(chatId, messageId, data, userId, query) {
        if (userId !== this.config.OWNER_ID) return;

        let orderId = data.startsWith('appr_prod_') ? data.replace('appr_prod_', '') : data.replace('approve_product_payment_', '');

        try {
            const productOrders = await this.db.loadProductOrders();
            const orderIndex = productOrders.findIndex(o => o.orderId === orderId && o.status === 'pending');

            if (orderIndex === -1) {
                await this.bot.answerCallbackQuery(query.id, {
                    text: '❌ Order tidak ditemukan atau sudah diproses',
                    show_alert: true
                });
                return;
            }

            const order = productOrders[orderIndex];

            const products = await this.db.loadProducts();
            const productIndex = products.findIndex(p => p.id === order.productId);

            if (productIndex === -1) {
                await this.bot.sendMessage(chatId, '❌ Produk tidak ditemukan di database');
                return;
            }

            if (products[productIndex].stock <= 0) {
                await this.bot.sendMessage(chatId, '❌ Stock produk habis, tidak bisa approve');
                return;
            }

            products[productIndex].stock -= 1;
            await this.db.saveProducts(products);

            productOrders[orderIndex].status = 'approved';
            productOrders[orderIndex].approvedAt = this.getIndonesianTimestamp();
            productOrders[orderIndex].approvedBy = userId;
            await this.db.saveProductOrders(productOrders);

            const product = products[productIndex];
            const timeInfo = this.getIndonesianTime();

            await this.sendProductToUser(parseInt(order.userId), product, order.orderId, timeInfo, 0);

            await this.sendTestimoniProduk(product, order.username, timeInfo);

            await this.bot.sendMessage(chatId,
                `✅ *ORDER PRODUK APPROVED*\n\n` +
                `🆔 Order ID: \`${order.orderId}\`\n` +
                `👤 User ID: \`${order.userId}\`\n` +
                `📦 Produk: ${product.name}\n` +
                `💰 Harga: Rp ${order.price.toLocaleString('id-ID')}\n` +
                `📦 Stock tersisa: ${products[productIndex].stock}\n\n` +
                `Data produk telah dikirim ke customer!`,
                { parse_mode: 'Markdown' }
            );

            await this.bot.answerCallbackQuery(query.id, {
                text: "✅ Order approved & data sent!"
            });

        } catch (error) {
            console.error('Approve product payment error:', error);
            await this.bot.sendMessage(chatId, '❌ Error approving product payment');
        }
    }

    async rejectProductPayment(chatId, messageId, data, userId, query) {
        if (userId !== this.config.OWNER_ID) return;

        let orderId = data.startsWith('rej_prod_') ? data.replace('rej_prod_', '') : data.replace('reject_product_payment_', '');

        try {
            const productOrders = await this.db.loadProductOrders();
            const orderIndex = productOrders.findIndex(o => o.orderId === orderId && o.status === 'pending');

            if (orderIndex === -1) {
                await this.bot.answerCallbackQuery(query.id, {
                    text: '❌ Order tidak ditemukan atau sudah diproses',
                    show_alert: true
                });
                return;
            }

            const order = productOrders[orderIndex];

            productOrders[orderIndex].status = 'rejected';
            productOrders[orderIndex].rejectedAt = this.getIndonesianTimestamp();
            productOrders[orderIndex].rejectedBy = userId;
            await this.db.saveProductOrders(productOrders);

            await this.bot.sendMessage(chatId,
                `❌ *ORDER PRODUK REJECTED*\n\n` +
                `🆔 Order ID: \`${order.orderId}\`\n` +
                `👤 User ID: \`${order.userId}\`\n` +
                `📦 Produk: ${order.productName}\n` +
                `💰 Harga: Rp ${order.price.toLocaleString('id-ID')}\n\n` +
                `User telah dinotifikasi.`,
                { parse_mode: 'Markdown' }
            );

            try {
                await this.bot.sendMessage(parseInt(order.userId),
                    `❌ *PEMBAYARAN DITOLAK*\n\n` +
                    `🆔 Order ID: \`${order.orderId}\`\n` +
                    `📦 Produk: ${order.productName}\n` +
                    `💰 Harga: Rp ${order.price.toLocaleString('id-ID')}\n\n` +
                    `Maaf, pembayaran Anda ditolak.\n` +
                    `Hubungi @Jeeyhosting untuk info lebih lanjut.`,
                    { parse_mode: 'Markdown' }
                );
            } catch (notifError) {
                console.log('Failed to notify user:', notifError.message);
            }

            await this.bot.answerCallbackQuery(query.id, {
                text: "✅ Order rejected"
            });

        } catch (error) {
            console.error('Reject product payment error:', error);
            await this.bot.sendMessage(chatId, '❌ Error rejecting product payment');
        }
    }

    async approveManualDeposit(chatId, messageId, data, userId, query) {
        if (userId !== this.config.OWNER_ID) return;

        let requestId = data.startsWith('appr_man_') ? data.replace('appr_man_', '') : data.replace('approve_manual_', '');

        try {
            const pendingDeposits = await this.db.loadPendingManualDeposits();
            const depositIndex = pendingDeposits.findIndex(d => d.requestId === requestId && d.status === 'pending');

            if (depositIndex === -1) {
                await this.bot.answerCallbackQuery(query.id, {
                    text: '❌ Request tidak ditemukan atau sudah diproses',
                    show_alert: true
                });
                return;
            }

            const deposit = pendingDeposits[depositIndex];

            const refundResult = await this.updateUserSaldo(deposit.userId, deposit.nominal, 'add');

            if (refundResult.success) {
                pendingDeposits[depositIndex].status = 'approved';
                pendingDeposits[depositIndex].approvedAt = this.getIndonesianTimestamp();
                pendingDeposits[depositIndex].approvedBy = userId;
                await this.db.savePendingManualDeposits(pendingDeposits);

                await this.bot.sendMessage(chatId,
                    `✅ *DEPOSIT APPROVED*\n\n` +
                    `🆔 Request ID: \`${requestId}\`\n` +
                    `👤 User ID: \`${deposit.userId}\`\n` +
                    `📛 Nama: ${deposit.fullName}\n` +
                    `📱 Username: @${deposit.username}\n` +
                    `💰 Nominal: Rp ${deposit.nominal.toLocaleString('id-ID')}\n` +
                    `💎 Saldo baru: Rp ${refundResult.newSaldo.toLocaleString('id-ID')}\n\n` +
                    `Saldo telah ditambahkan!`,
                    { parse_mode: 'Markdown' }
                );

                await this.bot.sendMessage(deposit.userId,
                    `✅ *DEPOSIT DISETUJUI*\n\n` +
                    `🆔 Request ID: \`${requestId}\`\n` +
                    `💰 Nominal: Rp ${deposit.nominal.toLocaleString('id-ID')}\n` +
                    `💎 Saldo baru: Rp ${refundResult.newSaldo.toLocaleString('id-ID')}\n\n` +
                    `Terima kasih!`,
                    { parse_mode: 'Markdown' }
                );

                await this.bot.answerCallbackQuery(query.id, {
                    text: "✅ Deposit approved!"
                });
            } else {
                await this.bot.sendMessage(chatId, '❌ Gagal menambahkan saldo');
            }

        } catch (error) {
            console.error('Approve manual deposit error:', error);
            await this.bot.sendMessage(chatId, '❌ Error approving deposit');
        }
    }

    async rejectManualDeposit(chatId, messageId, data, userId, query) {
        if (userId !== this.config.OWNER_ID) return;

        let requestId = data.startsWith('rej_man_') ? data.replace('rej_man_', '') : data.replace('reject_manual_', '');

        try {
            const pendingDeposits = await this.db.loadPendingManualDeposits();
            const depositIndex = pendingDeposits.findIndex(d => d.requestId === requestId && d.status === 'pending');

            if (depositIndex === -1) {
                await this.bot.answerCallbackQuery(query.id, {
                    text: '❌ Request tidak ditemukan atau sudah diproses',
                    show_alert: true
                });
                return;
            }

            const deposit = pendingDeposits[depositIndex];

            pendingDeposits[depositIndex].status = 'rejected';
            pendingDeposits[depositIndex].rejectedAt = this.getIndonesianTimestamp();
            pendingDeposits[depositIndex].rejectedBy = userId;
            await this.db.savePendingManualDeposits(pendingDeposits);

            await this.bot.sendMessage(chatId,
                `❌ *DEPOSIT DITOLAK*\n\n` +
                `🆔 Request ID: \`${requestId}\`\n` +
                `👤 User ID: \`${deposit.userId}\`\n` +
                `📛 Nama: ${deposit.fullName}\n` +
                `📱 Username: @${deposit.username}\n` +
                `💰 Nominal: Rp ${deposit.nominal.toLocaleString('id-ID')}\n\n` +
                `User telah dinotifikasi.`,
                { parse_mode: 'Markdown' }
            );

            try {
                await this.bot.sendMessage(deposit.userId,
                    `❌ *DEPOSIT DITOLAK*\n\n` +
                    `🆔 Request ID: \`${requestId}\`\n` +
                    `💰 Nominal: Rp ${deposit.nominal.toLocaleString('id-ID')}\n\n` +
                    `Maaf, deposit Anda ditolak.\n` +
                    `Hubungi @Jeeyhosting untuk info lebih lanjut.`,
                    { parse_mode: 'Markdown' }
                );
            } catch (notifError) {
                console.log('Failed to notify user:', notifError.message);
            }

            await this.bot.answerCallbackQuery(query.id, {
                text: "✅ Deposit rejected"
            });

        } catch (error) {
            console.error('Reject manual deposit error:', error);
            await this.bot.sendMessage(chatId, '❌ Error rejecting deposit');
        }
    }

    async deleteProduct(chatId, messageId, data, userId) {
        if (userId !== this.config.OWNER_ID) return;

        let productId = data.startsWith('del_prod_') ? data.replace('del_prod_', '') : data.replace('delete_product_', '');

        try {
            const products = await this.db.loadProducts();
            const productIndex = products.findIndex(p => p.id === productId);

            if (productIndex === -1) {
                await this.bot.sendMessage(chatId, '❌ Produk tidak ditemukan');
                return;
            }

            const product = products[productIndex];
            products.splice(productIndex, 1);
            await this.db.saveProducts(products);

            await this.db.deleteProduct(productId);

            await this.bot.sendMessage(chatId,
                `✅ *PRODUK DIHAPUS*\n\n` +
                `📦 Nama: ${product.name}\n` +
                `🆔 ID: \`${productId}\`\n\n` +
                `Produk dan semua file terkait telah dihapus.`,
                { parse_mode: 'Markdown' }
            );

        } catch (error) {
            console.error('Delete product error:', error);
            await this.bot.sendMessage(chatId, '❌ Error deleting product');
        }
    }

    async handleAddProductStart(chatId, messageId, userId) {
        if (userId !== this.config.OWNER_ID) {
            await this.bot.editMessageText('❌ Access Denied', {
                chat_id: chatId,
                message_id: messageId
            });
            return;
        }

        await this.bot.sendMessage(chatId,
            `➕ *TAMBAH PRODUK BARU*\n\n` +
            `Gunakan command: \`/produk_add\`\n\n` +
            `Atau kembali ke panel owner.`,
            { 
                parse_mode: 'Markdown',
                reply_markup: {
                    inline_keyboard: [[{ text: '🔙 Owner Panel', callback_data: 'owner_panel' }]]
                }
            }
        );
    }

    async handleDepositManual(msg, match) {
        const chatId = msg.chat.id;
        const userId = msg.from.id;
        const nominal = parseInt(match[1]);

        if (!nominal || nominal < 1000) {
            return this.bot.sendMessage(chatId, 
                "❌ Minimal deposit Rp 1,000\nContoh: `/deposit_manual 5000`",
                { parse_mode: 'Markdown' }
            );
        }

        const requestId = `REQ-${Date.now()}`;
        const username = await this.getUsernameDisplay(userId);
        const fullName = msg.from.first_name + (msg.from.last_name ? ' ' + msg.from.last_name : '');
        const timeInfo = this.getIndonesianTime();

        const pendingDeposits = await this.db.loadPendingManualDeposits();
        pendingDeposits.push({
            requestId: requestId,
            userId: userId,
            username: username,
            fullName: fullName,
            nominal: nominal,
            status: 'pending',
            createdAt: this.getIndonesianTimestamp(),
            timeInfo: timeInfo
        });
        await this.db.savePendingManualDeposits(pendingDeposits);

        await this.bot.sendMessage(chatId,
            `📋 *REQUEST DEPOSIT MANUAL*\n\n` +
            `🆔 Request ID: \`${requestId}\`\n` +
            `💰 Nominal: Rp ${nominal.toLocaleString('id-ID')}\n` +
            `⏳ Status: Menunggu approval\n\n` +
            `Request Anda akan diproses oleh owner.\n` +
            `Harap tunggu konfirmasi.`,
            { parse_mode: 'Markdown' }
        );

        try {
            await this.bot.sendMessage(this.config.OWNER_ID,
                `📋 *DEPOSIT MANUAL REQUEST BARU*\n\n` +
                `🆔 Request ID: \`${requestId}\`\n` +
                `👤 User ID: \`${userId}\`\n` +
                `📛 Nama: ${fullName}\n` +
                `📱 Username: @${username}\n` +
                `💰 Nominal: Rp ${nominal.toLocaleString('id-ID')}\n` +
                `📅 Waktu: ${timeInfo.date} ${timeInfo.time}\n\n` +
                `Approve atau Reject di Owner Panel.`,
                { 
                    parse_mode: 'Markdown',
                    reply_markup: {
                        inline_keyboard: [
                            [
                                { text: '✅ APPROVE', callback_data: `appr_man_${requestId}` },
                                { text: '❌ REJECT', callback_data: `rej_man_${requestId}` }
                            ]
                        ]
                    }
                }
            );
        } catch (notifError) {
            console.log('Failed to notify owner:', notifError.message);
        }
    }

    async handleReffCommand(msg, match) {
        const senderId = msg.from.id;
        const chatId = msg.chat.id;

        if (senderId !== this.config.OWNER_ID) {
            return this.bot.sendMessage(chatId, "❌ Command ini hanya untuk owner.");
        }

        const targetUserId = match[1];
        const amount = parseInt(match[2]);

        if (!amount || amount < 1) {
            return this.bot.sendMessage(chatId, "❌ Jumlah tidak valid. Contoh: `/reff 123456 5000`", {
                parse_mode: 'Markdown'
            });
        }

        const result = await this.updateUserSaldo(targetUserId, amount, 'add');

        if (result.success) {
            await this.bot.sendMessage(chatId,
                `✅ *SALDO BERHASIL DITAMBAHKAN*\n\n` +
                `👤 User ID: \`${targetUserId}\`\n` +
                `💰 Jumlah: Rp ${amount.toLocaleString('id-ID')}\n` +
                `💎 Saldo baru: Rp ${result.newSaldo.toLocaleString('id-ID')}`,
                { parse_mode: 'Markdown' }
            );

            try {
                await this.bot.sendMessage(targetUserId,
                    `✅ *SALDO DITAMBAHKAN*\n\n` +
                    `💰 +Rp ${amount.toLocaleString('id-ID')}\n` +
                    `💎 Saldo baru: Rp ${result.newSaldo.toLocaleString('id-ID')}\n\n` +
                    `Terima kasih!`,
                    { parse_mode: 'Markdown' }
                );
            } catch (notifError) {
                console.log('Failed to notify user:', notifError.message);
            }
        } else {
            await this.bot.sendMessage(chatId, '❌ Gagal menambahkan saldo');
        }
    }

    async handleBroadcast(msg, match) {
        const senderId = msg.from.id;
        const chatId = msg.chat.id;

        if (senderId !== this.config.OWNER_ID) {
            return this.bot.sendMessage(chatId, "❌ Command ini hanya untuk owner.");
        }

        const bcText = match[1];
        const users = await this.db.loadBroadcastUsers();

        await this.bot.sendMessage(chatId, 
            `📡 *BROADCAST DIMULAI*\n\n` +
            `Target: ${users.length} users\n` +
            `Pesan: Text only\n\n` +
            `Mohon tunggu...`,
            { parse_mode: 'Markdown' }
        );

        let success = 0;
        let failed = 0;

        for (const userId of users) {
            try {
                await this.bot.sendMessage(userId, bcText, { parse_mode: 'Markdown' });
                success++;
                await new Promise(resolve => setTimeout(resolve, 50));
            } catch (error) {
                failed++;
                console.log(`Failed to broadcast to ${userId}:`, error.message);
            }
        }

        await this.bot.sendMessage(chatId,
            `✅ *BROADCAST SELESAI*\n\n` +
            `✅ Sukses: ${success}\n` +
            `❌ Gagal: ${failed}\n` +
            `📊 Total: ${users.length}`,
            { parse_mode: 'Markdown' }
        );
    }

    async handlePhotoBroadcast(msg) {
        const senderId = msg.from.id;
        const chatId = msg.chat.id;

        if (senderId !== this.config.OWNER_ID) {
            return this.bot.sendMessage(chatId, "❌ Command ini hanya untuk owner.");
        }

        const caption = msg.caption.replace('/bc ', '');
        const photoId = msg.photo[msg.photo.length - 1].file_id;
        const users = await this.db.loadBroadcastUsers();

        await this.bot.sendMessage(chatId,
            `📡 *BROADCAST DIMULAI*\n\n` +
            `Target: ${users.length} users\n` +
            `Pesan: Photo + Caption\n\n` +
            `Mohon tunggu...`,
            { parse_mode: 'Markdown' }
        );

        let success = 0;
        let failed = 0;

        for (const userId of users) {
            try {
                await this.bot.sendPhoto(userId, photoId, {
                    caption: caption,
                    parse_mode: 'Markdown'
                });
                success++;
                await new Promise(resolve => setTimeout(resolve, 50));
            } catch (error) {
                failed++;
                console.log(`Failed to broadcast photo to ${userId}:`, error.message);
            }
        }

        await this.bot.sendMessage(chatId,
            `✅ *BROADCAST SELESAI*\n\n` +
            `✅ Sukses: ${success}\n` +
            `❌ Gagal: ${failed}\n` +
            `📊 Total: ${users.length}`,
            { parse_mode: 'Markdown' }
        );
    }

    async handleProdukList(msg) {
        const senderId = msg.from.id;
        const chatId = msg.chat.id;

        if (senderId !== this.config.OWNER_ID) {
            return this.bot.sendMessage(chatId, "❌ Command ini hanya untuk owner.");
        }

        const products = await this.db.loadProducts();

        if (products.length === 0) {
            return this.bot.sendMessage(chatId, '📦 *Belum ada produk.*', { parse_mode: 'Markdown' });
        }

        let productList = `📦 *DAFTAR PRODUK (${products.length})*\n\n`;

        products.forEach((prod, index) => {
            const paymentMethod = prod.paymentMethod === 'auto' ? '⚡ Auto' : 
                                prod.paymentMethod === 'manual' ? '📸 Manual' : '🔄 Both';
            const dataType = prod.productData ? 
                (prod.productData.type === 'file' ? '📄 File' : '📝 Text') :
                '❌ No data';
            
            productList += `${index + 1}. *${prod.name}*\n`;
            productList += `   💰 Harga: Rp ${prod.price.toLocaleString('id-ID')}\n`;
            productList += `   📦 Stock: ${prod.stock}\n`;
            productList += `   💳 Metode: ${paymentMethod}\n`;
            productList += `   📄 Data: ${dataType}\n`;
            productList += `   🆔 ID: \`${prod.id}\`\n\n`;
        });

        productList += `\n💡 Gunakan \`/delproduk PRODUCT_ID\` untuk hapus`;

        await this.bot.sendMessage(chatId, productList, { parse_mode: 'Markdown' });
    }

    async handleDelProduk(msg, match) {
        const senderId = msg.from.id;
        const chatId = msg.chat.id;
        const productId = match[1];

        if (senderId !== this.config.OWNER_ID) {
            return this.bot.sendMessage(chatId, "❌ Command ini hanya untuk owner.");
        }

        const products = await this.db.loadProducts();
        const productIndex = products.findIndex(p => p.id === productId);

        if (productIndex === -1) {
            return this.bot.sendMessage(chatId, '❌ Produk tidak ditemukan.');
        }

        const product = products[productIndex];
        products.splice(productIndex, 1);
        await this.db.saveProducts(products);

        await this.db.deleteProduct(productId);

        await this.bot.sendMessage(chatId,
            `✅ *PRODUK DIHAPUS*\n\n` +
            `📦 Nama: ${product.name}\n` +
            `🆔 ID: \`${productId}\`\n\n` +
            `Produk dan semua file terkait telah dihapus.`,
            { parse_mode: 'Markdown' }
        );
    }

    async handleDelete(msg, match) {
        const senderId = msg.from.id;
        const chatId = msg.chat.id;
        const targetUserId = match[1];

        if (senderId !== this.config.OWNER_ID) {
            return this.bot.sendMessage(chatId, "❌ Command ini hanya untuk owner.");
        }

        const users = await this.db.loadUsers();
        const userIndex = users.findIndex(u => u.id === targetUserId);

        if (userIndex === -1) {
            return this.bot.sendMessage(chatId, '❌ User tidak ditemukan.');
        }

        const deletedUser = users[userIndex];
        users.splice(userIndex, 1);
        await this.db.saveUsers(users);

        await this.bot.sendMessage(chatId,
            `✅ *USER DIHAPUS*\n\n` +
            `👤 User ID: \`${targetUserId}\`\n` +
            `💰 Saldo terhapus: Rp ${deletedUser.saldo.toLocaleString('id-ID')}`,
            { parse_mode: 'Markdown' }
        );
    }

    async handleInfo(msg, match) {
        const senderId = msg.from.id;
        const chatId = msg.chat.id;
        const targetUserId = match[1];

        if (senderId !== this.config.OWNER_ID) {
            return this.bot.sendMessage(chatId, "❌ Command ini hanya untuk owner.");
        }

        const user = await this.getUser(targetUserId);

        if (!user) {
            return this.bot.sendMessage(chatId, '❌ User tidak ditemukan.');
        }

        const productOrders = await this.db.loadProductOrders();
        const userOrders = productOrders.filter(o => o.userId === targetUserId);

        await this.bot.sendMessage(chatId,
            `👤 *USER INFO*\n\n` +
            `🆔 User ID: \`${targetUserId}\`\n` +
            `💰 Saldo: Rp ${user.saldo.toLocaleString('id-ID')}\n` +
            `📦 Total Order: ${userOrders.length}\n` +
            `📅 Terdaftar: ${user.date}`,
            { parse_mode: 'Markdown' }
        );
    }

    // ===== USER MENU METHODS =====

    async checkBalance(chatId, messageId, userId) {
        const user = await this.getUser(userId);
        const saldo = user ? user.saldo : 0;

        const keyboard = {
            inline_keyboard: [
                [{ text: '💳 Top Up', callback_data: 'topup' }],
                [{ text: '🔙 Menu Utama', callback_data: 'back_main' }]
            ]
        };

        const timeInfo = this.getIndonesianTime();

        const balanceText = `💰 *CEK SALDO*\n\n` +
            `👤 User ID: \`${userId}\`\n` +
            `💎 Saldo Anda: *Rp ${saldo.toLocaleString('id-ID')}*\n\n` +
            `📅 Tanggal: ${timeInfo.date}\n` +
            `🕐 Jam: ${timeInfo.time}\n\n` +
            `💡 Saldo dapat digunakan untuk membeli produk digital.`;

        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, balanceText, keyboard);
    }

    async showOrderHistory(chatId, messageId, userId) {
        const productOrders = await this.db.loadProductOrders();
        const userOrders = productOrders.filter(o => o.userId === userId.toString());

        const keyboard = {
            inline_keyboard: [[{ text: '🔙 Menu Utama', callback_data: 'back_main' }]]
        };

        let historyText = `📜 *RIWAYAT ORDER*\n\n`;

        if (userOrders.length === 0) {
            historyText += `📄 Belum ada riwayat order.\n\n`;
            historyText += `Mulai belanja di menu Produk Digital!`;
        } else {
            const recentOrders = userOrders.slice(-5).reverse();
            
            recentOrders.forEach((order, index) => {
                const statusEmoji = order.status === 'completed' || order.status === 'approved' ? '✅' : 
                                  order.status === 'pending' ? '⏳' : '❌';
                const statusText = order.status === 'completed' || order.status === 'approved' ? 'Sukses' : 
                                 order.status === 'pending' ? 'Pending' : 'Ditolak';
                
                historyText += `${index + 1}. ${statusEmoji} *${order.productName}*\n`;
                historyText += `   💰 Rp ${order.price.toLocaleString('id-ID')}\n`;
                historyText += `   📊 Status: ${statusText}\n`;
                historyText += `   🆔 ${order.orderId}\n`;
                historyText += `   📅 ${order.createdAt}\n\n`;
            });

            if (userOrders.length > 5) {
                historyText += `... dan ${userOrders.length - 5} order lainnya\n\n`;
            }

            historyText += `📊 Total Order: ${userOrders.length}`;
        }

        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, historyText, keyboard);
    }

    async showTopup(chatId, messageId) {
        const keyboard = {
            inline_keyboard: [
                [{ text: '⚡ QRIS Otomatis', callback_data: 'topup_auto' }],
                [{ text: '🔙 Menu Utama', callback_data: 'back_main' }]
            ]
        };

        const topupText = `💳 *TOP UP SALDO*\n\n` +
            `Pilih metode top up:\n\n` +
            `⚡ *QRIS Otomatis*\n` +
            `• Pembayaran via QRIS\n` +
            `• Saldo masuk otomatis\n` +
            `• Proses cepat (1-5 menit)\n\n` +
            `💡 *Cara Top Up:*\n` +
            `Ketik: \`/deposit JUMLAH\`\n` +
            `Contoh: \`/deposit 10000\`\n\n` +
            `Minimal deposit: Rp 1.000`;

        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, topupText, keyboard);
    }

    async showHelp(chatId, messageId) {
        const keyboard = {
            inline_keyboard: [[{ text: '🔙 Menu Utama', callback_data: 'back_main' }]]
        };

        const helpText = `ℹ️ *BANTUAN*\n\n` +
            `📝 *Cara Menggunakan Bot:*\n\n` +
            `1️⃣ *Top Up Saldo*\n` +
            `   • Ketik \`/deposit JUMLAH\`\n` +
            `   • Scan QRIS & bayar\n` +
            `   • Saldo masuk otomatis\n\n` +
            `2️⃣ *Beli Produk*\n` +
            `   • Pilih menu Produk Digital\n` +
            `   • Pilih produk yang diinginkan\n` +
            `   • Bayar dengan saldo/QRIS\n` +
            `   • Produk dikirim otomatis\n\n` +
            `3️⃣ *Cek Saldo & Riwayat*\n` +
            `   • Menu Cek Saldo\n` +
            `   • Menu Riwayat Order\n\n` +
            `❓ *Butuh Bantuan?*\n` +
            `Hubungi: @Jeeyhosting\n\n` +
            `⚡ *Bot Aktif 24/7*`;

        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, helpText, keyboard);
    }

    async showRules(chatId, messageId) {
        const keyboard = {
            inline_keyboard: [[{ text: '🔙 Menu Utama', callback_data: 'back_main' }]]
        };

        const rulesText = `📜 *SYARAT & KETENTUAN*\n\n` +
            `⚠️ *PENTING - HARAP DIBACA*\n\n` +
            `1️⃣ *Tentang Saldo*\n` +
            `   • Saldo yang ada di bot TIDAK BISA di-refund\n` +
            `   • Top up sesuai kebutuhan\n` +
            `   • Saldo hanya untuk transaksi di bot ini\n\n` +
            `2️⃣ *Tentang Produk*\n` +
            `   • Pastikan pilih produk dengan benar\n` +
            `   • Produk dikirim otomatis setelah bayar\n` +
            `   • Tidak ada pengembalian setelah produk terkirim\n\n` +
            `3️⃣ *Tentang Pembayaran*\n` +
            `   • QRIS Otomatis: saldo masuk otomatis\n` +
            `   • Manual: tunggu approval owner\n` +
            `   • Upload bukti yang jelas\n\n` +
            `4️⃣ *Larangan*\n` +
            `   • Spam atau flood bot\n` +
            `   • Menggunakan bot untuk hal ilegal\n` +
            `   • Chargeback setelah transaksi\n\n` +
            `⚠️ *Pelanggaran akan dibanned permanen*\n\n` +
            `📞 Support: @Jeeyhosting`;

        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, rulesText, keyboard);
    }

    async showMainMenu(chatId, messageId, userId) {
        const user = await this.getUser(userId);
        const uniqueUsers = await this.loadUniqueUsers();
        const usersWithBalance = await this.getUsersWithBalance();
        const products = await this.db.loadProducts();

        const keyboard = {
            inline_keyboard: [
                [
                    { text: '🛍️ Produk Digital', callback_data: 'produk_digital' },
                    { text: '💰 Cek Saldo', callback_data: 'check_balance' }
                ],
                [
                    { text: '📜 Riwayat Order', callback_data: 'order_history' },
                    { text: '💳 Top Up', callback_data: 'topup' }
                ],
                [
                    { text: '📜 Syarat & Ketentuan', callback_data: 'rules' },
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
        const saldoDisplay = user ? user.saldo.toLocaleString('id-ID') : '0';

        const mainText = `🏠 *MENU UTAMA*\n\n` +
            `👤 User ID: \`${userId}\`\n` +
            `💰 Saldo: *Rp ${saldoDisplay}*\n` +
            `📅 ${timeInfo.date} | 🕐 ${timeInfo.time}\n\n` +
            `📊 *Statistik Bot:*\n` +
            `👥 Total User: ${uniqueUsers.length}\n` +
            `💳 User dengan Saldo: ${usersWithBalance.length}\n` +
            `📦 Total Produk: ${products.length}\n\n` +
            `Pilih menu di bawah:`;

        await editPhotoCaption(this.bot, chatId, messageId, this.botLogo, mainText, keyboard);
    }

    // ===== UTILITY METHODS =====

    async getUser(userId) {
        const users = await this.db.loadUsers();
        return users.find(user => user.id === userId.toString());
    }

    async updateUserSaldo(userId, amount, operation) {
        try {
            const users = await this.db.loadUsers();
            const userIndex = users.findIndex(user => user.id === userId.toString());

            if (userIndex !== -1) {
                if (operation === 'add') {
                    users[userIndex].saldo += amount;
                } else if (operation === 'subtract') {
                    if (users[userIndex].saldo < amount) {
                        return { success: false, error: 'insufficient_balance' };
                    }
                    users[userIndex].saldo -= amount;
                }
                users[userIndex].date = this.getIndonesianTimestamp();
                
                await this.db.saveUsers(users);
                return { success: true, newSaldo: users[userIndex].saldo };
            } else {
                if (operation === 'add') {
                    users.push({
                        id: userId.toString(),
                        saldo: amount,
                        date: this.getIndonesianTimestamp()
                    });
                    await this.db.saveUsers(users);
                    return { success: true, newSaldo: amount };
                } else {
                    return { success: false, error: 'user_not_found' };
                }
            }
        } catch (error) {
            console.error('Update user saldo error:', error);
            return { success: false, error: 'database_error' };
        }
    }

    async addUserToBroadcastList(userId) {
        const users = await this.db.loadBroadcastUsers();
        if (!users.includes(userId)) {
            users.push(userId);
            await this.db.saveBroadcastUsers(users);
        }
    }

    async loadUniqueUsers() {
        const users = await this.db.loadUsers();
        const broadcastUsers = await this.db.loadBroadcastUsers();
        const allUserIds = new Set([
            ...users.map(u => u.id),
            ...broadcastUsers.map(u => u.toString())
        ]);
        return Array.from(allUserIds);
    }

    async getUsersWithBalance() {
        const users = await this.db.loadUsers();
        return users.filter(u => u.saldo > 0);
    }

    async getUsernameDisplay(userId) {
        try {
            const chatMember = await this.bot.getChatMember(userId, userId);
            if (chatMember.user.username) {
                return chatMember.user.username;
            }
            return chatMember.user.first_name || 'User';
        } catch (error) {
            return 'User';
        }
    }

    getIndonesianTime() {
        const now = new Date();
        const options = { timeZone: 'Asia/Jakarta' };
        const dateStr = now.toLocaleDateString('id-ID', { ...options, day: '2-digit', month: '2-digit', year: 'numeric' });
        const timeStr = now.toLocaleTimeString('id-ID', { ...options, hour: '2-digit', minute: '2-digit', second: '2-digit' });
        return {
            date: dateStr,
            time: timeStr,
            full: `${dateStr} ${timeStr}`
        };
    }

    getIndonesianTimestamp() {
        const time = this.getIndonesianTime();
        return time.full;
    }
}

// ============================================
// 🚀 START BOT
// ============================================
(async () => {
    try {
        const bot = new DigitalProductBot();
        await bot.initPromise;
        console.log('✅ Bot is running successfully!');
    } catch (error) {
        console.error('❌ Fatal error starting bot:', error);
        process.exit(1);
    }
})();