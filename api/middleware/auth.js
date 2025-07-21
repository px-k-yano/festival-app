// api/middleware/auth.js
const crypto = require('crypto');

// APIキーのハッシュ値（実際のAPIキーをSHA-256でハッシュ化したもの）
const VALID_API_KEY_HASHES = [
    "b02a4c47e34b976bfa3a44372c63905ca686180fc6f232cb4ff052179e8d634f", // メインPWAアプリ
    // "23623bf44f88d1d2b09b35572b1f0e10329b2c3ed1811942854f0ec7e105702f", // 予備/追加アプリ1
    // "6c98b105467fb5c615ceacea13176c311f418042a4b1987dbde2629391b2de3d", // 予備/追加アプリ2
];


/**
 * APIキー認証ミドルウェア
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
function authenticateApiKey(req, res, next) {
    // APIキーの取得（複数の方法をサポート）
    const apiKey = req.header('X-API-Key') || 
                   req.header('Authorization')?.replace('Bearer ', '') ||
                   req.query.apikey ||
                   req.body.apikey;

    if (!apiKey) {
        return res.status(401).json({ 
            error: 'API key is required',
            message: 'Please provide API key in X-API-Key header, Authorization header, or as query parameter' 
        });
    }

    // APIキーのハッシュ化
    const hashedApiKey = crypto.createHash('sha256').update(apiKey).digest('hex');

    // ハッシュ値の照合
    if (!VALID_API_KEY_HASHES.includes(hashedApiKey)) {
        // セキュリティログの記録
        console.warn(`Invalid API key attempt from IP: ${req.ip}, User-Agent: ${req.get('User-Agent')}`);
        
        return res.status(403).json({ 
            error: 'Invalid API key',
            message: 'The provided API key is not valid' 
        });
    }

    // 認証成功
    console.log(`API key authenticated for IP: ${req.ip}`);
    next();
}

/**
 * APIキーのハッシュ値を生成するヘルパー関数
 * @param {string} apiKey - 平文のAPIキー
 * @returns {string} - SHA-256ハッシュ値
 */
function generateApiKeyHash(apiKey) {
    return crypto.createHash('sha256').update(apiKey).digest('hex');
}

module.exports = {
    authenticateApiKey,
    generateApiKeyHash
};