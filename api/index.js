require("dotenv").config();
const archiver = require("archiver");
const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const { Pool } = require("pg");
const { EmailClient } = require("@azure/communication-email");
const multer = require("multer");
const path = require("path");
const helmet = require("helmet");
//const cors = require("cors");
const rateLimit = require("express-rate-limit");
const cors = require("cors"); // 🔧 追加

// 認証ミドルウェアのインポート
const { authenticateApiKey } = require("./middleware/auth");

const app = express();

// セキュリティミドルウェア
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// 🔧 CORS設定（複数オリジン対応）
app.use(cors({
  origin: [
    'https://nweb3poc.vercel.app',     // Vercel本番アプリ
    'http://localhost:8081',           // ローカル開発環境
    'http://localhost:3000',           // React/Next.js開発用
    'http://localhost:19006',          // Expo開発用
    'http://localhost:19000',          // Expo Metro用
    'http://192.168.11.23:8081',       // 実機ローカルIPアドレス
    /^https:\/\/.*\.vercel\.app$/,     // 全てのVercelサブドメイン
    /^http:\/\/localhost:\d+$/,        // 全てのlocalhost
    /^http:\/\/192\.168\.\d+\.\d+:\d+$/, // ローカルネットワーク
    /^http:\/\/10\.\d+\.\d+\.\d+:\d+$/   // ローカルネットワーク
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'x-api-key',
    'Accept',
    'Origin',
    'X-Requested-With'
  ],
  credentials: true
}));

// レート制限
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15分
    max: 100, // 最大100リクエスト
    message: {
        error: 'Too many requests',
        message: 'Please try again later'
    },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// Application Gatewayからのヘッダーを信頼
app.set("trust proxy", true);

// 🔧 デバッグ用CORS情報ログ出力（オプション）
app.use((req, res, next) => {
  console.log(`CORS Request from: ${req.headers.origin || 'unknown'}`);
  next();
});

// X-Forwarded-Protoヘッダーをチェック
// app.use((req, res, next) => {
//   if (req.header("x-forwarded-proto") !== "https") {
//     res.redirect(`https://${req.header("host")}${req.url}`);
//   } else {
//     next();
//   }
// });

// 通常のミドルウェア設定
app.use(express.json({ limit: '50mb' }));

// 一時ファイル保存先
const upload = multer({ 
    dest: "uploads/",
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB制限
    }
});
const uploadsDir = path.join(__dirname, "uploads");

// uploadsディレクトリが存在しない場合は作成
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const connectionString = process.env.CONNECTION_STRING;
const emailClient = new EmailClient(connectionString);

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

/**
 * 一時ファイルを削除する関数
 * @param {string[]} excludeFiles - 削除対象から除外するファイル名の配列
 */
function cleanupTempFiles(excludeFiles = []) {
  try {
    const files = fs.readdirSync(uploadsDir);
    files.forEach((file) => {
      if (!excludeFiles.includes(file)) {
        const filePath = path.join(uploadsDir, file);
        if (fs.statSync(filePath).isFile()) {
          fs.unlinkSync(filePath);
          console.log(`Deleted temp file: ${file}`);
        }
      }
    });
  } catch (error) {
    console.error("Error cleaning up temp files:", error.message);
  }
}

// ハッシュ値からブロックチェーンアカウントアドレスを取得する
async function getBlockchainAccountAddressByHash(hashValue) {
  try {
    const result = await pool.query(
      `SELECT blockchain_account_address FROM photos WHERE hash_value = $1`,
      [hashValue]
    );
    
    if (result.rowCount === 0) {
      return null; // 該当するレコードが見つからない場合
    }
    
    return result.rows[0].blockchain_account_address;
  } catch (error) {
    console.error('ハッシュ値による検索エラー:', error);
    throw new Error(`ハッシュ値による検索に失敗しました: ${error.message}`);
  }
}

// データベースのphotosテーブルにレコードを追加する
async function addRecord(hashValue, blockchainAccountAddress) {
  // まず、ユーザーが存在するかチェック
  const userCheck = await pool.query(
    `SELECT blockchain_account_address FROM users WHERE blockchain_account_address = $1`,
    [blockchainAccountAddress]
  );
  
  if (userCheck.rowCount === 0) {
    throw new Error(`ユーザーが見つかりません: ${blockchainAccountAddress}. 先にユーザー登録を行ってください。`);
  }

  return await pool.query(
    `INSERT INTO photos (hash_value, blockchain_account_address) VALUES ($1, $2) RETURNING *`,
    [hashValue, blockchainAccountAddress]
  );
}

/* * Boxのメールアップロード機能を使用して、zipファイルを送信する
 * @param {string} zipPath - zipファイルのパス
 * @param {string} zipFileName - zipファイル名
 * @returns {Promise<number>} - HTTPステータスコード
 */
async function sendBoxFile(zipPath) {
  const zipFileName = path.basename(zipPath);
  // zipファイルの内容を取得する
  const content = fs.readFileSync(zipPath);
  // zipファイルの内容をBase64エンコードする
  const base64Content = content.toString("base64");

  // メール内容
  const emailMessage = {
    senderAddress: process.env.SENDER_ADDRESS,
    content: {
      subject: "Test Email",
      plainText: "Hello world via email.",
      html: `
      <html>
        <body>
          <h1>Hello world via email.</h1>
        </body>
      </html>`,
    },
    attachments: [
      {
        name: zipFileName,
        attachmentType: "File",
        contentType: "application/zip",
        contentInBase64: base64Content,
      },
    ],
    recipients: {
      to: [{ address: process.env.RECIPIENT_ADDRESS }],
    },
  };

  try {
    // メールを送信する
    const response = await emailClient.beginSend(emailMessage);
    console.log("Email sent successfully");
  } catch (error) {
    console.error("Error sending email:", error);
    throw error;
  }
}

// ヘルスチェック（認証不要）
app.get("/health", async (req, res) => {
    res.status(200).send("App Server OK\n");
});

// API認証を適用する全てのAPIエンドポイント
app.use('/api', authenticateApiKey);

// CSVファイルから項目を読み込むAPI
app.post("/api/csv", upload.single("file"), async (req, res) => {
  try {
    // ファイルがアップロードされていない場合
    if (!req.file) {
      return res.status(400).json({
        error: "CSVファイルがアップロードされていません"
      });
    }

    // アップロードされたファイルのパス
    const filePath = req.file.path;
    
    // CSVファイルの内容を読み込む
    const csvContent = fs.readFileSync(filePath, 'utf8');
    
    // CSVデータを一行ずつ解析
    const lines = csvContent.split('\n');
    const data = [];
    let headers = [];
    let processedRows = 0;
    let skippedRows = 0;
    
    // 空のファイルチェック
    const nonEmptyLines = lines.filter(line => line.trim() !== '');
    if (nonEmptyLines.length === 0) {
      fs.unlinkSync(filePath);
      return res.status(400).json({
        error: "CSVファイルが空です"
      });
    }

    // 一行ずつ処理
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex].trim();
      
      // 空行をスキップ
      if (line === '') {
        continue;
      }

      // CSVの値を解析（簡易的なCSV解析）
      const values = [];
      let currentValue = '';
      let inQuotes = false;
      
      for (let i = 0; i < line.length; i++) {
        const char = line[i];
        
        if (char === '"') {
          inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
          values.push(currentValue.trim());
          currentValue = '';
        } else {
          currentValue += char;
        }
      }
      // 最後の値を追加
      values.push(currentValue.trim());

      // ヘッダー行の処理（最初の非空行）
      if (headers.length === 0) {
        headers = values.map(header => header.replace(/^"|"$/g, ''));
        console.log(`CSV Headers (行 ${lineIndex + 1}):`, headers);
        continue;
      }

      // データ行の処理
      if (values.length === headers.length) {
        const row = {};
        headers.forEach((header, index) => {
          // クォートを除去
          row[header] = values[index].replace(/^"|"$/g, '');
        });
        data.push(row);
        processedRows++;
        console.log(`処理済み行 ${lineIndex + 1}:`, row);
      } else {
        skippedRows++;
        console.warn(`行 ${lineIndex + 1} をスキップ: 列数が一致しません (期待: ${headers.length}, 実際: ${values.length})`);
        console.warn(`問題のある行: "${line}"`);
      }
    } 

    // 一時ファイルを削除
    fs.unlinkSync(filePath);

    const nftRes = [];
    for (const row of data) {
      console.log("row", row);
      try {
        // row.hashをDBでから検索し該当するブロックチェーンアカウントアドレスを取得する
        const blockchain_account_address = await getBlockchainAccountAddressByHash(row.hash);
        // 写真NFTを発行するAPIを呼び出す
        const response = await fetch(`${process.env.BLOCKCHAIN_KALEIDO_SERVER_BASE_URL}api/register-photo`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": process.env.API_KEY, // APIキーをヘッダーに追加
          },
          redirect: "manual",
          body: JSON.stringify({
            blockchain_account_address: blockchain_account_address,
            instaPhotoUrl: row.instaPhotoUrl,
            likeCount: row.likeCount,
          }),
        });
        const responseJson = await response.json();
        const tokenId = responseJson.tokenId;
        console.log("responseJson", responseJson);
        console.log("tokenId", tokenId);

        // 既存レコードを更新
        const updateResponse = await pool.query(
          `UPDATE photos SET 
              instagram_photo_url = $1,
              token_id = $2,
              likes = $3,
              blockchain_account_address = $4,
              updated_at = CURRENT_TIMESTAMP
            WHERE hash_value = $5
            RETURNING *`,
          [row.instaPhotoUrl, tokenId, row.likeCount, blockchain_account_address, row.hash]
        );
        console.log("updateResponse", updateResponse);
        nftRes.push(updateResponse.rows);

      } catch (error) {
        console.error("写真NFT発行エラー:", error);
        // エラーが発生した場合は、エラーメッセージを追加
        nftRes.push({
          error: `行 ${data.indexOf(row) + 1} のNFT発行に失敗しました: ${error.message}`,
          row: row
        });
        throw new Error(error);
      }
    }

    // 結果を返す
    res.status(200).json({
      message: "nftを発行しました",
      response: nftRes,
    });

  } catch (error) {
    console.error("写真NFT発行エラー:", error);
    
    // エラー時も一時ファイルがあれば削除
    if (req.file && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (unlinkError) {
        console.error("一時ファイル削除エラー:", unlinkError);
      }
    }
    
    res.status(500).json({
      error: "CSVファイルの読み込みに失敗しました",
      details: error.message
    });
  }
});

app.post("/api/user", async (req, res) => {
  // パラメータを取得
  const blockchainAccountAddress = req.body.blockchainAccountAddress || ""; // ブロックチェーンアカウントアドレス
  const nickname = req.body.nickname || ""; // ニックネーム
  if (!blockchainAccountAddress || !nickname) {
    return res.status(400).send("ブロックチェーンアカウントアドレスとニックネームは必須です");
  }
  /* localhost:3000/api/user/registerを呼び出す
   引数はブロックチェーンアカウントアドレスとニックネーム */
  try {
    const response = await fetch(`${process.env.BLOCKCHAIN_KALEIDO_SERVER_BASE_URL}api/users/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.API_KEY, // APIキーをヘッダーに追加
      },
      redirect: "manual",
      body: JSON.stringify({
        blockchain_account_address: blockchainAccountAddress,
        nickname: nickname,
      }),
    });
    const json = await response.json();
    console.log(json);
    if (!json.success) {
      console.error("User registration failed:", json.error);
      throw new Error(JSON.stringify({ message: json.error }));
    }

    // ユーザーをusersテーブルに挿入
    const dbResponse = await pool.query(
      `INSERT INTO users (blockchain_account_address, nickname, token_id) VALUES ($1, $2, $3) RETURNING *`,
      [blockchainAccountAddress, nickname, json.user.token_id]
    );

    console.log("dbResponse", dbResponse);

    // ユーザー登録成功時のレスポンス
    const user = json.user;
    res.status(200).send({
      message: json.message || "ユーザー登録が完了しました",
      blockchainAccountAddress: user.blockchain_account_address,
      nickname: user.nickname,
      tokenId: user.token_id
    });
  } catch (error) {
    console.error("Error calling user registration API:", error);
    return res.status(500).send("ユーザー登録APIの呼び出しに失敗しました: " + error.message);
  }
});

// "file"はhtmlのnam属性と一致させる
app.post("/api/box", upload.single("file"), async (req, res) => {
  // サーバー側でアップロードされたファイルをリネームする
  const oldFile = path.join(uploadsDir, req.file.filename);
  const newFile = path.join(uploadsDir, req.file.originalname);
  fs.renameSync(oldFile, newFile);

  // パラメータを取得
  const blockchainAccountAddress = req.body.blockchain_account_address || ""; // ブロックチェーンアカウントアドレス
  const nickname = req.body.nickname || ""; // ニックネーム
  const comment = req.body.comment || ""; // コメント

  // ブロックチェーンアカウントアドレス、ニックネーム、コメントからハッシュ値を生成する
  const hash = crypto
    .createHash("sha256")
    .update(`${blockchainAccountAddress}${nickname}${comment}`)
    .digest("hex");

  try {
    // DBに保存する
    const response = await addRecord(hash, blockchainAccountAddress);

    console.log("DB response:", response.status, response.statusText);

    // ファイル一覧を作成する
    const textFiles = [
      { name: "nickname.txt", content: nickname },
      { name: "comment.txt", content: comment },
      { name: "hash.txt", content: hash },
    ];

    // ファイル一覧をuploadsディレクトリに保存する
    textFiles.forEach((file) => {
      fs.writeFileSync(`uploads/${file.name}`, file.content, "utf8");
    });

    // zipファイル名を作成する
    const datetime = new Date();
    const zipFileName = [
      datetime.getFullYear(),
      String(datetime.getMonth() + 1).padStart(2, "0"),
      String(datetime.getDate()).padStart(2, "0"),
      String(datetime.getHours()).padStart(2, "0"),
      String(datetime.getMinutes()).padStart(2, "0"),
      String(datetime.getSeconds()).padStart(2, "0"),
      String(datetime.getMilliseconds()).padStart(3, "0"),
    ].join("");

    // zipファイルのパスを作成する
    const zipPath = path.join(uploadsDir, `${zipFileName}.zip`);
    // ファイル書き込みストリーム作成する
    const output = fs.createWriteStream(zipPath);
    // archiverを使用してzipファイルを作成する
    const archive = archiver("zip");

    // zipファイルの書き込みが完了したときの処理
    output.on("close", async () => {
      try {
        console.log("file", fs.readdirSync(uploadsDir));
        // const response = await sendBoxFile(zipPath);

        // メール送信成功後、一時ファイルをクリーンアップ
        cleanupTempFiles();

        res.status(200).send({
          message: "Zip file created and sent via email",
          zipFileName: `${path.basename(zipPath)}`,
        });
      } catch (error) {
        console.error("Error sending zip file via email:", error.message);

        // エラー時も一時ファイルをクリーンアップ
        cleanupTempFiles();

        res
          .status(500)
          .send("Failed to send zip file via email: " + error.message);
      }
    });

    // zipファイルの書き込みエラー処理
    archive.on("error", (err) => {
      console.error("Error creating zip file:", err);

      // エラー時も一時ファイルをクリーンアップ
      cleanupTempFiles();

      res.status(500).send("Failed to create zip file: " + err.message);
      throw err;
    });

    // zipファイルのストリームとarchiverを紐づける
    archive.pipe(output);

    // アップロードされたファイルをzipに追加する
    fs.readdirSync(uploadsDir).forEach((file) => {
      const filePath = path.join(uploadsDir, file);
      if (fs.statSync(filePath).isFile()) {
        if (file != `${zipFileName}.zip`) {
          archive.file(filePath, { name: file });
        }
      }
    });

    // zipファイルを作成する
    archive.finalize();
  } catch (error) {
    console.error("Error connecting to the database:", error.message);

    // データベースエラー時も一時ファイルをクリーンアップ
    cleanupTempFiles();

    res.status(500).send("Database error: " + error.message);
  }
});

const PORT = process.env.PORT || 4000;
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    
    // サーバー起動時に既存の一時ファイルをクリーンアップ
    cleanupTempFiles();
    console.log("Cleaned up temporary files on server start");
});

// graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received.');
    console.log('Closing HTTP server.');
    server.close(() => {
        console.log('HTTP server closed.');
        pool.end();
        process.exit(0);
    });
});