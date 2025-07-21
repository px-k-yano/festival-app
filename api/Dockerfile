# api/Dockerfile
FROM node:20-alpine

# セキュリティのためroot以外のユーザーを作成
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

WORKDIR /app

# 依存関係のインストール
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# アプリケーションコードのコピー
COPY . .

# uploadsディレクトリの作成と権限設定
RUN mkdir -p uploads && chown -R nodejs:nodejs /app

# 非rootユーザーに切り替え
USER nodejs

EXPOSE 4000

# ヘルスチェックの追加
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:4000/health || exit 1

CMD ["npm", "run", "dev"]