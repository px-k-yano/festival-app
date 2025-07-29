CREATE TABLE users (
  blockchain_account_address VARCHAR(50) PRIMARY KEY,
  nickname VARCHAR(50) NOT NULL,
  token_id VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE photos (
  id SERIAL PRIMARY KEY,
  hash_value VARCHAR(64) NOT NULL DEFAULT '',
  instagram_photo_url VARCHAR(255) NOT NULL DEFAULT '',
  upload_status VARCHAR(20) NOT NULL DEFAULT 'Boxアップロード待ち',
  token_id VARCHAR(255) NOT NULL DEFAULT '',
  likes INTEGER NOT NULL DEFAULT 0,
  blockchain_account_address VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (blockchain_account_address) REFERENCES users(blockchain_account_address)
);