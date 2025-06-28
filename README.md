# TLS対応HTTPサーバーライブラリ

libuv、OpenSSL、llhttpを組み合わせた高性能なHTTP/HTTPSサーバーライブラリです。  
[httpserver.h](https://github.com/jeremycw/httpserver.h)との互換APIを提供しつつ、TLSサポートと柔軟な設定オプションを追加しています。

## 特徴

- 🚀 **高性能**: libuv非同期I/O + llhttp高速パーサー
- 🔒 **TLS対応**: 平文HTTP、HTTPS自己署名証明書、独自証明書サポート
- 📁 **mkcert対応**: ローカル開発用証明書の簡単利用
- 🔄 **API互換**: 既存のhttpserver.hコードがそのまま動作
- ⚙️ **統合API**: 設定構造体ベースの使いやすいAPI

## 必要な依存関係

- **libuv** - 非同期I/Oライブラリ
- **OpenSSL** - TLS/SSL暗号化
- **llhttp** - HTTPパーサー（同梱）

### Ubuntu/Debianでのインストール
```bash
sudo apt-get update
sudo apt-get install libuv1-dev libssl-dev
```

### macOSでのインストール（Homebrew）
```bash
brew install libuv openssl
```

## ビルド

```bash
make                    # ライブラリとテストプログラムをビルド
make libhttpserver.a    # ライブラリのみ
make test_unified       # 統合APIテストプログラム
```

## 使用方法

### 基本的な使用方法

```c
#include "httpserver.h"

void handle_request(struct http_request_s* request) {
    // レスポンスを作成
    struct http_response_s* response = http_response_init();
    http_response_status(response, 200);
    http_response_header(response, "Content-Type", "text/plain");
    http_response_body(response, "Hello, World!", 13);
    
    // レスポンスを送信
    http_respond(request, response);
    http_response_destroy(response);
}

int main() {
    // HTTPサーバーを作成
    http_server_config_t config = http_server_config_http(8080, handle_request);
    http_server_t* server = http_server_create(&config);
    
    // サーバーを開始
    http_server_listen(server);
    http_server_destroy(server);
    return 0;
}
```

### 統合API（推奨）

#### 1. 平文HTTPサーバー
```c
// ヘルパー関数を使用
http_server_config_t config = http_server_config_http(8080, handle_request);
http_server_t* server = http_server_create(&config);

// または直接設定
http_server_config_t config = {
    .port = 8080,
    .handler = handle_request,
    .tls_enabled = 0
};
```

#### 2. HTTPS（自己署名証明書）
```c
http_server_config_t config = http_server_config_default(8443, handle_request);
http_server_t* server = http_server_create(&config);
```

#### 3. HTTPS（独自証明書）
```c
http_server_config_t config = http_server_config_https(
    8443, handle_request, "server.pem", "server-key.pem");
http_server_t* server = http_server_create(&config);
```

#### 4. mkcert証明書を使用
```bash
# 証明書を生成
mkcert localhost 127.0.0.1 ::1
```

```c
http_server_config_t config = http_server_config_https(
    8443, handle_request, "localhost+2.pem", "localhost+2-key.pem");
http_server_t* server = http_server_create(&config);
```


## API リファレンス

### 設定構造体
```c
typedef struct {
    int port;                      // ポート番号
    http_request_handler_t handler; // リクエストハンドラー
    int tls_enabled;               // 0=HTTP, 1=HTTPS
    const char* cert_file;         // 証明書ファイル（NULL=自己署名）
    const char* key_file;          // 秘密鍵ファイル（NULL=自己署名）
} http_server_config_t;
```

### メイン関数
```c
// サーバー管理
http_server_t* http_server_create(const http_server_config_t* config);
int http_server_listen(http_server_t* server);
void http_server_destroy(http_server_t* server);

// 設定ヘルパー
http_server_config_t http_server_config_http(int port, handler);
http_server_config_t http_server_config_default(int port, handler);
http_server_config_t http_server_config_https(int port, handler, cert, key);
```

### リクエスト処理
```c
// リクエスト情報取得
const char* http_request_method(http_request_t* request);
const char* http_request_target(http_request_t* request);
const char* http_request_header(http_request_t* request, const char* name);
const char* http_request_body(http_request_t* request);
size_t http_request_body_length(http_request_t* request);
```

### レスポンス作成
```c
// レスポンス作成
http_response_t* http_response_init(void);
void http_response_status(http_response_t* response, int status);
void http_response_header(http_response_t* response, const char* name, const char* value);
void http_response_body(http_response_t* response, const char* body, size_t length);
int http_respond(http_request_t* request, http_response_t* response);
void http_response_destroy(http_response_t* response);
```

## テストプログラム

### 統合APIテスト
```bash
# HTTP サーバー（ポート8080）
./test_unified http
curl http://localhost:8080

# HTTPS 自己署名証明書（ポート8443）
./test_unified https
curl -k https://localhost:8443

# HTTPS mkcert証明書（ポート8443）
mkcert localhost 127.0.0.1 ::1
./test_unified mkcert
curl https://localhost:8443
```


## プロジェクト構造

```
├── src/
│   ├── httpserver.h    # メインヘッダーファイル
│   ├── httpserver.c    # メイン実装
│   ├── llhttp.h        # llhttpパーサーヘッダー
│   ├── llhttp.c        # llhttpパーサー実装
│   ├── api.c           # llhttp API実装
│   └── http.c          # llhttp HTTP処理
├── tests/
│   └── test_unified.c  # 統合APIテスト
├── Makefile            # ビルド設定
└── README.md           # このファイル
```

## ビルドオプション

```bash
make                    # 全てビルド
make debug             # デバッグビルド
make clean             # クリーンアップ
make check-deps        # 依存関係チェック
make test              # テスト実行
make install           # システムインストール
make uninstall         # アンインストール
```

## パフォーマンス

- **llhttp**: Node.jsで使用される高速HTTPパーサー
- **libuv**: 非同期I/Oによる高い並行性
- **OpenSSL**: 最適化されたTLS実装
- **メモリ効率**: 接続ごとの最小限のメモリ使用

## セキュリティ

- TLS 1.2+ のみサポート（SSL/TLS v3は無効）
- 自己署名証明書の自動生成
- mkcert対応でローカル開発時の証明書警告なし
- メモリ安全性を考慮した実装

## トラブルシューティング

### 依存関係エラー
```bash
# 依存関係をチェック
make check-deps

# Ubuntu/Debian
sudo apt-get install libuv1-dev libssl-dev

# macOS
brew install libuv openssl
```

### ポート使用中エラー
```bash
# ポート使用状況を確認
sudo netstat -tlnp | grep :8080
sudo netstat -tlnp | grep :8443

# プロセスを終了
sudo pkill test_server
```

### TLS証明書エラー
```bash
# mkcert証明書を再生成
mkcert -uninstall
mkcert -install
mkcert localhost 127.0.0.1 ::1
```

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。

## 貢献

プルリクエストやIssueは歓迎します。バグ報告や機能要望がありましたら、GitHubのIssueにご投稿ください。

## 関連プロジェクト

- [httpserver.h](https://github.com/jeremycw/httpserver.h) - 元となったHTTPサーバーライブラリ
- [libuv](https://github.com/libuv/libuv) - 非同期I/Oライブラリ
- [llhttp](https://github.com/nodejs/llhttp) - 高速HTTPパーサー
- [mkcert](https://github.com/FiloSottile/mkcert) - ローカル開発用証明書ツール