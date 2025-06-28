# ast-grep の使い方の指針(CLAUDE.md)

### 基本方針
コード分析、検索、リファクタリング作業において、テキストベースのツール（grep、sed、awk等）ではなく、**ast-grep**を優先的に使用してください。

### ast-grep使用が必須の場面

#### 1. コード検索・分析
- 関数定義の検索
- 特定のパターンの構文要素の抽出
- API使用箇所の特定
- 依存関係の分析

```bash
# 推奨: 構文的に正確な検索
ast-grep --pattern 'function $NAME($$$) { $$$ }'

# 非推奨: テキストベースの検索
grep "function.*(" *.js
```

#### 2. リファクタリング作業
- 関数名・変数名の一括変更
- API呼び出しの形式変更
- 構文パターンの統一
- 廃止予定機能の置換

```bash
# 推奨: 構文を理解した置換
ast-grep --pattern 'console.log($MSG)' --rewrite 'logger.info($MSG)'

# 非推奨: 文字列置換
sed 's/console.log/logger.info/g'
```

#### 3. コード品質チェック
- 特定のアンチパターンの検出
- セキュリティ上問題のあるコードの特定
- コーディング規約違反の検出

### 実装指針

#### パターンファイルの活用
複雑な検索・置換パターンは設定ファイルに記述してください：

```yaml
# .ast-grep/rules/deprecated-api.yml
id: replace-deprecated-api
message: Replace deprecated API call
severity: warning
language: JavaScript
rule:
  pattern: oldApi.method($$$)
fix: newApi.method($$$)
```

#### 言語サポートの確認
ast-grepは以下の言語をサポートしています：
- JavaScript/TypeScript
- Python
- Rust
- Go
- Java
- C/C++
- その他多数

言語固有の構文理解を活用して、より精密な操作を行ってください。

### 禁止事項

以下の場面でのテキストベースツール使用は避けてください：
- 構文要素（関数、クラス、変数等）を対象とした検索
- プログラムの構造を変更するリファクタリング
- コードの意味を理解する必要がある分析作業

### 例外的にテキストベースツールを使用する場面

- 設定ファイル（JSON、YAML等）の処理
- ログファイルの解析
- ドキュメント（Markdown等）の編集
- ast-grepが対応していない言語での作業

### パフォーマンス考慮事項

大規模コードベースでの作業時は：
- 適切なファイルパターンでスコープを限定
- 並列処理オプションの活用
- インクリメンタル処理の検討

### 品質保証

ast-grepによる変更後は必ず：
- 構文エラーの確認
- テストスイートの実行
- 変更箇所のコードレビュー

### 学習リソース

- [ast-grep公式ドキュメント](https://ast-grep.github.io/)
- パターンマッチング構文の理解
- 言語固有のAST構造の把握

---

**重要**: この指示に従うことで、より安全で正確なコード操作が可能になり、意図しない副作用や構文エラーを防ぐことができます。