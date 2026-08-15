# ドキュメント索引

## 最初に読む

| 目的 | 文書 |
|---|---|
| 最短でセットアップして起動する | [QUICKSTART.md](QUICKSTART.md) |
| 症状から解決方法を探す | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| アプリが満たす要件を確認する | [REQUIREMENTS.md](REQUIREMENTS.md) |
| 現在できないこと・前提条件を確認する | [CONSTRAINTS.md](CONSTRAINTS.md) |
| 全体構成とデータフローを理解する | [DESIGN.md](DESIGN.md) |

## 設計資料

| 文書 | 主題 |
|---|---|
| [DESIGN.md](DESIGN.md) | システム全体、責務分割、データフロー、キャッシュ、ランキング方針 |
| [FRONTEND.md](FRONTEND.md) | Streamlitフロントエンドの構造、状態管理、バックエンド境界 |
| [BACKEND.md](BACKEND.md) | 実行パイプライン、外部API、設定、正規化、採点、例外 |
| [UI.md](UI.md) | 画面要素、操作、表示状態、エラー表示、改善基準 |
| [DB-SCHEMA.md](DB-SCHEMA.md) | RDB未採用の現状とJSONキャッシュの論理スキーマ |
| [SECURITY.md](SECURITY.md) | シークレット、外部通信、ログ、キャッシュ、信頼境界 |

## 作業管理

| 文書 | 使う場面 |
|---|---|
| [PLANS.md](PLANS.md) | 長時間・複雑タスクのExecution Planを作成・更新するとき |
| [TASKS.md](TASKS.md) | 複数工程を持つ大規模タスクを管理するとき |
| [TODO.md](TODO.md) | 単独で完了できる小規模タスクを管理するとき |
| [TECH-DEBT-TRACKER.md](TECH-DEBT-TRACKER.md) | 実装済みだが将来の保守性や運用性に負債がある項目を追跡するとき |
| [ISSUES.md](ISSUES.md) | 再現済みの不具合、制限、調査中の問題を追跡するとき |
| [WORKLOG.md](WORKLOG.md) | 実施した変更と検証結果を時系列で残すとき |
| [MEMORY.md](MEMORY.md) | 頻繁には変わらない長期的な判断・知識を残すとき |

## 補助資料

| 文書 | 内容 |
|---|---|
| [REFERENCES.md](REFERENCES.md) | リポジトリ内の一次資料と外部公式資料 |
| [AI_GUIDE.md](AI_GUIDE.md) | 将来のAI向け指示用。現在は意図的に空 |

## 文書の役割分担

- 現在の実装事実は `src/`、`tests/`、`pyproject.toml`、`.env.example` を正とする。
- `REQUIREMENTS.md` は満たすべき振る舞い、`CONSTRAINTS.md` は前提と限界を記録する。
- `DESIGN.md` は採用した設計を記録し、未実装の候補は実装済みと混同しない。
- `ISSUES.md` は観測された問題、`TECH-DEBT-TRACKER.md` は既知の構造的負債を扱う。
- `TODO.md` は小規模作業、`TASKS.md` は複数工程の成果、`PLANS.md` は複雑タスクの遂行方法を扱う。
- `MEMORY.md` は安定した知識だけを残し、日々の進捗は `WORKLOG.md` へ記録する。

## 旧資料の統合先

2026-08-15の再編で、旧 `docs/` の内容を次へ分配統合した。旧ファイルは重複と矛盾を避けるため廃止する。

| 旧ファイル | 主な統合先 |
|---|---|
| `CACHE_DESIGN.md` | [DESIGN.md](DESIGN.md)、[DB-SCHEMA.md](DB-SCHEMA.md)、[SECURITY.md](SECURITY.md)、[TECH-DEBT-TRACKER.md](TECH-DEBT-TRACKER.md) |
| `DATA_MODEL_SPEC.md` | [BACKEND.md](BACKEND.md)、[DB-SCHEMA.md](DB-SCHEMA.md)、[REQUIREMENTS.md](REQUIREMENTS.md) |
| `ENVIRONMENT_VARIABLES.md` | [BACKEND.md](BACKEND.md)、[QUICKSTART.md](QUICKSTART.md)、[CONSTRAINTS.md](CONSTRAINTS.md)、[SECURITY.md](SECURITY.md) |
| `EXTERNAL_API_SPEC.md` | [BACKEND.md](BACKEND.md)、[SECURITY.md](SECURITY.md)、[TROUBLESHOOTING.md](TROUBLESHOOTING.md)、[REFERENCES.md](REFERENCES.md) |
| `PRODUCTION_DESIGN_GUIDE.md` | [DESIGN.md](DESIGN.md)、[SECURITY.md](SECURITY.md)、[TECH-DEBT-TRACKER.md](TECH-DEBT-TRACKER.md)、[TASKS.md](TASKS.md) |
| `README_dev.md` | [DESIGN.md](DESIGN.md)、[BACKEND.md](BACKEND.md)、[FRONTEND.md](FRONTEND.md)、[QUICKSTART.md](QUICKSTART.md) |

## 変更時の更新先

| 変更内容 | 同時に確認する文書 |
|---|---|
| 環境変数・既定値 | `BACKEND.md`、`QUICKSTART.md`、`CONSTRAINTS.md`、`.env.example` |
| Pydanticモデル | `BACKEND.md`、`DB-SCHEMA.md`、`REQUIREMENTS.md` |
| UIの入力・表示・状態 | `FRONTEND.md`、`UI.md`、`QUICKSTART.md` |
| 外部API・再試行・URL制約 | `BACKEND.md`、`SECURITY.md`、`TROUBLESHOOTING.md` |
| キャッシュキー・TTL・保存形式 | `DESIGN.md`、`DB-SCHEMA.md`、`SECURITY.md` |
| 既知の制限または不具合 | `CONSTRAINTS.md`、`ISSUES.md`、必要に応じて `TECH-DEBT-TRACKER.md` |
| 大規模な将来作業 | `TASKS.md`。着手時は `PLANS.md` に従ってExecution Planを作る |

## 検証

文書変更では少なくとも次を確認する。

```sh
git diff --check
```

コードの仕様を変更した場合は、文書確認に加えて次も実行する。

```sh
uv run ruff check .
uv run ruff format --check .
uv run pytest
```
