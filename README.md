# rspamd-jev

Rspamd + Ollamaを維持したまま、TypeSafe Jevを追加評価する**シャドーモード専用**Luaプラグインです。Jevのアカウント/APIキーを取得する前に、ローカルモックで疎通・異常系・比較ログを確認できます。

**初期状態は無効・外部送信なし。受信拒否、スコア加減算、Bayes自動学習は実装していません。**

評価予定先: `192.168.1.4`。このリポジトリの作成時点ではSSH認証が通らず、サーバーのバージョン・設定は未確認、インストールも未実施です。既存Ollama連携が標準の`gpt`モジュール（`GPT_CHECK` / `GPT_SPAM` / `GPT_HAM`）であることを設置前に確認してください。

## 構成と評価範囲

```text
通常のRspamd -> 既存GPT_CHECK/Ollama -> JEV_CHECK -> 最終JEV_LOG
                    |                    |
                  既存判定             スコア0の観測だけ
```

- `rspamd/jev.lua`: 非同期HTTP、入力抽出、応答検証、確率/信頼度による観測ラベル、比較ログ。
- `rspamd/jev.conf`: 無効状態の設定例。
- `tools/mock_jev.py`: Python標準ライブラリだけで動くループバック限定モック。
- `tools/summarize.py`: Rspamdログ/JSONLから比較・遅延・費用・正解ラベル付き指標を集計。
- `tests/`: Lua境界テスト、Python HTTP/集計テスト、実Rspamdの隔離スモークテスト。

`require_gpt = true`では`GPT_CHECK`の終了を依存関係で待ち、既存GPT判定が観測されたメールだけをサンプリングします。JevへGPT判定・既存総合スコアは送信しません。比較対象は同じメールですが、プロンプト・入力抽出はOllamaと同一とは限りません。

`JEV_HAM`、`JEV_SPAM`、`JEV_PHISHING`、`JEV_UNCERTAIN`、`JEV_ERROR`は登録スコア・挿入重みともに0です。これらを既存のcomposite/force_actions/学習条件へ追加しないでください。Jevの処理時間は追加されるため、「スコアが不変」と「遅延も不変」は異なります。

## APIキーなしで確認

必要環境: Python 3.10以降、LuaJITまたはLua。Python追加パッケージは不要です。

```sh
make test
# LuaJITがなければ:
make test LUA=lua

python3 tools/mock_jev.py --outcome phishing
# 別ターミナル:
curl --fail http://127.0.0.1:18080/health
```

モックは本文を判定せず、起動時の`--outcome`を返します。`ham` / `spam` / `phishing` / `uncertain` / `429` / `500` / `529` / `malformed`が選べます。`--delay 3`でタイムアウトを再現できます。実APIキーをモックへ渡さないでください。

ネイティブのRspamdがあるLinuxでは、既存サービスの設定を触らず、一時ディレクトリ・別ポート・合成メールで確認できます。

```sh
python3 tests/smoke_rspamd.py
```

GitHub Actionsもこのスモークテストを実行します。ここではOllamaの出力シンボルを合成するため、実Ollamaとの連携・実Jevの精度を確認するものではありません。LuaテストではHTTP/UCL/Rspamd APIをダブルに置き換え、ネイティブテストで実JSON・MIME・スケジューラを補完します。

## 192.168.1.4への追加

以下は**サーバー上で管理者が実行する手順**です。SSHユーザー・インストール経路・サービス実行ユーザーを確認し、既存設定をバックアップしてください。コンテナ運用ならコンテナ内のパス/ネットワークに読み替えます。

```sh
rspamd --version
sudo rspamadm configtest
# ローカル画面で確認。APIキー等が含まれる場合があるので出力を公開しない:
sudo rspamadm configdump gpt
```

`gpt.type = "ollama"`、モデル、`GPT_CHECK`と判定シンボル、`autolearn`の設定を確認します。比較のために既存`gpt.conf`やスコアを変更する必要はありません。既存Ollamaによる自動学習が有効なら、評価中の基準が変化する点を記録してください。

このリポジトリをサーバーへ配置した後:

```sh
sudo install -d -m 0755 /etc/rspamd/plugins.d
sudo install -m 0644 rspamd/jev.lua /etc/rspamd/plugins.d/jev.lua
sudo install -m 0644 rspamd/jev.conf /etc/rspamd/local.d/jev.conf
```

同名ファイルが既にある場合は上書きせず内容を確認します。既存の`/etc/rspamd/rspamd.conf.local`へ次のブロックを**追記**します。ファイル全体を置き換えないでください。

```ucl
jev {
  .include "$LOCAL_CONFDIR/local.d/jev.conf"
}
```

標準設定の`modules.try_path`が`$LOCAL_CONFDIR/plugins.d/`を読み込むことを確認してください。独自構成で読み込まれない場合は、既存の`rspamd.local.lua`から次の1行を追加する方法もあります。**両方の方法を併用しない**でください。

```lua
dofile('/etc/rspamd/plugins.d/jev.lua')
```

### モックでサーバー側を確認

モックはRspamdと同じホスト/ネットワーク名前空間で起動します。Mac上のモックを`192.168.1.4`の`127.0.0.1`から参照することはできません。

```sh
python3 tools/mock_jev.py --outcome phishing
```

`local.d/jev.conf`を次の設定に変更します。

```ucl
enabled = true;
mode = "mock";
url = "http://127.0.0.1:18080/v1/systemone";
allow_external = false;
sample_rate = 1.0;
require_gpt = true;
```

キーの追記ではなく既存の値を編集し、重複させないでください。`require_gpt = true`ではOllamaが評価をスキップしたメールにはJevも問い合わせません。モック単体の確認に限り`false`にできますが、その場合のGPT比較は順序が保証されません。実評価では`true`に戻します。

```sh
sudo rspamadm configtest
# configtest成功時のみ。環境がreloadを提供しない場合は計画的なrestart:
sudo systemctl reload rspamd
```

個人情報を含まない合成メールを`rspamc`で検査し、従来のスコア/アクションと`JEV_*`のスコア0、ログの`JEV_EVAL`を確認します。モックの固定判定を実際の検出性能と解釈しないでください。

確認後は`enabled = false`に戻して再読込すれば、アカウント発行までHTTPリクエストは一切行われません。

### APIキー発行後

本番APIへの送信を許可できる**評価用受信ドメイン**を選びます。送信内容・米国での処理・保持期間/ZDR・契約条件を確認してください。学習に使われないことは、保存されないことと同じではありません。

APIキーはGitやコマンドラインに書かず、サーバー上で`sudoedit`等を使って`/etc/rspamd/jev-api-key`へ1行で保存します。所有者root、Rspamd実行グループに読み取りだけを許可（例: `0640 root:_rspamd`、実環境のグループに読み替え）してください。

```ucl
enabled = true;
mode = "live";
url = "https://api.typesafe.ai/v1/systemone";
model = "jev-1.13.0";
allow_external = true;
api_key_file = "/etc/rspamd/jev-api-key";
recipient_domains = ["evaluation.example.com"];
require_gpt = true;
sample_rate = 0.05;
```

`evaluation.example.com`は例です。自分が管理し、外部送信を承認したドメインへ変更します。全SMTP受信者のドメインが完全一致する場合だけ送信します。サブドメインの暗黙許可・ワイルドカードはありません。受信者不明・認証済み送信メールはスキップします。

`configtest`成功後に再読込します。キーは設定ロード時に読み込むため、ローテーション時にも再読込が必要です。`jev-latest`等の可変エイリアスは拒否し、モデルを固定します。指定バージョンがアカウントで利用できるかも確認してください。

## ログと比較

既存のRspamdログへ`JEV_EVAL { ... }`を1スキャンにつき1行記録します（Rspamd自体がチェックを省略したタスクを除く）。

記録するもの: メッセージdigest、時刻、mock/live、モデル/質問版、閾値、サンプリング率、GPT判定/確率/設定モデル、最終Rspamdスコア/アクション、Jev確率/信頼度/観測ラベル、API時間/使用量、スキップ/エラー理由。

**プラグインの評価レコードには本文・件名・アドレス・URL・APIキー・APIの生エラー応答を記録しません。** Rspamd既存ログのプレフィックス/別のログ行はその限りではありません。digestを含む評価ログもメールと照合可能な情報としてアクセスを制限してください。

```sh
python3 tools/summarize.py /path/to/rspamd.log --mode mock
python3 tools/summarize.py /path/to/rspamd.log --mode live
# journaldの場合:
journalctl -u rspamd -o cat | python3 tools/summarize.py - --mode live
```

JSON出力の主な項目:

| 項目 | 意味 |
|---|---|
| `statuses` / `skip_error_reasons` | 成功・失敗・評価対象外の数と理由 |
| `agreement` / `baseline_vs_jev` | GPTシンボルとJevの二値判定一致。正解率ではない |
| `http_latency_ms` | Jev HTTP要求のp50/p95/p99。Ollama時間や総スキャン時間ではない |
| `estimated_success_cost_usd` | 成功応答の入力トークンからの概算。失敗分等を含む請求額ではない |
| `current_pipeline_actions` | 現行Rspamd+Ollamaの最終アクション |
| `paired_labeled_*` | 同じ判定可能・正解ラベル付き集合でのJev対GPTシンボル比較 |
| `pipeline_paired_labeled_*` | 同じ集合でのJev対現行Rspamd+Ollama最終アクション比較 |

正解ラベルはOllamaから作らず、人手確認したCSVを指定します。ヘッダは`message_digest,label`、ラベルは`ham` / `spam` / `phishing`です。CSV/メール/評価ログは`.gitignore`で除外しています。

```sh
python3 tools/summarize.py /path/to/rspamd.log --labels /private/path/labels.csv
```

二値評価ではspamとphishingを迷惑メール側へまとめます。Jevの`uncertain`、GPTの未観測/競合/不確実は対応するペア精度計算から除外し、coverageを別に出します。最終アクションは`no action`を正常、`reject`/`add header`/`rewrite subject`/`quarantine`/`discard`を迷惑メール側として扱い、`greylist`/`soft reject`などは保留です。サイト独自の隔離運用等がこの解釈に合うか確認してください。

同じdigestの再スキャンは品質指標では最新の成功結果だけを使い、API費用/遅延には全スキャンを含めます。モデル・質問版・閾値・サンプリング率・GPTモデルの混在はエラーになるため、期間/設定別にログを分割してください。正常メールの誤検知率と見逃し改善、保留率を重視し、未知の精度を0や100%で補いません。

## 安全制約・現在の限界

- 外部送信する情報: 件名、From/Reply-To、最大4つの非添付テキストパート（HTMLはタグ除去）、URL/表示文字/ホスト、添付名/MIME型、固定リストの認証検証シンボル。宛先一覧、添付内容、SMTP認証情報は送りません。
- URLのクエリや本文には個人情報/トークンが残り得ます。**自動匿名化はしていません。** 機密メールの外部送信を許可しないでください。メール中のリンクへはアクセスしません。
- 最大本文6,000 **UTF-8バイト**、本文を含む送信JSON最大24,576バイト。バイト境界で文字を壊さず切り詰め、切り詰めを記録します。トークン上限の厳密な計算ではありません。
- 画像/OCR・添付解析は対象外。本文の切り詰め、複数MIME表現、欠けた購読履歴による誤判定は別途評価が必要です。
- タイムアウト1.5秒、再試行なし、失敗時は既存判定を維持し、60秒の休止。401/429/529、不正JSON/不正確率、モデル不一致、HTTPの予約失敗も明示的に記録します。
- レート上限1要求/秒、同時2要求、休止状態は**ワーカーごと**です。全体共有のRedis制限ではありません。ワーカー数×1要求/秒＋同アカウントの他用途がAPI制限を超えないよう設定してください。大規模運用・バースト制御は未対応です。
- キャッシュは意図的に未実装。評価時のキャッシュ混入・誤ったキーによる判定再利用を避ける代わりに、再スキャンもAPI使用量が発生します。
- GPTがスキップした正常/スパムや、Rspamdが早期終了したメールは既定の比較対象外です。これだけで全受信メールの性能を主張できません。
- Jevの信頼度は誤検知率の保証ではありません。プロンプトインジェクションへの指示だけで安全を保証せず、人手の正解データと悪意ある本文で検証してください。
- 日本語の性能、実アカウントの遅延/制限、対象サーバーでの互換性は実地確認が必要です。現時点で自動拒否へ移行する機能は提供していません。

## 停止・削除

まず`local.d/jev.conf`の`enabled = false`にして`configtest`後に再読込します。削除時は追加した`jev`ブロック/任意の`dofile`だけを除去してから、専用プラグイン・設定・キーを個別に削除します。既存`gpt`設定や`rspamd.conf.local`全体は削除しません。

## 参考

- [TypeSafe API](https://docs.typesafe.ai/api)
- [モデル・レート制限・言語対応](https://docs.typesafe.ai/models)
- [既知の弱点](https://docs.typesafe.ai/model-jaggedness/jev-1.13)
- [Rspamd GPTプラグイン](https://docs.rspamd.com/modules/gpt/)
- [Rspamd Lua HTTP](https://docs.rspamd.com/lua/rspamd_http/)
