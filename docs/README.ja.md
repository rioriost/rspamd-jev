# rspamd-jev 導入ガイド

[English / 設定・レポート項目の完全なリファレンス](../README.md)

TypeSafe Jevをメール判定の追加評価に使う、**特定ホストに依存しないRspamd用プラグイン**です。通常のRspamdだけで動き、Ollama・OpenAI・`gpt`モジュールは任意の比較対象です。

現段階は**実験的なシャドー評価専用**です。初期状態は無効、外部送信なし。Jevの結果はスコア0で記録し、配送アクションやBayes学習フラグを変更しません。実メールでの精度・遅延の評価前に、自動受信拒否へ使わないでください。

## 事前準備

| 用途 | 必要なもの |
|---|---|
| プラグインの実行 | 動作中のRspamd、設定の管理権限、ログへのアクセス。LuaはRspamd内蔵のものを使用 |
| 互換性確認 | CIでの実機相当確認はUbuntu 24.04のRspamd 3.8.1。最古の確認済みバージョンであり、古い版の利用を推奨するものではありません。利用するサポート対象版で確認してください |
| Jevの実API | TypeSafeの利用可能なアカウント・APIキー・固定モデル、DNS、`api.typesafe.ai:443`へのHTTPS通信、信頼できるCA証明書 |
| 外部送信の承認 | 対象メール・受信ドメインの承認、処理地域・保持期間・契約の確認 |
| モック・集計 | Python 3.10以降。追加パッケージは不要 |
| 開発用テスト | Python、make、LuaJITまたはLua。ネイティブテストにはLinux/Unix上のRspamdとrspamadm |
| GPTとの比較（任意） | 標準の`GPT_CHECK` / `GPT_*`シンボルを出力する、設定済みのRspamd `gpt`モジュール |

Python・単独のLuaインタープリターは、プラグインを動かすだけなら不要です。GPU、NPU、Redis、ローカルAIモデルも必須ではありません。Jev本体はTypeSafe側で推論します。

Rspamd本体・MTA・Ollamaの導入はこのプロジェクトの対象外です。既存のフィルタリングを動作させてから追加してください。APIがwaitlist中なら、モックでの確認まで進めて無効状態で待機できます。

## インストール

### 1. 環境の確認

以下はRspamdを実行するホスト上で行います。

```sh
git clone https://github.com/rioriost/rspamd-jev.git
cd rspamd-jev
rspamd --version
sudo rspamadm configtest
sudo rspamadm configdump modules
```

実際の設定ディレクトリ、サービス実行ユーザー/グループ、ワーカー数、再読込方法、MTA/Rspamdのタイムアウトを確認し、既存設定をリポジトリ外へバックアップします。

以下の`/etc/rspamd`は一例です。`/usr/local/etc/rspamd`やコンテナ独自の配置を使っている場合は読み替えてください。推奨の読込方式は`modules.try_path`によるローカル`plugins.d`の読込です。

### 2. 無効状態で配置

初回導入専用のコマンドです。同名ファイルがあれば中断し、後述の更新手順を使います。

```sh
CONFDIR=/etc/rspamd
sudo test ! -e "$CONFDIR/plugins.d/jev.lua" &&
sudo test ! -e "$CONFDIR/local.d/jev.conf" &&
sudo install -d -m 0755 "$CONFDIR/plugins.d" "$CONFDIR/local.d" &&
sudo install -m 0644 rspamd/jev.lua "$CONFDIR/plugins.d/jev.lua" &&
sudo install -m 0644 rspamd/jev.conf "$CONFDIR/local.d/jev.conf"
```

既存の`rspamd.conf.local`へ次のブロックを一度だけ**追記**します。ファイル全体やパッケージ標準設定を置き換えないでください。

```ucl
jev {
  .include "$LOCAL_CONFDIR/local.d/jev.conf"
}
```

`$LOCAL_CONFDIR`はRspamdの設定変数です。サンプル`jev.conf`はブロック内部だけを含むので、さらに`jev {}`で囲みません。初期状態は`enabled = false`です。

```sh
sudo rspamadm configtest
# 成功時のみ。サービス管理方法に応じて読み替え:
sudo systemctl reload rspamd
```

reload非対応なら計画的にrestartします。構文が正しくてもプラグインが読まれているとは限らないため、次のスキャンでシンボルとログまで確認します。

### 3. モックで確認

モックをRspamdと**同じネットワーク名前空間**で、別ターミナルから起動します。

```sh
python3 tools/mock_jev.py --outcome phishing
curl --fail http://127.0.0.1:18080/health
```

`local.d/jev.conf`の既存値を編集します。重複キーを追記しないでください。

```ucl
enabled = true;
mode = "mock";
url = "http://127.0.0.1:18080/v1/systemone";
allow_external = false;
require_gpt = false;
sample_rate = 1.0;
```

`configtest`、再読込の後、個人情報を含まない合成メールをスキャンします。以下はnormal workerが`127.0.0.1:11333`の場合です。milterポートではなく、実際のスキャナの接続先へ変更します。

```sh
printf 'From: sender@example.test\nTo: recipient@example.test\nSubject: Synthetic Jev test\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nThis is synthetic mail for plugin verification.\n' |
  rspamc -h 127.0.0.1:11333
```

スコア0の`JEV_PHISHING`、`"mode":"mock"`の`JEV_EVAL`ログ、無効時と同じ最終スコア/アクションを確認します。既存の設定でスキャン自体が省略される場合は、本番設定を緩めず`make smoke`の隔離環境で確認してください。

モックはメールを分類せず、指定した固定結果を返します。`--outcome`には`ham`、`spam`、`phishing`、`uncertain`、`429`、`500`、`529`、`malformed`を指定できます。`--delay 3`でタイムアウトを再現できます。実APIキーは渡しません。

確認後は`enabled = false`で再読込し、モックをCtrl-Cで停止します。APIキー待ちの期間はこの状態にしてください。

### 4. APIキー発行後

本文、件名、From/Reply-To、URL等がTypeSafeへ送信されます。**自動匿名化は行いません。** 対象データの承認と[保持・契約条件](https://docs.typesafe.ai/legal)を確認してください。「学習不使用」は「保存しない」と同じではありません。

キーはリポジトリ外のファイルに1行で保存し、Rspamdが読み取れる所有者/権限にします。英語READMEに安全なファイル作成例があります。`root:_rspamd`、`0640`は一例であり、実際のサービス実行ユーザー/グループに合わせます。`sudoedit`等を使い、キーをコマンド引数、Git、issueに書かないでください。`Bearer`や引用符はファイルに入れません。

```ucl
enabled = true;
mode = "live";
url = "https://api.typesafe.ai/v1/systemone";
model = "jev-1.13.0";
allow_external = true;
api_key_file = "/etc/rspamd/jev-api-key";
recipient_domains = ["evaluation.example.com"];
require_gpt = false;
sample_rate = 0.05;
```

キーの絶対パスと受信ドメインを自環境に合わせます。全SMTP受信者のドメインが完全一致するメールのみ対象です。受信者不明、対象外の同報先、認証済み送信メールはスキップします。MTA/スキャナからSMTP受信者が渡されることも確認してください。

固定モデルがアカウントで利用できるか、キーをRspamdユーザーが読めるかを確認して、`configtest`後に再読込します。キーのローテーションにも再読込が必要です。

## 動作と任意のGPT比較

既定の`require_gpt = false`では、通常のRspamdだけでJevを評価します。GPTがあれば、全postfilter終了後に比較用の判定も記録します。GPTの判定がないことを「正常」とは解釈しません。

`require_gpt = true`は、別途動作確認済みの`gpt`モジュールとの**比較対象限定**用です。`GPT_CHECK`の終了を待ち、GPT判定がないメールを除外します。この設定自体がGPTを導入・有効化することはありません。Ollamaでも他の対応プロバイダーでも利用できます。

既存のモデル・プロンプト・スコア・自動学習設定は変更しません。GPT判定と既存の総合スコアはJevへ送りません。ただし、モデル間で入力抽出や質問が同一とは限らず、GPTによる対象選別や既存の自動学習が比較に影響することには注意してください。

JevはシャドーモードでもAPIの応答を待つため、メール単位の処理時間は増えます。非同期通信は追加遅延がゼロという意味ではありません。

## 集計と移行

```sh
python3 tools/summarize.py /path/to/rspamd.log --mode mock
python3 tools/summarize.py /path/to/rspamd.log --mode live
python3 tools/summarize.py /path/to/rspamd.log --labels /private/path/labels.csv
```

人手の正解CSVは`message_digest,label`、ラベルは`ham` / `spam` / `phishing`です。`agreement`は任意のGPTとの一致率であり、正解率ではありません。GPTなしでも`pipeline_paired_labeled_rspamd`と`pipeline_paired_labeled_jev`で現行Rspamd対Jevを比較できます。不確実・未観測は該当の精度計算から除外し、coverageを別に記録します。

ログには本文・件名・アドレス・URL・キーを含めませんが、Rspamd既存ログの別の行やプレフィックスはその限りではありません。digest、ログ、ラベルも保護対象です。設定が異なる実験のログは混ぜず、正常メールの誤検知率・見逃し改善・保留率を優先して評価します。

**初期版からの更新時の注意:**

- `require_gpt`の既定値を`true`から`false`へ変更しました。以前の比較範囲を維持する場合は、更新前に`true`を明示してください。未指定のまま更新するとAPI送信対象が広がる可能性があります。
- 既存`jev.conf`をサンプルで上書きしません。キーの配置も自環境の設定を維持します。
- 新ログには`require_gpt`が含まれます。旧ログは単独で読み込めますが、新旧の対象選別条件を混在させないでください。
- 集計の`pipeline_paired_labeled_rspamd_ollama`は互換用の非推奨別名として残しています。新しい利用者はプロバイダー非依存の`pipeline_paired_labeled_rspamd`を使ってください。

## 制約・設定・運用

全設定の既定値と意味は[英語READMEの設定表](../README.md#configuration-reference)を参照してください。

既定の本文上限は6,000 UTF-8バイト、送信JSON上限は24,576バイト。最大4つの非添付テキスト、URL、添付名/型などを使い、画像/OCR・添付内容は解析しません。URLへアクセスせず、切り詰めを記録します。

タイムアウト1.5秒、再試行なし、エラー後の休止60秒。要求開始1件/秒、同時2件は**ワーカーごとの制限**であり、全体共有ではありません。ワーカー数・他のAPI利用を含めてクォータ内に収めてください。キャッシュがないため再スキャンにも費用が発生し得ます。モデルの信頼度は誤検知率や攻撃耐性の保証ではありません。

独自のLua読込方式では、auto-load対象外の場所へ配置し、既存`rspamd.local.lua`から1回だけ`dofile`します。`plugins.d`の自動読込と併用しません。コンテナでは設定/プラグインを永続化し、キーを読み取り専用でマウントします。モック用のloopbackはコンテナごとに別物です。

更新時はプラグインと設定をバックアップし、プラグインだけを更新、必要な設定差分を手動反映して`configtest`・再読込・合成メール確認を行います。失敗時はバックアップへ戻します。

停止は`enabled = false`にして検証後に再読込。削除時は追加したinclude/任意の`dofile`と専用ファイルだけを除去し、既存Rspamd/GPT設定全体を削除しません。

```sh
make test
make test LUA=lua
make smoke   # Linux: 既存サービスを変更しない隔離Rspamdテスト
```

CIではサンプル設定と`plugins.d`相当の読込を使い、無効状態、GPTなし、明示的なGPT比較、遅れて完了する任意のGPT判定を確認します。GPT出力とメールは合成データであり、実Jevの精度評価とは異なります。

## 一般配布に向けて

現時点で配布ライセンスは未選定です。Public設定だけでは第三者による再利用・再配布の許諾にはならないため、一般利用を推奨する前にライセンスの選定が必要です。
