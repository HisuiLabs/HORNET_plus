# HORNETベースOnion Routingによるセキュア・マルチパスルーティング

## 技術仕様書 バージョン1.0

---

## 目次

1. [はじめに](#1-はじめに)
   1. [目的](#11-目的)
   2. [スコープ](#12-スコープ)
   3. [定義と略語](#13-定義と略語)
   
2. [システム概要](#2-システム概要)
   1. [アーキテクチャ](#21-アーキテクチャ)
   2. [コンポーネント](#22-コンポーネント)
   3. [通信フロー](#23-通信フロー)

3. [プロトコル仕様](#3-プロトコル仕様)
   1. [パケットフォーマット](#31-パケットフォーマット)
   2. [セッション確立（ハンドシェイク）](#32-セッション確立ハンドシェイク)
   3. [暗号化と復号化](#33-暗号化と復号化)
   4. [マルチパス経路選択](#34-マルチパス経路選択)
   5. [動的経路再計算](#35-動的経路再計算)
   6. [SRv6連携](#36-srv6連携)
   
4. [セキュリティ仕様](#4-セキュリティ仕様)
   1. [TEE統合](#41-tee統合)
   2. [鍵管理](#42-鍵管理)
   3. [認証メカニズム](#43-認証メカニズム)
   4. [脅威モデルと対策](#44-脅威モデルと対策)
   
5. [性能最適化](#5-性能最適化)
   1. [並列処理](#51-並列処理)
   2. [ハードウェアアクセラレーション](#52-ハードウェアアクセラレーション)
   3. [バッファリング戦略](#53-バッファリング戦略)
   
6. [実装ガイドライン](#6-実装ガイドライン)
   1. [開発環境](#61-開発環境)
   2. [インターフェース定義](#62-インターフェース定義)
   3. [エラー処理](#63-エラー処理)
   
7. [テストと評価](#7-テストと評価)
   1. [テスト方法論](#71-テスト方法論)
   2. [性能評価基準](#72-性能評価基準)
   3. [セキュリティ検証](#73-セキュリティ検証)
   
8. [付録](#8-付録)
   1. [参考文献](#81-参考文献)
   2. [変更履歴](#82-変更履歴)

---

## 1. はじめに

### 1.1 目的

本仕様書は、従来の高速Onion RoutingプロトコルであるHORNETを拡張し、TEE（Trusted Execution Environment）、マルチパスルーティング、およびハードウェアアクセラレーションを統合した新しい匿名通信プロトコルの設計と実装について定義する。本プロトコルは、高速かつ高セキュアな匿名通信を実現し、ネットワーク障害に対する耐性を向上させることを目的としている。

### 1.2 スコープ

本仕様書は以下の範囲をカバーする：

- パケットフォーマットと通信プロトコルの定義
- セッション確立（ハンドシェイク）手順
- Onion Routingの暗号化・復号プロセス
- 動的経路再計算アルゴリズム
- SRv6との連携方式
- TEEとの統合手法
- ハードウェアアクセラレーションの利用方法
- セキュリティ対策とリスク軽減手法
- 性能最適化とテスト方法

### 1.3 定義と略語

- **HORNET**: High-speed Onion Routing at the Network Edge
- **TEE**: Trusted Execution Environment（信頼実行環境）
- **SRv6**: Segment Routing over IPv6
- **SGX**: Software Guard Extensions（Intelが開発したTEE技術）
- **SID**: Segment Identifier（SRv6のセグメント識別子）
- **AS**: Autonomous System（自律システム）
- **MAC**: Message Authentication Code（メッセージ認証コード）
- **PKI**: Public Key Infrastructure（公開鍵基盤）
- **PSK**: Pre-Shared Key（事前共有鍵）
- **HMAC**: Hash-based Message Authentication Code（ハッシュベースのメッセージ認証コード）

---

## 2. システム概要

### 2.1 アーキテクチャ

本システムは、送信者、複数の中継ノード、および受信者から構成される分散アーキテクチャを採用する。各中継ノードはTEEを搭載し、パケットの復号と経路選択を安全に行う。システム全体はIPv6ネットワーク上で動作し、SRv6の機能を活用して柔軟な経路制御を実現する。

アーキテクチャの主な特徴：

1. **送信者**：
   - 送信元アプリケーション
   - Onion暗号化を実行
   - マルチパス候補の初期計算

2. **中継ノード**：
   - TEE搭載のルーター/サーバー
   - Onion層の復号処理
   - 動的経路再計算
   - パケット転送

3. **受信者**：
   - 宛先アプリケーション
   - 最終的なペイロード受信

各コンポーネント間の通信は、IPv6およびSRv6を利用して行われる。

### 2.2 コンポーネント

システムの主要コンポーネントとその機能は以下の通り：

#### 2.2.1 送信者コンポーネント

- **パス探索エンジン**：ネットワークトポロジ情報に基づいて複数の経路候補を計算
- **パス評価モジュール**：経路候補の優先順位付け
- **Onion暗号化エンジン**：多層暗号化の適用
- **SRv6ヘッダ生成器**：IPv6パケットのSRv6ヘッダ設定
- **セッション管理モジュール**：ノードとの通信セッション管理

#### 2.2.2 中継ノードコンポーネント

- **TEEエンクレーブ**：セキュアな処理環境
- **認証モジュール**：パケット送信元の検証
- **SRv6パケット処理エンジン**：SRv6ヘッダ解析と処理
- **Onion層復号モジュール**：暗号化層の復号
- **ネットワーク監視エージェント**：リンク状態と性能のモニタリング
- **代替パス選択エンジン**：ネットワーク状況悪化時の経路再計算
- **パケット転送エンジン**：次ホップへのパケット転送

#### 2.2.3 共通インフラストラクチャ

- **分散ノードディレクトリ**：利用可能なノードリストと属性情報
- **暗号ライブラリ**：標準的な暗号アルゴリズム実装
- **TEE対応ハードウェア**：Intel SGXなどのTEE実装

### 2.3 通信フロー

システムの通信フローは以下の順序で進行する：

1. **初期化フェーズ**：
   - 送信者がパス探索エンジンを使用して複数の候補経路を算出
   - 各パスの評価と優先順位付け
   - 優先順位付きパスリストの作成と暗号化

2. **セッション確立フェーズ**：
   - 送信者は最初のノードとセキュアな通信チャネルを確立
   - 暗号化されたパスリストを最初のノードのTEEに安全に送信
   - 各中継ノードとの鍵交換

3. **データ送信フェーズ**：
   - 送信者は選択したパスに対応するSRv6ヘッダを生成
   - Onion暗号化を適用
   - 最初のノードにパケットを送信

4. **中継フェーズ**：
   - 各ノードでTEEによる認証
   - SRv6ヘッダに基づくパケット転送
   - Onion層の復号と次ホップ情報の抽出
   - ネットワーク状況モニタリングと必要に応じた経路変更

5. **受信フェーズ**：
   - 最終ノードから受信者へのパケット配信
   - 受信者によるデータ受信と処理

---

## 3. プロトコル仕様

### 3.1 パケットフォーマット

#### 3.1.1 IPv6基本ヘッダ
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |


                          Source Address                        +


|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |


                       Destination Address                      +


|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

- Version: IPv6の場合は6（4ビット）
- Traffic Class: QoS制御用（8ビット）
- Flow Label: フロー識別子（20ビット）
- Payload Length: 拡張ヘッダとペイロードの長さ（16ビット）
- Next Header: 次のヘッダタイプ（8ビット）- SRv6ヘッダの場合は43
- Hop Limit: TTL相当（8ビット）
- Source Address: 送信元IPv6アドレス（128ビット）
- Destination Address: 宛先IPv6アドレス（128ビット）

#### 3.1.2 SRv6ヘッダ（IPv6ルーティングヘッダタイプ4）

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Next Header  |   Hdr Ext Len |  Routing Type | Segments Left |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Last Entry   |     Flags     |              Tag              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |


                       Segment List[0] (SID)                    +


|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |

                       Segment List[1] (SID)                    +


|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
...

|                                                               |

                       Segment List[n] (SID)                    +


|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

- Next Header: Onion Routingヘッダを示す値（8ビット）
- Hdr Ext Len: 8オクテット単位でのヘッダ長（8ビット）
- Routing Type: SRv6の場合は4（8ビット）
- Segments Left: 残りのセグメント数（8ビット）
- Last Entry: セグメントリストの最後のインデックス（8ビット）
- Flags: 各種フラグ（8ビット）
- Tag: プロトコル固有のタグ（16ビット）
- Segment List: SIDのリスト（各128ビット）

#### 3.1.3 Onion Routingヘッダ

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Next Header  |   Hdr Ext Len |   OR Type    |    Version    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Session ID                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |


                      MAC (Authentication)                      +


|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |

  
                      Encrypted Onion Layer                     +


|                          (Variable)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

- Next Header: ペイロードのタイプを示す値（8ビット）
- Hdr Ext Len: 8オクテット単位でのヘッダ長（8ビット）
- OR Type: Onion Routingのタイプ（8ビット）
- Version: プロトコルバージョン（8ビット）
- Session ID: セッション識別子（32ビット）
- MAC: メッセージ認証コード（256ビット）
- Encrypted Onion Layer: 現在のノード用に暗号化された層（可変長）
  - 次ホップ情報
  - ノード固有の処理情報
  - 内部の暗号化されたOnion層（次ノード用）

#### 3.1.4 ペイロードフォーマット

ペイロードは可変長であり、アプリケーションデータを含む。Onion暗号化により保護され、最終的な受信者のみが復号できる。

### 3.2 セッション確立（ハンドシェイク）

セッション確立プロセスは、送信者と各中継ノード間で安全な通信チャネルを確立し、暗号鍵を交換するために使用される。

#### 3.2.1 ハンドシェイクプロトコル

1. **ステップ1: 送信者→最初のノード**
   - 送信者は乱数NonceS、Diffie-Hellmanパラメータg^a、サポートする暗号スイートリストを生成
   - 最初のノードの公開鍵で暗号化し送信

Sender -> Node1: {NonceS, g^a, CipherSuites}PK_Node1

2. **ステップ2: 最初のノード→送信者**
- ノードはTEE内で受信データを復号
- 互換性のある暗号スイートを選択
- 乱数NonceN、Diffie-Hellmanパラメータg^b、選択した暗号スイートを生成
- 送信者の公開鍵で暗号化し返信

Node1 -> Sender: {NonceN, g^b, SelectedCipherSuite, HMAC}PK_Sender

3. **ステップ3: 共有秘密の導出**
- 両者はDiffie-Hellmanパラメータから共有秘密g^ab を計算
- 共有秘密、ノンス、およびセッションIDから鍵導出関数（KDF）を使用して、セッション鍵を導出

SessionKey = KDF(g^ab, NonceS, NonceN, SessionID)

4. **ステップ4: 送信者→最初のノード（確認）**
- 送信者は確立された鍵を使用して確認メッセージを送信


Sender -> Node1: {Confirm, HMAC}SessionKey
コピー
5. **ステップ5: パスリスト送信**
- 送信者は優先順位付きのパスリストをセッション鍵で暗号化して送信
Sender -> Node1: {PathList, HMAC}SessionKey
コピー
#### 3.2.2 後続ノードとのセッション確立

送信者は、各中継ノードとの間で個別にセッションを確立する必要がある。このプロセスは、Sphinx暗号化フォーマットを拡張したプロトコルを使用して行われる。

1. **ステップ1: 送信者→ノードi（初期化）**
- 送信者は一時的なDiffie-Hellmanキーペアを生成
- ノードiの公開鍵を使用して暗号化したセッション初期化メッセージを生成
Sender -> NodeI: {EphemeralKey, Nonce, HMAC}PK_NodeI
コピー
2. **ステップ2: ノードi→送信者（応答）**
- ノードiはTEE内で一時的なキーペアを生成
- セッションパラメータを返信
NodeI -> Sender: {EphemeralKey_Response, Nonce_Response, HMAC}EphemeralKey
コピー
3. **ステップ3: 共有鍵導出**
- 両者は共有鍵を導出
SharedKey_I = KDF(DHCompute(EphemeralKey, EphemeralKey_Response), Nonce, Nonce_Response)
コピー
### 3.3 暗号化と復号化

#### 3.3.1 Onion暗号化プロセス（送信者側）

1. **準備段階**
- 送信者は各中継ノードとのセッション確立で得た共有鍵を収集
- 送信者はパスリストから選択した経路に基づき、ノードのリストを決定

2. **内側から外側への暗号化**
- 送信者はまず最も内側の層（最終ノード向け）を暗号化
Layer_N = Encrypt(SharedKey_N, {NextHop: Destination, Payload})
- 次に、内側から外側に向かって順次各層を暗号化
Layer_N-1 = Encrypt(SharedKey_N-1, {NextHop: Node_N, Layer_N})
Layer_N-2 = Encrypt(SharedKey_N-2, {NextHop: Node_N-1, Layer_N-1})
...
Layer_1 = Encrypt(SharedKey_1, {NextHop: Node_2, Layer_2})
3. **MACの生成**
- 各層には認証データ（MAC）を付加
MAC_i = HMAC(MACKey_i, Layer_i || SessionID)
4. **最終パケットの組み立て**
- 送信者は最終的なパケットを組み立て
FinalPacket = IPv6Header + SRv6Header + OnionHeader + Layer_1
#### 3.3.2 Onion復号プロセス（中継ノード側）

1. **パケット受信と認証**
- ノードiはパケットを受信し、MACを検証
VerifyMAC(MACKey_i, Received_MAC, Layer_i || SessionID)
2. **自分の層の復号**
- ノードはTEE内で自分の層を復号
DecryptedLayer = Decrypt(SharedKey_i, Layer_i)
3. **次ホップ情報の抽出**
- 復号されたデータから次ホップ情報を抽出
NextHop = ExtractNextHop(DecryptedLayer)
InnerLayer = ExtractInnerLayer(DecryptedLayer)
4. **新しいMACの生成**
- 次ホップノード用の新しいMACを生成
NewMAC = HMAC(MACKey_NextHop, InnerLayer || SessionID)
5. **パケット転送**
- SRv6ヘッダを更新し、次ホップにパケットを転送
UpdatedPacket = UpdateSRv6Header(Packet) + OnionHeader + InnerLayer + NewMAC
ForwardPacket(NextHop, UpdatedPacket)
#### 3.3.3 使用する暗号アルゴリズム

- **対称暗号**: AES-256-GCM（認証付き暗号）
- **非対称暗号**: RSA-4096（セッション確立）、ECDH P-384（鍵交換）
- **ハッシュ関数**: SHA-384
- **MAC**: HMAC-SHA-384
- **鍵導出関数**: HKDF（HMAC-based Key Derivation Function）

### 3.4 マルチパス経路選択

#### 3.4.1 経路探索アルゴリズム

経路探索は、ネットワークをグラフG = (V, E)として表現し、各エッジe ∈ Eに複数の重み（遅延、帯域幅、信頼性など）を割り当てる多目的最適化問題として扱う。

1. **グラフ構築**
- ノードv ∈ Vには以下の属性を付与:
  - 処理能力（CPU、メモリ）
  - 信頼度スコア（0-1）
  - 地理的位置（オプショナル）
  - サポート機能（TEE種別、HWアクセラレーション）

- エッジe ∈ Eには以下の属性を付与:
  - 遅延（ミリ秒）
  - 帯域幅（Mbps）
  - パケットロス率（%）
  - 混雑度（0-1）

2. **K最短経路アルゴリズム**
- 基本となるアルゴリズムはYen's K最短経路アルゴリズムを拡張したバージョン
- 複数の制約条件（最小帯域幅、最大遅延など）を加味
- 疑似コード：
function FindKShortestPaths(Graph G, Node source, Node destination, int K, Constraints C):
Paths = []
A = [ShortestPath(G, source, destination, C)]  // 最初の最短経路
コピー   for k = 2 to K:
       for i = 0 to size(A[k-2]) - 1:
           SpurNode = A[k-2][i]
           RootPath = A[k-2][0...i]
           
           for each path P in Paths where RootPath is a prefix of P:
               Remove edge P[i] -> P[i+1] from G temporarily
           
           SpurPath = ShortestPath(G with removed edges, SpurNode, destination, C)
           Candidate = RootPath + SpurPath
           
           if Candidate satisfies all constraints in C:
               Paths.append(Candidate)
           
           Restore removed edges to G
       
       if Paths is empty:
           break
       
       Sort Paths by multi-objective criteria
       A[k-1] = Paths[0]  // 次の最良経路を追加
       Paths.remove(Paths[0])
   
   return A
#### 3.4.2 経路評価とランキング

複数の候補経路を評価し、ランキングするための多目的評価関数を定義する。

1. **メトリクスの正規化**
各メトリクスを0〜1の範囲に正規化:
normalized_metric = (metric - min_value) / (max_value - min_value)
コピー
または逆メトリクス（低いほど良い場合）:
normalized_metric = 1 - (metric - min_value) / (max_value - min_value)
コピー
2. **重み付けスコア計算**
PathScore = w_latency * normalized_latency +
w_bandwidth * normalized_bandwidth +
w_packetloss * normalized_packetloss +
w_node_trust * normalized_node_trust +
w_path_diversity * normalized_path_diversity
コピー
デフォルト重み:
- w_latency = 0.3
- w_bandwidth = 0.25
- w_packetloss = 0.2
- w_node_trust = 0.15
- w_path_diversity = 0.1

3. **パス多様性の計算**
経路の多様性を確保するため、既に選択された経路集合に対する新しい経路の多様性を評価:
diversity(P, Selected) = min_{S in Selected} {Node_Diversity(P, S), Edge_Diversity(P, S)}
Node_Diversity(P1, P2) = 1 - |Nodes(P1) ∩ Nodes(P2)| / |Nodes(P1) ∪ Nodes(P2)|
Edge_Diversity(P1, P2) = 1 - |Edges(P1) ∩ Edges(P2)| / |Edges(P1) ∪ Edges(P2)|
コピー
#### 3.4.3 パスリスト管理

パスリストは、優先順位付きの複数経路候補を管理するためのデータ構造であり、以下の情報を含む：

1. **パスリスト構造**
PathList = {
SessionID: <unique session identifier>,
Timestamp: <creation timestamp>,
Expiry: <expiration timestamp>,
Paths: [
{
Priority: 1,
PathID: <unique path identifier>,
Nodes: [Node1, Node2, ..., NodeN],
SRv6Segments: [SID1, SID2, ..., SIDN],
PathMetrics: {
Latency: <estimated latency>,
Bandwidth: <estimated bandwidth>,
TrustScore: <aggregate trust score>,
Reliability: <reliability score>
}
},
{
Priority: 2,
...
},
...
]
}
2. **パスリスト暗号化**
パスリストは送信者のTEE内で暗号化され、最初のノードに送信される：
EncryptedPathList = Encrypt(TEE_Secret_Key, PathList)


3. **パスリスト更新ポリシー**
   - 定期的な更新: デフォルトでは30分ごと
   - イベントトリガー更新: 以下の条件が満たされた場合
     - 現在のパスの半数以上が使用不可になった場合
     - ネットワークトポロジが大幅に変更された場合
     - ノードからの明示的な更新要求があった場合

### 3.5 動的経路再計算

ネットワーク状況の変化に応じて動的に経路を変更するためのアルゴリズムを定義する。

#### 3.5.1 ネットワークモニタリング

各ノードは以下のメトリクスを継続的にモニタリングする：

1. **ローカルメトリクス**
   - CPU使用率: 5秒間の平均使用率（%）
   - メモリ使用率: 使用中メモリの割合（%）
   - キューの深さ: 処理待ちパケット数
   - パケット処理レート: 1秒あたりの処理パケット数

2. **リンクメトリクス**
   - パケットロス率: 直近100パケットのロス率（%）
   - 遅延: エコーパケットによる測定（ミリ秒）
   - 帯域利用率: リンク帯域の使用率（%）
   - ジッター: 遅延の標準偏差（ミリ秒）

3. **ノード状態**
   - 後続ノード到達性: ICMP/TEEベースのReachabilityチェック
   - 障害通知: 他のノードからの明示的な障害通知

#### 3.5.2 経路変更トリガー条件

以下の条件のいずれかが満たされた場合、経路変更プロセスをトリガーする：

1. **パフォーマンス閾値ベース**
   - CPU使用率 > 90%が連続30秒間
   - メモリ使用率 > 85%が連続30秒間
   - パケットロス率 > 5%が連続10秒間
   - 遅延増加 > ベースライン遅延の200%が連続20秒間

2. **障害ベース**
   - 後続ノードが3回連続してreachabilityチェックに失敗
   - 明示的なノード障害通知を受信
   - TCP接続のタイムアウトまたはリセット

3. **TEE特有のトリガー**
   - TEEの整合性検証失敗
   - TEEリソース枯渇（例：EPC枯渇）
   - TEE内での署名検証失敗

#### 3.5.3 代替パス選択

経路変更がトリガーされた場合、ノードのTEE内で以下のアルゴリズムを実行：

function SelectAlternativePath(PathList, CurrentPath, TriggerEvent):
// 使用可能なパスをフィルタリング
AvailablePaths = Filter(PathList.Paths, p =>
IsAvailable(p) &&
p != CurrentPath &&
!ContainsFailedNode(p, TriggerEvent.FailedNode)
)
if AvailablePaths.isEmpty():
    return RequestPathListUpdate()

// 現在のネットワーク状況に基づいてパスを再評価
for each path in AvailablePaths:
    path.CurrentScore = CalculatePathScore(path, CurrentNetworkState)

// 合計スコアの高い順にソート
SortByScore(AvailablePaths)

// 最良の代替パスを選択
return AvailablePaths[0]

#### 3.5.4 SRv6ヘッダの動的更新

代替パスが選択されたら、SRv6ヘッダを更新して新しい経路を反映：

function UpdateSRv6Header(Packet, NewPath):
CurrentSRv6Header = ExtractSRv6Header(Packet)
NewSegmentList = NewPath.SRv6Segments


// 現在のノード以降のセグメントを新しいパスのセグメントで置き換え
CurrentPosition = GetCurrentPosition(CurrentSRv6Header)
UpdatedSegmentList = NewSegmentList.slice(CurrentPosition)

// 新しいSRv6ヘッダを構築
NewSRv6Header = CreateSRv6Header(
    Segments = UpdatedSegmentList,
    SegmentsLeft = UpdatedSegmentList.length - 1
)

// パケットのヘッダを更新
return ReplaceHeader(Packet, CurrentSRv6Header, NewSRv6Header)

#### 3.5.5 パス変更通知

経路変更が発生した場合、後続のノードに通知するオプションのメカニズム：

function NotifyPathChange(NewPath, Reason):
Notification = {
Type: "PathChange",
SessionID: CurrentSession.ID,
OldPathID: CurrentPath.ID,
NewPathID: NewPath.ID,
Timestamp: CurrentTime(),
Reason: Reason
}

// TEEで署名
Signature = TEE_Sign(TEE_PrivateKey, Notification)

// 次のノードに通知を送信
SendToNextNode(NewPath.Nodes[0], Notification, Signature)

### 3.6 SRv6連携

SRv6（Segment Routing over IPv6）機能を活用して経路制御を行う方法を定義する。

#### 3.6.1 SRv6セグメントの構成

SRv6セグメント識別子（SID）は以下の形式で構成：

<Locator>:<Function>:<Argument>

- **Locator**: IPv6アドレスプレフィックス（通常は64ビット）
- **Function**: 特定の機能を表す16ビットの識別子
- **Argument**: 関数に渡すパラメータ（48ビット）

例：`2001:db8:0:1:0:f:0:1`
- Locator: `2001:db8:0:1`
- Function: `0:f`
- Argument: `0:1`

#### 3.6.2 SRv6機能と動作モード

本プロトコルでは以下のSRv6機能を使用：

1. **End動作（基本転送）**
   - SIDがノード自身の場合、次のセグメントに転送

function End(Packet):
If SegmentsLeft > 0:
SegmentsLeft -= 1
UpdateIPv6DA(Packet, SegmentList[SegmentsLeft])
Forward(Packet)

2. **End.X動作（特定インターフェースへの転送）**
- 特定のリンクを通じて転送（マルチパスのため重要）

function End.X(Packet, NextHopInterface):
If SegmentsLeft > 0:
SegmentsLeft -= 1
UpdateIPv6DA(Packet, SegmentList[SegmentsLeft])
Forward(Packet, via=NextHopInterface)

3. **End.T動作（テーブル検索）**
- 特定のルーティングテーブルで次ホップを決定

function End.T(Packet, TableID):
If SegmentsLeft > 0:
SegmentsLeft -= 1
UpdateIPv6DA(Packet, SegmentList[SegmentsLeft])
LookupAndForward(Packet, TableID)

4. **End.DT6動作（宛先ベーステーブル検索）**
- IPv6宛先アドレスに基づいてテーブル検索

function End.DT6(Packet, TableID):
Strip SR Header
LookupAndForward(Packet, TableID)

#### 3.6.3 SRv6ポリシー

SRv6ポリシーは経路を表現するためのセグメントリストと関連メタデータから構成：

SRv6Policy = {
PolicyID: <unique identifier>,
Headend: <source node>,
Endpoint: <destination node>,
Color: <policy class>,
SegmentList: [Segment1, Segment2, ..., SegmentN],
Metadata: {
Latency: <expected latency>,
Bandwidth: <minimum bandwidth>,
Priority: <policy priority>
}
}


#### 3.6.4 SRv6とOnion Routingの統合

SRv6とOnion Routingを統合するための処理フロー：

1. **パス選択とSRv6ポリシー作成**

function CreateSRv6PolicyFromPath(Path):
SegmentList = []
for each Node in Path:
SID = CreateSIDForNode(Node)
SegmentList.append(SID)

   return {
       PolicyID: GenerateUUID(),
       Headend: Path[0],
       Endpoint: Path[Path.length-1],
       Color: DetermineColor(Path),
       SegmentList: SegmentList,
       Metadata: ExtractPathMetrics(Path)
   }

2. **SRv6ヘッダ生成**
function GenerateSRv6Header(SRv6Policy):
return {
NextHeader: ONION_ROUTING_PROTOCOL,
HdrExtLen: CalculateLength(SRv6Policy.SegmentList),
RoutingType: 4,  // SRv6
SegmentsLeft: SRv6Policy.SegmentList.length - 1,
LastEntry: SRv6Policy.SegmentList.length - 1,
Flags: 0,
Tag: 0,
SegmentList: SRv6Policy.SegmentList
}


3. **SRv6対応パケット処理（中継ノード）**
function ProcessSRv6Packet(Packet):
SRv6Header = ExtractSRv6Header(Packet)
CurrentSID = GetCurrentSID(SRv6Header)

   if CurrentSID == MyLocalSID:
       // このノード宛のパケット
       if IsOnionRoutingPacket(Packet):
           // Onion層を処理
           DecryptOnionLayer(Packet)
       
       // 次のセグメントへ
       if SRv6Header.SegmentsLeft > 0:
           SRv6Header.SegmentsLeft -= 1
           NextSID = SRv6Header.SegmentList[SRv6Header.SegmentsLeft]
           UpdateDestinationAddress(Packet, NextSID)
       else:
           // 最後のセグメント
           StripSRv6Header(Packet)
   
   Forward(Packet)


function InitializeEnclave():
// エンクレーブの作成
EnclaveID = sgx_create_enclave(
"onion_routing_enclave.so",
SGX_DEBUG_FLAG,
&LaunchToken,
&TokenUpdated,
&EnclaveID,
NULL
)


2. **リモート証明プロセス**
function PerformRemoteAttestation(EnclaveID, ChallengeData):
// クォートの生成
sgx_report_t report
ecall_create_report(
EnclaveID,
&status,
&targetInfo,
ChallengeData,
sizeof(ChallengeData),
&report
)

  // クォートからの署名付き証明の取得
   sgx_quote_t quote
   sgx_get_quote(
       &report,
       quoteType,
       &spid,
       NULL,
       NULL,
       0,
       NULL,
       &quote,
       sizeof(sgx_quote_t)
   )
   
   return quote

   3. **暗号操作**
function EnclaveCryptoOperations(EnclaveID, OperationType, InputData):
// 入力データをセキュアにエンクレーブに渡す
ecall_crypto_operation(
EnclaveID,
&status,
OperationType,
InputData,
InputDataLength,
OutputData,
OutputDataLength
)

   return OutputData

   
#### 4.1.3 TEEセキュリティ対策

TEE使用時でも考慮すべきセキュリティリスクと対策：

1. **サイドチャネル攻撃対策**
- キャッシュタイミング攻撃対策: 定時間アルゴリズムの使用
- メモリアクセスパターン対策: ORAMに似たメモリアクセスパターンの実装
- 電力解析対策: ランダムな処理追加による消費電力の均一化

2. **エンクレーブロールバック攻撃対策**
- モノトニックカウンタの使用
- SGXのシールドデータにバージョン情報を付加
- 外部の監査可能なログによる検証

3. **制御チャネル攻撃対策**
- SGXとホストOSの相互作用を最小限に抑える設計
- 制御フローの秘匿化
- 重要パラメータの冗長検証

### 4.2 鍵管理

セキュアな鍵管理は、プロトコルのセキュリティを確保するために不可欠である。

#### 4.2.1 鍵の種類と用途

プロトコルで使用される主な鍵の種類：

1. **ノード固有の鍵ペア**
- **用途**: ノード認証、セッション確立時の初期通信
- **保存場所**: 公開鍵は公開され、秘密鍵はTEE内に保存
- **アルゴリズム**: RSA-4096 または ECDSA P-384
- **更新頻度**: 年1回、またはセキュリティインシデント発生時

2. **セッション鍵**
- **用途**: 送信者とノード間の安全な通信
- **保存場所**: TEE内のセキュアストレージのみ
- **アルゴリズム**: AES-256-GCM
- **更新頻度**: セッションごと（通常8時間ごと）

3. **Onion暗号化鍵**
- **用途**: 各層のOnion暗号化
- **保存場所**: 送信者とノードのTEE内
- **アルゴリズム**: AES-256-GCM
- **更新頻度**: パケットバッチごと（または一定時間ごと）

4. **MAC鍵**
- **用途**: メッセージ認証コード生成
- **保存場所**: TEE内のみ
- **アルゴリズム**: HMAC-SHA-384
- **更新頻度**: セッション鍵と同期

#### 4.2.2 鍵導出プロセス

鍵導出関数（KDF）を使用して各種鍵を生成するプロセス：

function DeriveKeys(SharedSecret, Context):
// HKDF抽出フェーズ（PRK生成）
PRK = HKDF-Extract(Salt=NULL, IKM=SharedSecret)

// HKDF拡張フェーズ（各種鍵の導出）
EncryptionKey = HKDF-Expand(PRK, "enc" || Context || 0x01, 32)
MACKey = HKDF-Expand(PRK, "mac" || Context || 0x02, 48)
IVBase = HKDF-Expand(PRK, "iv" || Context || 0x03, 12)

return {
    EncryptionKey: EncryptionKey,
    MACKey: MACKey,
    IVBase: IVBase
}

#### 4.2.3 鍵ローテーションポリシー

鍵の定期的な更新によりセキュリティを維持：

1. **長期鍵のローテーション**
   - ノード固有の鍵ペアは年1回、または以下の場合に更新:
     - セキュリティインシデント発生時
     - TEEのファームウェア/ソフトウェア更新時
     - 管理ポリシーで定められた期間経過時

2. **セッション鍵のローテーション**
   - 基本ローテーション間隔: 8時間ごと
   - トラフィック量ベースローテーション: 100GB処理ごと
   - 条件ベースローテーション: ネットワーク状態変化時

3. **緊急鍵更新プロトコル**

function EmergencyKeyRotation(Reason):
// 緊急ローテーションの通知
BroadcastMessage = {
Type: "EmergencyKeyRotation",
Timestamp: CurrentTime(),
ReasonCode: Reason,
NodeID: MyNodeID
}
コピー   // TEEで署名
   Signature = TEE_Sign(NodePrivateKey, BroadcastMessage)
   
   // 全接続ノードに通知
   Broadcast(BroadcastMessage, Signature)
   
   // 新しい鍵を生成
   GenerateNewKeys()
   
   // リモート証明を再実行
   PerformRemoteAttestation()
コピー
#### 4.2.4 鍵エスクローと監査

法的要件に対応しつつプライバシーを最大限保護するためのポリシー：

1. **No Single Point of Compromise**
- どの単一のノードも通信全体を復号できないアーキテクチャ
- TEEによる鍵の保護で、ノード管理者も鍵にアクセス不可

2. **監査ログの保護**
- TEE内でのみ生成・保存される暗号化された監査ログ
- 複数の信頼できる当事者による閾値暗号を用いた復号

3. **法的インターセプトフレームワーク**
- 複数管轄にまたがる複数当局の承認を必要とする仕組み
- TEE内の特別なインターセプトエンクレーブによる制限付き監視

### 4.3 認証メカニズム

システム内の各エンティティを確実に認証するためのメカニズムを定義する。

#### 4.3.1 ノード認証

ネットワーク内のノードを認証するプロセス：

1. **初期ノード認証**
- ノード証明書を使用したTLS認証
- 分散PKIシステムによる証明書検証
- TEEリモート証明の実行と検証

2. **継続的ノード認証**
- 定期的なリモート証明の再検証（12時間ごと）
- チャレンジ-レスポンス認証の実行（ランダム間隔）
- TEE測定値の変更検知と対応

3. **ノード認証プロトコル**
function AuthenticateNode(NodeCertificate, RemoteAttestationQuote):
// 証明書の検証
if (!VerifyCertificate(NodeCertificate, TrustedCAs)):
return FAIL
コピー   // リモート証明の検証
   if (!VerifyRemoteAttestation(RemoteAttestationQuote)):
       return FAIL
   
   // チャレンジ-レスポンスの実行
   Challenge = GenerateRandomChallenge()
   ExpectedResponse = CalculateExpectedResponse(Challenge, NodeCertificate)
   ActualResponse = SendChallengeAndWaitForResponse(Challenge, Node)
   
   if ActualResponse != ExpectedResponse:
       return FAIL
   
   return SUCCESS
#### 4.3.2 パケット認証

個々のパケットを認証するメカニズム：

1. **MAC生成と検証**
- 各Onion層にはMAC（メッセージ認証コード）を付加
- HMAC-SHA-384を使用
- セッション固有のMAC鍵を使用

2. **認証プロセス**
function AuthenticatePacket(Packet, SessionKey):
// MACの抽出
ReceivedMAC = ExtractMAC(Packet)
   PacketData = ExtractPacketDataWithoutMAC(Packet)
   
   // 予期されるMACの計算
   ExpectedMAC = CalculateHMAC(SessionKey.MACKey, PacketData)
   
   // MACの比較
   return ConstantTimeCompare(ReceivedMAC, ExpectedMAC)
3. **リプレイ防止**
- 単調増加するシーケンス番号の使用
- セッション固有のノンスとカウンタの組み合わせ
- スライディングウィンドウベースのシーケンス番号検証

#### 4.3.3 送信者認証

送信者を認証するメカニズム：

1. **TEEベース認証**
- 送信者のTEEによる認証トークンの生成
- ノードのTEEによるトークン検証
- 相互リモート証明の実行

2. **匿名認証**
- 送信者の匿名性を保持しつつ認証を実現
- ゼロ知識証明に基づく認証
- グループ署名または盲署名の使用

### 4.4 脅威モデルと対策

想定される脅威とそれに対する防御策を定義する。

#### 4.4.1 主要な脅威

1. **グローバル監視者攻撃**
- **脅威**: ネットワークトラフィックの大部分を監視できる攻撃者
- **脆弱性**: トラフィック相関分析による送信者-受信者の特定
- **リスクレベル**: 高

2. **ノード侵害攻撃**
- **脅威**: 一部の中継ノードを制御する攻撃者
- **脆弱性**: 侵害されたノードでのトラフィック解析、マルウェア注入
- **リスクレベル**: 中

3. **出口ノード攻撃**
- **脅威**: 出口ノードを制御する攻撃者
- **脆弱性**: 暗号化されていないトラフィックの盗聴
- **リスクレベル**: 中～高

4. **サイドチャネル攻撃**
- **脅威**: TEEの弱点を悪用する攻撃者
- **脆弱性**: メモリアクセスパターン、タイミング情報からの秘密情報漏洩
- **リスクレベル**: 中

5. **サービス拒否（DoS）攻撃**
- **脅威**: システムリソースを枯渇させる攻撃者
- **脆弱性**: リソース枯渇によるサービス中断
- **リスクレベル**: 中

#### 4.4.2 対策

1. **グローバル監視者攻撃への対策**
- マルチパスルーティングによる通信分散
- ダミートラフィックの生成（パディング）
- 通信パターンの正規化（固定サイズパケット、タイミング）
- 定期的な経路変更のランダム化

2. **ノード侵害攻撃への対策**
- TEEによる処理の保護
- 各ノードの知識の最小化（Need-to-know原則）
- 相互ノード監視と異常検知
- ノード評価とブラックリスト機構

3. **出口ノード攻撃への対策**
- エンドツーエンド暗号化の推奨
- 出口ノードでのコンテンツフィルタリング
- 出口ノードの評判システム
- 出口ノード多様性の確保

4. **サイドチャネル攻撃への対策**
- 定時間暗号アルゴリズムの実装
- ランダム化されたメモリアクセスパターン
- TEEセキュリティ更新の定期適用
- ハードウェアセキュリティ対策の組み込み

5. **DoS攻撃への対策**
- クライアントパズルによる計算コスト付加
- レート制限とリソース割り当て
- 分散型負荷分散
- アダプティブリソース管理

#### 4.4.3 セキュリティ評価基準

システムのセキュリティレベルを評価するための基準：

1. **匿名性メトリクス**
- 送信者匿名性セット（k-匿名性）
- 受信者匿名性セット
- 関係匿名性（送信者-受信者の非関連付け）

2. **攻撃耐性評価**
- ノード侵害閾値（総ノード数の何%までの侵害に耐えるか）
- トラフィック解析耐性（ROC曲線による評価）
- サイドチャネル攻撃耐性（情報漏洩ビットレート）

3. **セキュリティ監査要件**
- コード監査の頻度と範囲
- 侵入テスト要件
- 脆弱性開示ポリシー

## 5. 性能最適化

高速かつ効率的な通信を実現するための性能最適化技術について定義する。

### 5.1 並列処理

暗号処理やパケット処理の高速化のための並列処理手法を定義する。

markdownコピー#### 5.1.1 マルチコア処理

1. **処理分散アーキテクチャ**
  - パケット処理パイプラインの各ステージを別コアに割り当て
  - NUMA（Non-Uniform Memory Access）アウェアなメモリ割り当て
  - コア親和性を考慮したスレッドスケジューリング

2. **コンカレントパケット処理**
function ConcurrentPacketProcessing(PacketBatch):
// パケットバッチを複数のワーカースレッドに分散
PacketGroups = DivideIntoGroups(PacketBatch, NumThreads)
コピー   // 各ワーカースレッドを起動
   Threads = []
   for i = 0 to NumThreads - 1:
       thread = CreateThread(ProcessPacketGroup, PacketGroups[i])
       Threads.append(thread)
   
   // すべてのスレッドの完了を待機
   WaitForAll(Threads)
   
   // 処理結果を収集
   Results = CollectResults(Threads)
   return Results
コピー
3. **並列処理の最適化**
- ワークスティーリングスケジューラの実装
- キャッシュラインの競合を最小化するデータレイアウト
- ロックフリーおよびウェイトフリーデータ構造の使用

#### 5.1.2 パイプライン処理

処理ステージを効率的にパイプライン化して全体のスループットを向上：

1. **パイプラインステージ**
- ステージ1: パケットパーシング（IP, SRv6ヘッダの解析）
- ステージ2: 認証（MAC検証）
- ステージ3: 復号処理（Onion層の復号）
- ステージ4: ルーティング決定（次ホップの決定）
- ステージ5: 転送処理（SRv6ヘッダの更新と転送）

2. **パイプライン実装**
function PipelinedPacketProcessing():
// 各ステージのキューを初期化
Queues = [Queue() for i in range(NUM_STAGES + 1)]
コピー   // 各ステージのワーカースレッドを起動
   Workers = []
   for stage = 0 to NUM_STAGES - 1:
       worker = CreateThread(
           StageProcessor, 
           stage, 
           Queues[stage],   // 入力キュー
           Queues[stage+1]  // 出力キュー
       )
       Workers.append(worker)
   
   // パイプライン処理を継続
   while Running:
       // 入力パケットを最初のキューに追加
       if HasIncomingPackets():
           Packet = ReceivePacket()
           Queues[0].Enqueue(Packet)
       
       // 最終キューからパケットを取り出して送信
       if !Queues[NUM_STAGES].IsEmpty():
           Packet = Queues[NUM_STAGES].Dequeue()
           TransmitPacket(Packet)
       
       Sleep(1)  // CPU負荷軽減
コピー
3. **バックプレッシャー機構**
- 過負荷時にパイプラインの上流に通知するメカニズム
- キュー長に基づくスロットリング
- 優先度ベースのスケジューリング

#### 5.1.3 SIMD最適化

Single Instruction Multiple Data（SIMD）命令セットを活用した高速化：

1. **SIMD対応暗号処理**
- AES-NIを使用したAES暗号化/復号の高速化
- AVX2/AVX-512を使用したSHA-256/384ハッシュ計算の高速化
- PCLMULQDQ命令によるGalois Field乗算の高速化（GCMモード）

2. **バッチ処理最適化**
- 複数のパケット/ブロックを同時に処理
- SIMDレジスタアラインメントの最適化
- ループアンローリングとベクトル化

### 5.2 ハードウェアアクセラレーション

ハードウェアアクセラレーターを活用して処理速度を向上。

#### 5.2.1 暗号アクセラレーション

1. **AES-NIの活用**
- AESENC, AESENCLAST命令の使用
- キースケジュールの最適化
- 実装例:
function AES_Encrypt_AESNI(uint8_t* plaintext, uint8_t* ciphertext,
const uint8_t* roundkeys, int numRounds):
// プレーンテキストをXMMレジスタにロード
__m128i m = _mm_loadu_si128((__m128i*)plaintext)
コピー   // 初期ラウンドキーを適用
   m = _mm_xor_si128(m, _mm_loadu_si128((__m128i*)roundkeys))
   
   // 中間ラウンド
   for (int i = 1; i < numRounds; i++):
       m = _mm_aesenc_si128(m, _mm_loadu_si128((__m128i*)(roundkeys + i * 16)))
   
   // 最終ラウンド
   m = _mm_aesenclast_si128(m, _mm_loadu_si128((__m128i*)(roundkeys + numRounds * 16)))
   
   // 結果を保存
   _mm_storeu_si128((__m128i*)ciphertext, m)
コピー
2. **QATの統合**
- Intel QuickAssist Technology（QAT）の統合
- 暗号処理と圧縮処理のオフロード
- バルク暗号処理の高速化

3. **GPUによる暗号処理**
- GPU並列処理を活用した大量データの並列暗号化
- Onion暗号化層の一括生成
- CUDA/OpenCLを使用した実装

#### 5.2.2 ネットワークアクセラレーション

1. **DPDK（Data Plane Development Kit）の活用**
- カーネルバイパスによる高速パケット処理
- ポーリングモードによる割り込みオーバーヘッド削減
- バルクパケット処理の最適化
function DPDKPacketProcessing():
// EALの初期化
rte_eal_init(argc, argv)
コピー   // メモリプールの初期化
   mbuf_pool = rte_pktmbuf_pool_create(
       "MBUF_POOL",
       NUM_MBUFS,
       MBUF_CACHE_SIZE,
       0,
       RTE_MBUF_DEFAULT_BUF_SIZE,
       rte_socket_id()
   )
   
   // ポートの設定
   rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf)
   
   // メインループ
   while True:
       // パケットバッチを受信
       nb_rx = rte_eth_rx_burst(port, 0, pkts_burst, MAX_PKT_BURST)
       
       // 受信したパケットを処理
       for i = 0 to nb_rx - 1:
           ProcessOnionRoutingPacket(pkts_burst[i])
       
       // 処理したパケットを送信
       nb_tx = rte_eth_tx_burst(port, 0, pkts_burst, nb_rx)
コピー
2. **SmartNIC活用**
- プログラマブルネットワークカード（SmartNIC）によるパケット処理オフロード
- P4言語を使用したSRv6ヘッダ処理の実装
- FPGA/ASICベースのパケット処理アクセラレーション

3. **ゼロコピーネットワーキング**
- メモリコピーを最小化したパケット処理
- mmap()を使用したユーザ空間/カーネル空間間のデータ共有
- バッファ再利用による効率的なメモリ管理

### 5.3 バッファリング戦略

効率的なパケット処理のためのバッファリング戦略：

#### 5.3.1 パケットキューイング

1. **多段キューイング**
- 入力キュー、処理キュー、出力キューの3段階キューイング
- パイプラインステージ間のバッファリング
- 優先度ベースのキューイング

2. **輻輳制御**
- Active Queue Management（AQM）の実装
- Random Early Detection（RED）アルゴリズムの使用
- Explicit Congestion Notification（ECN）のサポート

3. **Quality of Service（QoS）**
- トラフィッククラス分類（低遅延/高帯域幅/標準）
- Hierarchical Token Bucket（HTB）による帯域幅制御
- 公平なスケジューリングアルゴリズム（DRR, HFSC）

#### 5.3.2 メモリ管理

1. **メモリプール**
- 固定サイズバッファプールによるメモリ割り当てオーバーヘッド削減
- NUMA対応メモリプール（ローカルメモリ優先）
- Zero Copy I/Oのサポート

2. **キャッシュ最適化**
- キャッシュライン境界に合わせたデータ構造
- キャッシュプリフェッチの最適化
- 不要なキャッシュラインの競合を回避するパディング

## 6. 実装ガイドライン

具体的な実装に際して参照すべきガイドラインを提供する。

### 6.1 開発環境

#### 6.1.1 推奨ハードウェア

| コンポーネント | 最小要件 | 推奨仕様 |
|--------------|---------|---------|
| CPU | Intel Core i5（SGX対応） | Intel Xeon Gold（SGX対応） |
| RAM | 8GB | 32GB以上 |
| ネットワーク | 1Gbps NIC | 10/25Gbps NIC、DPDK対応 |
| ストレージ | SSD 128GB | NVMe SSD 512GB以上 |
| TPM | TPM 2.0 | TPM 2.0（ファームウェア対応） |

#### 6.1.2 ソフトウェア要件

| ソフトウェア | バージョン | 用途 |
|------------|----------|------|
| OS | Ubuntu 22.04 LTS | ベースOS |
| Rust | 1.70以上 | 主要実装言語 |
| Rust-SGX SDK | 1.1.4以上 | SGX統合 |
| DPDK | 22.11以上 | 高速パケット処理 |
| VyOS | 1.4以上 | ルーティング機能 |
| FRRouting | 8.4以上 | BGP/OSPFサポート |
| ContainerLab | 0.45.0以上 | テスト環境 |

#### 6.1.3 開発ツール

1. **ビルドシステム**
- Cargo（Rustパッケージマネージャ）
- CMake（C/C++コンポーネント用）
- Docker（コンテナ化）

2. **テストツール**
- Cargo Test（単体テスト）
- ContainerLab（ネットワークテスト）
- AFL（American Fuzzy Lop、ファジングテスト）
- Valgrind/ASAN（メモリリーク検出）

3. **性能測定**
- perf（Linux性能分析）
- iperf3（帯域幅測定）
- DTrace/BPF（動的トレーシング）
- FlameGraph（ボトルネック可視化）

### 6.2 インターフェース定義

#### 6.2.1 APIインターフェース

ノードとアプリケーション間のAPIインターフェース：

1. **管理API**
```rust
/// ノード設定インターフェース
pub trait NodeConfig {
    /// ノードを初期化する
    fn initialize(&mut self, config: NodeConfiguration) -> Result<(), NodeError>;
    
    /// ノードの現在の状態を取得する
    fn get_status(&self) -> NodeStatus;
    
    /// ノードのパラメータを更新する
    fn update_parameters(&mut self, params: NodeParameters) -> Result<(), NodeError>;
    
    /// ノードをシャットダウンする
    fn shutdown(&mut self) -> Result<(), NodeError>;
}

/// パス管理インターフェース
pub trait PathManagement {
    /// 利用可能なパスを取得する
    fn get_available_paths(&self) -> Vec<PathInfo>;
    
    /// パスメトリクスを取得する
    fn get_path_metrics(&self, path_id: PathId) -> Option<PathMetrics>;
    
    /// パスの優先順位を更新する
    fn update_path_priorities(&mut self, priorities: HashMap<PathId, u32>) 
        -> Result<(), PathError>;
}

ユーザーAPI
rustコピー/// 匿名通信クライアントインターフェース
pub trait AnonymousClient {
    /// クライアントの初期化
    fn initialize(&mut self, config: ClientConfig) -> Result<ClientHandle, ClientError>;
    
    /// 匿名接続の確立
    fn establish_connection(&mut self, destination: Destination) 
        -> Result<ConnectionId, ConnectionError>;
    
    /// データの送信
    fn send_data(&self, connection_id: ConnectionId, data: &[u8]) 
        -> Result<usize, DataTransferError>;
    
    /// データの受信
    fn receive_data(&self, connection_id: ConnectionId, buffer: &mut [u8]) 
        -> Result<usize, DataTransferError>;
    
    /// 接続の終了
    fn close_connection(&mut self, connection_id: ConnectionId) 
        -> Result<(), ConnectionError>;
}


6.2.2 パケットインターフェース
ネットワークパケット処理インターフェース：
rustコピー/// パケット処理インターフェース
pub trait PacketProcessor {
    /// パケットの受信と処理
    fn process_packet(&mut self, packet: &mut Packet) -> Result<ProcessingAction, PacketError>;
    
    /// パケットバッチの処理
    fn process_packet_batch(&mut self, packets: &mut [Packet]) 
        -> Vec<Result<ProcessingAction, PacketError>>;
    
    /// 処理統計の取得
    fn get_statistics(&self) -> ProcessingStatistics;
}

/// TEEパケット処理インターフェース
pub trait TeePacketProcessor {
    /// TEE内でのパケット処理
    fn tee_process_packet(
        &mut self, 
        encrypted_data: &[u8], 
        additional_data: &[u8]
    ) -> Result<Vec<u8>, TeeProcessingError>;
    
    /// TEE内での認証処理
    fn tee_authenticate_packet(
        &self,
        packet_data: &[u8],
        auth_data: &[u8]
    ) -> Result<bool, TeeAuthenticationError>;
}
6.2.3 設定ファイルフォーマット
システム設定を定義するYAMLフォーマット：
yamlコピー# ノード設定例
node:
  id: "node1.example.org"
  role: "relay"  # entry, relay, exit
  tee:
    type: "sgx"
    enclave_path: "/opt/onion/enclave.signed.so"
    quoting_type: "ecdsa"
  network:
    interfaces:
      - name: "eth0"
        ipv6: "2001:db8::1/64"
        mtu: 1500
        dpdk: true
    srv6:
      enabled: true
      locator_prefix: "2001:db8:cafe::"
      function_prefix: "f::"
      sid_format: "ioam"
  performance:
    threads: 8
    crypto_accel: true
    max_concurrent_sessions: 10000
    buffer_pool_size: 1024
  security:
    key_rotation_interval: 28800  # 8時間（秒単位）
    min_tee_version: "2.17"
    allowed_cipher_suites:
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256
6.3 エラー処理
6.3.1 エラー分類
システムで発生し得るエラーの分類：

設定エラー

無効な設定パラメータ
互換性のないTEEバージョン
利用できないハードウェア機能


初期化エラー

TEE初期化失敗
ネットワークインターフェース初期化失敗
権限不足


通信エラー

パケット破損
タイムアウト
ルート到達不能


暗号エラー

認証失敗
署名検証失敗
復号失敗


リソースエラー

メモリ枯渇
CPUオーバーロード
キュー溢れ



6.3.2 エラー処理戦略
エラー発生時の処理戦略：

検出と記録

すべてのエラーを詳細に記録（TEE内の安全なログ）
エラーの重大度分類とアラート生成


リカバリ

トランザクショナルなエラー処理
フォールバックメカニズム
グレースフル縮退（機能制限付きでの継続）



7. テストと評価
システムの品質と性能を確保するためのテストと評価方法を定義する。
7.1 テスト方法論
7.1.1 単体テスト
個々のコンポーネントの機能を検証するテスト：

暗号モジュールテスト

既知のテストベクトルに対する暗号化/復号の検証
鍵導出関数の検証
MAC生成/検証の正確性


パケット処理テスト

パケットパーシングの正確性
SRv6ヘッダ処理の検証
Onion層処理の検証


経路選択アルゴリズムテスト

様々なネットワークトポロジでの最短経路計算
フェイルオーバー処理の検証
負荷分散の効果測定



7.1.2 統合テスト
複数コンポーネントの連携を検証するテスト：

プロトコルフローテスト

セッション確立から終了までの全フロー検証
異常系（パケットロス、遅延など）でのフロー検証
プロトコルバージョン互換性テスト


TEE統合テスト

エンクレーブ初期化とリモート証明の検証
TEE内での暗号処理の正確性
TEE-ホスト間の安全な通信


ネットワーク統合テスト

ContainerLabによる仮想ネットワークテスト
実ネットワーク環境での動作検証
SRv6対応ルーターとの相互運用性



7.1.3 システムテスト
システム全体の動作を検証するテスト：

機能検証テスト

エンドツーエンド通信の検証
各ユースケースの完全なフロー検証
設定変更時の動作検証


安定性テスト

長時間稼働テスト（7日間以上）
高負荷状態での安定性
メモリリークやリソース枯渇の検出


セキュリティテスト

ペネトレーションテスト
ファジングテスト
脆弱性スキャン



7.2 性能評価基準
システムの性能を測定するための基準と目標値：
7.2.1 スループット測定

パケット処理能力

小パケット（64バイト）: 1Mpps以上
大パケット（1500バイト）: 20Gbps以上
測定方法: DPDKのテスト機能やiperf3を使用


セッション処理能力

新規セッション確立率: 1000セッション/秒以上
同時アクティブセッション数: 10万以上
測定方法: カスタムベンチマークツール


暗号処理性能

AES-256-GCM処理速度: 10Gbps以上
Onion層生成速度: 5000パケット/秒以上
測定方法: OpenSSLベンチマークの拡張版



7.2.2 レイテンシ測定

処理レイテンシ

パケット処理レイテンシ: 100μs以下（ノードあたり）
経路再計算レイテンシ: 500μs以下
測定方法: 高精度タイムスタンプによる測定


エンドツーエンドレイテンシ

3ホップ経路: 10ms以下（物理的距離による遅延を除く）
5ホップ経路: 20ms以下（物理的距離による遅延を除く）
測定方法: 往復時間（RTT）測定


フェイルオーバー時間

ノード障害検出: 500ms以下
経路切り替え完了: 1秒以下
測定方法: パケット連続送信中の障害挿入テスト



7.2.3 リソース使用率

CPU使用率

通常負荷時: コアあたり30%以下
最大負荷時: コアあたり80%以下
測定方法: mpstatとcgroupによる監視


メモリ使用率

基本メモリ使用量: 2GB以下
セッションあたりのメモリ増加: 10KB以下
測定方法: pmap, vmstatによる測定


ネットワークバッファ使用率

受信バッファ使用率: 70%以下（最大負荷時）
送信バッファ使用率: 60%以下（最大負荷時）
測定方法: ethtoolとnetstatによる統計



7.3 セキュリティ検証
セキュリティレベルを検証するためのテスト：
7.3.1 脆弱性評価

自動脆弱性スキャン

一般的な脆弱性データベースとの照合
バイナリレベルの脆弱性スキャン
ソースコード静的解析


ペネトレーションテスト

ブラックボックステスト（外部からの攻撃シミュレーション）
グレーボックステスト（一部内部情報を持った攻撃シミュレーション）
社内および第三者機関によるテスト


ファジングテスト

プロトコルファジング（不正な形式のパケット生成）
API入力ファジング
メモリ破損の検出



7.3.2 匿名性検証

トラフィック分析耐性

相関攻撃に対する耐性測定
タイミング攻撃に対する耐性測定
統計的匿名性の評価


ノード侵害シミュレーション

単一ノード侵害時の情報漏洩量測定
複数ノード侵害時の情報漏洩量測定
TEE侵害時のリスク評価


匿名セット測定

k-匿名性評価（送信者識別の困難さ）
送信者-受信者の関連付け困難性評価
多様なネットワークトポロジでの匿名性レベル測定



7.3.3 監査とセキュリティレビュー

コードレビュー

セキュリティ専門家によるコードレビュー
安全なコーディング規約の遵守確認
第三者によるセキュリティレビュー


暗号実装の検証

暗号ライブラリの実装レビュー
サイドチャネル耐性の検証
暗号プリミティブの妥当性検証


TEEセキュリティレビュー

エンクレーブコードの分析
メモリアクセスパターンの分析
リモート証明プロセスの検証



8. 付録
8.1 参考文献

Danezis, G., & Evans, B. (2015). HORNET: High-speed onion routing at the network edge. In Proceedings of the 2015 ACM SIGSAC conference on computer and communications security (pp. 757-768).
Filsfils, C., Previdi, S., Ginsberg, L., Decraene, B., Litkowski, S., & Shakir, R. (2017). Segment routing in IPv6 (SRv6). Internet Engineering Task Force (IETF) Internet-Draft.
Dingledine, R., Mathewson, N., & Syverson, P. (2004). Tor: The second-generation onion router. In USENIX Security Symposium (Vol. 13, p. 14).
Danezis, G., & Goldberg, I. (2009). Sphinx: A compact and provably secure mix format. In International Workshop on Privacy in Electronic Society (pp. 1-10).
Peng, S., Chen, H., Li, Z., Wu, J., & Xiong, N. (2018). SRv6-based traffic engineering for 5G transport network. China Communications, 15(12), 191-201.
McKeen, F., Alexandrovich, I., Berkowitz, A., Geva, S., Gracias, R., Hotovy, S., ... & Weisse, O. (2013). Innovative instructions and software model for isolated execution. In Software and Compilers for Embedded Systems (SCOPES), 2013 International Conference on (pp. 1-10). IEEE.
Costan, V., & Devadas, S. (2016). Intel SGX Explained. IACR Cryptology ePrint Archive, 2016, 86.
Johnson, D., Menezes, A., & Vanstone, S. (2001). The elliptic curve digital signature algorithm (ECDSA). International journal of information security, 1(1), 36-63.
Kohno, T., Palacio, A., & Black, J. (2003). Building secure crypto: AES-GCM-SIV. IACR Cryptology ePrint Archive, 2019, 396.
Dwork, C. (2006). Differential privacy. In International Colloquium on Automata, Languages, and Programming (pp. 1-12). Springer.
