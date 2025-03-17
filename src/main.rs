use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use rand::Rng;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hkdf::Hkdf;

// 定数
const PROTOCOL_VERSION: u8 = 1;
const DEFAULT_PORT_BASE: u16 = 9000;

// エラータイプ
#[derive(Debug)]
enum Error {
    IoError(std::io::Error),
    CryptoError(String),
    ParseError(String),
    ProtocolError(String),
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IoError(error)
    }
}

// SRv6ヘッダー構造体
#[derive(Clone, Debug)]
struct SRv6Header {
    next_header: u8,
    hdr_ext_len: u8,
    routing_type: u8, // SRv6では4
    segments_left: u8,
    last_entry: u8,
    flags: u8,
    tag: u16,
    segment_list: Vec<Ipv6Addr>,
}

impl SRv6Header {
    fn new(segment_list: Vec<Ipv6Addr>) -> Self {
        let last_entry = (segment_list.len() - 1) as u8;
        Self {
            next_header: 43, // Onion Routingヘッダー
            hdr_ext_len: ((segment_list.len() * 16 + 8) / 8) as u8,
            routing_type: 4,
            segments_left: last_entry,
            last_entry,
            flags: 0,
            tag: 0,
            segment_list,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.next_header);
        bytes.push(self.hdr_ext_len);
        bytes.push(self.routing_type);
        bytes.push(self.segments_left);
        bytes.push(self.last_entry);
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.tag.to_be_bytes());
        
        // セグメントリスト
        for segment in &self.segment_list {
            bytes.extend_from_slice(&segment.octets());
        }
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 8 {
            return Err(Error::ParseError("SRv6ヘッダーが短すぎます".into()));
        }
        
        let next_header = bytes[0];
        let hdr_ext_len = bytes[1];
        let routing_type = bytes[2];
        let segments_left = bytes[3];
        let last_entry = bytes[4];
        let flags = bytes[5];
        let tag = u16::from_be_bytes([bytes[6], bytes[7]]);
        
        // セグメント数の計算
        let segments_count = last_entry as usize + 1;
        let expected_len = 8 + segments_count * 16;
        
        if bytes.len() < expected_len {
            return Err(Error::ParseError("SRv6ヘッダーデータが不足しています".into()));
        }
        
        // セグメントリストの解析
        let mut segment_list = Vec::with_capacity(segments_count);
        for i in 0..segments_count {
            let offset = 8 + i * 16;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[offset..offset + 16]);
            segment_list.push(Ipv6Addr::from(octets));
        }
        
        Ok(Self {
            next_header,
            hdr_ext_len,
            routing_type,
            segments_left,
            last_entry,
            flags,
            tag,
            segment_list,
        })
    }

    fn get_current_sid(&self) -> Option<Ipv6Addr> {
        let index = (self.last_entry - self.segments_left) as usize;
        self.segment_list.get(index).cloned()
    }
    
    fn advance_segment(&mut self) -> Option<Ipv6Addr> {
        if self.segments_left == 0 {
            return None;
        }
        self.segments_left -= 1;
        self.get_current_sid()
    }
}

// Onion層構造体
struct OnionLayer {
    next_hop: Vec<u8>,
    payload: Vec<u8>,
}

impl OnionLayer {
    fn new(next_hop: Vec<u8>, payload: Vec<u8>) -> Self {
        Self { next_hop, payload }
    }
    
    fn encrypt(&self, key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher_key = Key::<Aes256Gcm>::from_slice(key)
            .clone();
        let cipher = Aes256Gcm::new(&cipher_key);
        let nonce = Nonce::<Aes256Gcm>::from_slice(nonce);
        
        // 次ホップ情報とペイロードを連結
        let mut plaintext = Vec::new();
        let next_hop_len = (self.next_hop.len() as u16).to_be_bytes();
        plaintext.extend_from_slice(&next_hop_len);
        plaintext.extend_from_slice(&self.next_hop);
        plaintext.extend_from_slice(&self.payload);
        
        cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|e| Error::CryptoError(format!("暗号化エラー: {}", e)))
    }
    
    fn decrypt(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Self, Error> {
        let cipher_key = Key::<Aes256Gcm>::from_slice(key)
            .clone();
        let cipher = Aes256Gcm::new(&cipher_key);
        let nonce = Nonce::<Aes256Gcm>::from_slice(nonce);
        
        let plaintext = cipher.decrypt(nonce, data)
            .map_err(|e| Error::CryptoError(format!("復号化エラー: {}", e)))?;
        
        if plaintext.len() < 2 {
            return Err(Error::CryptoError("復号データが短すぎます".into()));
        }
        
        // 次ホップ情報の長さを取得
        let next_hop_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        
        if plaintext.len() < 2 + next_hop_len {
            return Err(Error::CryptoError("復号データが不足しています".into()));
        }
        
        // 次ホップ情報とペイロードを分離
        let next_hop = plaintext[2..2 + next_hop_len].to_vec();
        let payload = plaintext[2 + next_hop_len..].to_vec();
        
        Ok(Self { next_hop, payload })
    }
}

// Onionルーティングヘッダー
struct OnionHeader {
    version: u8,
    session_id: u32,
    nonce: [u8; 12],
    mac: [u8; 32],
}

impl OnionHeader {
    fn new(session_id: u32, nonce: [u8; 12]) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            session_id,
            nonce,
            mac: [0; 32], // 初期値、後で計算
        }
    }
    
    fn set_mac(&mut self, mac: [u8; 32]) {
        self.mac = mac;
    }
    
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.extend_from_slice(&[0, 0, 0]); // 予約済み
        bytes.extend_from_slice(&self.session_id.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.mac);
        bytes
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 52 {
            return Err(Error::ParseError("Onionヘッダーが短すぎます".into()));
        }
        
        let version = bytes[0];
        let session_id = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[8..20]);
        
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&bytes[20..52]);
        
        Ok(Self {
            version,
            session_id,
            nonce,
            mac,
        })
    }
}

// ノードタイプ
enum NodeType {
    Sender,
    Relay(Ipv6Addr), // ローカルSID
    Receiver,
}

// ノード構造体
struct Node {
    node_type: NodeType,
    address: SocketAddr,
    session_keys: Mutex<HashMap<u32, Vec<u8>>>,
    mac_keys: Mutex<HashMap<u32, Vec<u8>>>,
}

impl Node {
    fn new(node_type: NodeType, address: SocketAddr) -> Self {
        Self {
            node_type,
            address,
            session_keys: Mutex::new(HashMap::new()),
            mac_keys: Mutex::new(HashMap::new()),
        }
    }
    
    fn set_session_key(&self, session_id: u32, key: Vec<u8>) {
        let mut keys = self.session_keys.lock().unwrap();
        keys.insert(session_id, key);
    }
    
    fn set_mac_key(&self, session_id: u32, key: Vec<u8>) {
        let mut keys = self.mac_keys.lock().unwrap();
        keys.insert(session_id, key);
    }
    
    async fn run(&self, socket: Arc<UdpSocket>) -> Result<(), Error> {
        let mut buf = vec![0u8; 65536];
        
        match &self.node_type {
            NodeType::Sender => {
                // 送信者の処理は別途実装
                println!("送信者ノードを起動中: {}", self.address);
            },
            NodeType::Relay(local_sid) => {
                println!("中継ノードを起動中: {} (SID: {})", self.address, local_sid);
                loop {
                    let (len, src) = socket.recv_from(&mut buf).await?;
                    println!("[中継] パケット受信: {} bytes from {}", len, src);
                    
                    match self.process_relay_packet(&buf[..len]).await {
                        Ok((processed_packet, next_hop)) => {
                            println!("[中継] パケット転送: {} bytes to {}", processed_packet.len(), next_hop);
                            socket.send_to(&processed_packet, next_hop).await?;
                        },
                        Err(e) => {
                            println!("[中継] パケット処理エラー: {:?}", e);
                        }
                    }
                }
            },
            NodeType::Receiver => {
                println!("受信ノードを起動中: {}", self.address);
                loop {
                    let (len, src) = socket.recv_from(&mut buf).await?;
                    println!("[受信] パケット受信: {} bytes from {}", len, src);
                    
                    match self.process_receiver_packet(&buf[..len]) {
                        Ok(message) => {
                            println!("[受信] 受信メッセージ: {}", String::from_utf8_lossy(&message));
                        },
                        Err(e) => {
                            println!("[受信] パケット処理エラー: {:?}", e);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    async fn process_relay_packet(&self, packet: &[u8]) -> Result<(Vec<u8>, SocketAddr), Error> {
        // SRv6ヘッダーを解析
        let mut srv6_offset = 0; // 本来はIPv6ヘッダーの後
        let mut srv6_header = SRv6Header::from_bytes(&packet[srv6_offset..])?;
        
        // 自分宛かチェック
        if let NodeType::Relay(local_sid) = &self.node_type {
            let current_sid = srv6_header.get_current_sid()
                .ok_or(Error::ProtocolError("SIDが見つかりません".into()))?;
                
            if &current_sid != local_sid {
                return Err(Error::ProtocolError("このノード宛ではありません".into()));
            }
        } else {
            return Err(Error::ProtocolError("中継ノードではありません".into()));
        }
        
        // SRv6ヘッダーのサイズを計算
        let srv6_size = 8 + srv6_header.segment_list.len() * 16;
        
        // Onionヘッダーを解析
        let onion_header_offset = srv6_offset + srv6_size;
        let onion_header = OnionHeader::from_bytes(&packet[onion_header_offset..])?;
        
        // セッション鍵を取得
        let session_key = {
            let keys = self.session_keys.lock().unwrap();
            keys.get(&onion_header.session_id)
                .ok_or(Error::ProtocolError("セッション鍵が見つかりません".into()))?
                .clone()
        };
        
        // MAC鍵を取得
        let mac_key = {
            let keys = self.mac_keys.lock().unwrap();
            keys.get(&onion_header.session_id)
                .ok_or(Error::ProtocolError("MAC鍵が見つかりません".into()))?
                .clone()
        };
        
        // MACを検証（ここでは簡略化）
        // 実際には暗号化されたレイヤーとセッションIDを含めて計算
        
        // Onion層を復号
        let onion_data_offset = onion_header_offset + 52; // Onionヘッダーサイズ
        let onion_layer = OnionLayer::decrypt(
            &packet[onion_data_offset..],
            &session_key,
            &onion_header.nonce
        )?;
        
        // 次ホップ情報をパース
        let next_hop_str = std::str::from_utf8(&onion_layer.next_hop)
            .map_err(|_| Error::ParseError("次ホップ文字列の解析に失敗".into()))?;
        
        let next_hop: SocketAddr = next_hop_str.parse()
            .map_err(|_| Error::ParseError("次ホップアドレスの解析に失敗".into()))?;
            
        // SRv6ヘッダーを更新
        srv6_header.advance_segment();
        
        // 新しいパケットを構築
        let mut new_packet = Vec::new();
        new_packet.extend_from_slice(&srv6_header.to_bytes());
        new_packet.extend_from_slice(&onion_header.to_bytes());
        new_packet.extend_from_slice(&onion_layer.payload);
        
        Ok((new_packet, next_hop))
    }
    
    fn process_receiver_packet(&self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        // 受信者の処理は単純化
        // SRv6ヘッダーとOnionヘッダーを解析した後、最終ペイロードを取得
        
        let mut offset = 0;
        let srv6_header = SRv6Header::from_bytes(&packet[offset..])?;
        
        offset += 8 + srv6_header.segment_list.len() * 16;
        let onion_header = OnionHeader::from_bytes(&packet[offset..])?;
        
        // セッション鍵を取得
        let session_key = {
            let keys = self.session_keys.lock().unwrap();
            keys.get(&onion_header.session_id)
                .ok_or(Error::ProtocolError("セッション鍵が見つかりません".into()))?
                .clone()
        };
        
        offset += 52; // Onionヘッダーサイズ
        
        // 最終ペイロードを復号
        let onion_layer = OnionLayer::decrypt(
            &packet[offset..],
            &session_key,
            &onion_header.nonce
        )?;
        
        // 最終ペイロードを返す
        Ok(onion_layer.payload)
    }
    
    async fn send_message(&self, 
                         session_id: u32,
                         path: Vec<Ipv6Addr>, 
                         node_addresses: &[SocketAddr],
                         keys: &[Vec<u8>],
                         message: &[u8],
                         socket: &UdpSocket) -> Result<(), Error> {
        if path.len() != keys.len() {
            return Err(Error::ProtocolError("パスとキーの数が一致しません".into()));
        }
        
        // 最終ペイロード（シンプル化のため宛先情報は固定）
        let mut current_payload = message.to_vec();
        let mut nonce_base = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_base);
        
        // 内側から外側へ暗号化
        for i in (0..path.len()).rev() {
            let mut nonce = nonce_base;
            // 各層で異なるノンスを使用
            nonce[0] = i as u8;
            
            let next_hop = if i == path.len() - 1 {
                // 最終ノードは受信者アドレスへ転送
                "final_destination".as_bytes().to_vec()
            } else {
                // それ以外は次のノードのアドレスを指定
                node_addresses[i+1].to_string().as_bytes().to_vec()
            };
            
            let onion_layer = OnionLayer::new(next_hop, current_payload);
            current_payload = onion_layer.encrypt(&keys[i], &nonce)?;
            nonce_base = nonce;
        }
        
        // Onionヘッダーを作成
        let mut onion_header = OnionHeader::new(session_id, nonce_base);
        
        // MACを計算（簡略化）
        let mac = [0u8; 32]; // 実際にはHMACを計算
        onion_header.set_mac(mac);
        
        // SRv6ヘッダーを作成
        let srv6_header = SRv6Header::new(path);
        
        // 最終パケットを構築
        let mut packet = Vec::new();
        packet.extend_from_slice(&srv6_header.to_bytes());
        packet.extend_from_slice(&onion_header.to_bytes());
        packet.extend_from_slice(&current_payload);
        
        // 送信
        socket.send_to(&packet, node_addresses[0]).await?;
        println!("[送信] パケット送信: {} bytes to {}", packet.len(), node_addresses[0]);
        
        Ok(())
    }
}

// KDFヘルパー関数
fn derive_keys(shared_secret: &[u8], context: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let salt = b"HORNET-POC-Salt";
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    
    let mut encryption_key = vec![0u8; 32];
    hkdf.expand(&[&context[..], b"enc"], &mut encryption_key)
        .expect("HKDF拡張に失敗");
        
    let mut mac_key = vec![0u8; 32];
    hkdf.expand(&[&context[..], b"mac"], &mut mac_key)
        .expect("HKDF拡張に失敗");
    
    (encryption_key, mac_key)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("HORNETベースOnion Routing Proof of Concept");
    
    // ノードアドレスを設定
    let localhost = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let sender_addr = SocketAddr::new(localhost, DEFAULT_PORT_BASE);
    let relay1_addr = SocketAddr::new(localhost, DEFAULT_PORT_BASE + 1);
    let relay2_addr = SocketAddr::new(localhost, DEFAULT_PORT_BASE + 2);
    let relay3_addr = SocketAddr::new(localhost, DEFAULT_PORT_BASE + 3);
    let receiver_addr = SocketAddr::new(localhost, DEFAULT_PORT_BASE + 4);
    
    // SIDを設定
    let relay1_sid = "2001:db8::1".parse::<Ipv6Addr>()?;
    let relay2_sid = "2001:db8::2".parse::<Ipv6Addr>()?;
    let relay3_sid = "2001:db8::3".parse::<Ipv6Addr>()?;
    
    // 送信者ノードを作成
    let sender_node = Arc::new(Node::new(
        NodeType::Sender,
        sender_addr
    ));
    
    // 中継ノード1を作成
    let relay1_node = Arc::new(Node::new(
        NodeType::Relay(relay1_sid),
        relay1_addr
    ));
    
    // 中継ノード2を作成
    let relay2_node = Arc::new(Node::new(
        NodeType::Relay(relay2_sid),
        relay2_addr
    ));
    
    // 中継ノード3を作成
    let relay3_node = Arc::new(Node::new(
        NodeType::Relay(relay3_sid),
        relay3_addr
    ));
    
    // 受信者ノードを作成
    let receiver_node = Arc::new(Node::new(
        NodeType::Receiver,
        receiver_addr
    ));
    
    // セッションIDを生成
    let session_id = rand::thread_rng().gen::<u32>();
    
    // シンプル化のために、事前に鍵を生成して各ノードに配布
    let relay1_key = vec![1u8; 32];
    let relay2_key = vec![2u8; 32];
    let relay3_key = vec![3u8; 32];
    let receiver_key = vec![4u8; 32];
    
    // 各ノードに鍵を設定
    relay1_node.set_session_key(session_id, relay1_key.clone());
    relay2_node.set_session_key(session_id, relay2_key.clone());
    relay3_node.set_session_key(session_id, relay3_key.clone());
    receiver_node.set_session_key(session_id, receiver_key.clone());
    
    // MAC鍵も設定（簡略化）
    relay1_node.set_mac_key(session_id, vec![101u8; 32]);
    relay2_node.set_mac_key(session_id, vec![102u8; 32]);
    relay3_node.set_mac_key(session_id, vec![103u8; 32]);
    receiver_node.set_mac_key(session_id, vec![104u8; 32]);
    
    // ソケットを作成
    let sender_socket = Arc::new(UdpSocket::bind(sender_addr).await?);
    let relay1_socket = Arc::new(UdpSocket::bind(relay1_addr).await?);
    let relay2_socket = Arc::new(UdpSocket::bind(relay2_addr).await?);
    let relay3_socket = Arc::new(UdpSocket::bind(relay3_addr).await?);
    let receiver_socket = Arc::new(UdpSocket::bind(receiver_addr).await?);
    
    // 各ノードを別タスクで実行
    let relay1_handle = {
        let socket = Arc::clone(&relay1_socket);
        let node = Arc::clone(&relay1_node);
        tokio::spawn(async move {
            if let Err(e) = node.run(socket).await {
                eprintln!("中継1エラー: {:?}", e);
            }
        })
    };
    
    let relay2_handle = {
        let socket = Arc::clone(&relay2_socket);
        let node = Arc::clone(&relay2_node);
        tokio::spawn(async move {
            if let Err(e) = node.run(socket).await {
                eprintln!("中継2エラー: {:?}", e);
            }
        })
    };
    
    let relay3_handle = {
        let socket = Arc::clone(&relay3_socket);
        let node = Arc::clone(&relay3_node);
        tokio::spawn(async move {
            if let Err(e) = node.run(socket).await {
                eprintln!("中継3エラー: {:?}", e);
            }
        })
    };
    
    let receiver_handle = {
        let socket = Arc::clone(&receiver_socket);
        let node = Arc::clone(&receiver_node);
        tokio::spawn(async move {
            if let Err(e) = node.run(socket).await {
                eprintln!("受信者エラー: {:?}", e);
            }
        })
    };
    
    // 少し待ってから送信
    sleep(Duration::from_secs(1)).await;
    
    // パスとノードアドレスの準備
    let path = vec![relay1_sid, relay2_sid, relay3_sid];
    let node_addresses = vec![relay1_addr, relay2_addr, relay3_addr, receiver_addr];
    let keys = vec![relay1_key, relay2_key, relay3_key];
    
    // テストメッセージ送信
    println!("テストメッセージを送信します...");
    sender_node.send_message(
        session_id,
        path,
        &node_addresses,
        &keys,
        b"Hello, HORNET Onion Routing!",
        &sender_socket
    ).await?;
    
    // メインスレッドを継続（実際のシステムでは適切な終了条件を設定）
    sleep(Duration::from_secs(10)).await;
    
    println!("終了中...");
    
    Ok(())
}
