
use std::vec::Vec;
use std::io::Read;
use std::sync::LazyLock;
use bytes::{Bytes, BytesMut, BufMut};
use thiserror::Error;
use std::convert::TryInto;
use std::array::TryFromSliceError;
use std::str::Utf8Error;
use std::num::TryFromIntError;
use iroh::{EndpointAddr, endpoint::{Connection, ConnectionError, Endpoint, ReadError, RecvStream, SendStream, WriteError, presets}};
use iroh_tickets::{Ticket, endpoint::EndpointTicket};
use log::{error, warn, info, debug};
use tokio;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use sonic_rs::{JsonPointer, PointerNode, JsonValueTrait};
use ahash::RandomState;
use std::fmt::{Formatter};
use std::sync::Arc;
use tokio_websockets::proto::{WebSocketStream, Message};
use futures_util::{SinkExt, StreamExt};

use crate::GetIrohPacketError::UnexpectedEOS;

pub mod test;

pub const ALPN: &[u8] = b"nostr-iroh-proxy/0";

pub static ALPNs: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| { vec![(ALPN.to_vec())] });

pub struct IrohPacket {
    pub flags: u32,
    pub id: String,
    pub payload: String
}

impl IrohPacket {
    pub const EPHEMERAL: u32 = 1;
    fn is_ephemeral(&self) -> bool {
        IrohPacket::EPHEMERAL & self.flags > 0
    }
    fn is_persistent(&self) -> bool {
        IrohPacket::EPHEMERAL & self.flags == 0
    }
    fn new(flags: u32, id: &str, payload: String) -> IrohPacket {
        return IrohPacket { flags: flags, id: id.to_string(), payload: payload }
    }
    fn dump(&self) {
        println!("Packet from client:");
        println!("Flags: {}", self.flags);
        println!("Id: ({}) \"{}\"", self.id.len(), self.id);
        println!("Payload: ({}) \"{}\"", self.payload.len(), self.payload);
        println!("-------------------------");
    }
}

#[derive(Error, Debug)]
pub enum GetIrohPacketError {
    #[error("Data read error: {0}")]
    DataReadError(#[from] ReadError),
    #[error("Error while converting bytes into u32: {0}")]
    U32ConvertError(#[from] TryFromSliceError),
    #[error("Error while converting bytes into UTF-8: {0}")]
    Utf8Error(#[from] Utf8Error),
    #[error("Unexpected EOS")]
    UnexpectedEOS
}

#[derive(Error, Debug)]
pub enum SendIrohPacketError {
    #[error("Data write error: {0}")]
    DataWriteError(#[from] WriteError),
    #[error("Error while converting u32 into bytes: {0}")]
    U32ConvertError(#[from]  TryFromIntError)
}

pub struct IrohRecvStream {
    stream: RecvStream,
    current_chunk: Bytes
}

impl IrohRecvStream {
    pub const MAX_CHUNK_SIZE: usize = 1024*8;

    fn new(stream: RecvStream) -> IrohRecvStream {
        return IrohRecvStream { stream: stream, current_chunk: Bytes::new() }
    }

    async fn read_packet(&mut self) -> Result<Option<IrohPacket>, GetIrohPacketError> {
        let mut packet: IrohPacket = IrohPacket::new(0, "", "".to_string());
        let mut buf: BytesMut = BytesMut::new();
        let mut id_len;
        let mut payl_len;
        if self.current_chunk.len() == 0 {
            let op = self.stream.read_chunk(Self::MAX_CHUNK_SIZE).await?;
            if op == None { return Ok(None) }
            self.current_chunk = op.unwrap();
        }
        if self.current_chunk.len() >= 12 {
            packet.flags = u32::from_be_bytes(self.current_chunk[..4].try_into()?);
            id_len = u32::from_be_bytes(self.current_chunk[4..8].try_into()?) as usize;
            payl_len = u32::from_be_bytes(self.current_chunk[8..12].try_into()?) as usize;
            self.current_chunk.split_to(12);
        } else {
            buf.extend_from_slice(&self.current_chunk);
            loop {
                let op = self.stream.read_chunk(Self::MAX_CHUNK_SIZE).await?;
                if op == None { return Err(UnexpectedEOS) }
                self.current_chunk = op.unwrap();
                if buf.len() + self.current_chunk.len() > 12 {
                    let rest = self.current_chunk.split_to(12 - buf.len());
                    buf.extend_from_slice(&rest);
                    break;
                }
                buf.extend_from_slice(&self.current_chunk);
                if buf.len() == 12 { break }
            }
            packet.flags = u32::from_be_bytes(buf[..4].try_into()?);
            id_len = u32::from_be_bytes(buf[4..8].try_into()?) as usize;
            payl_len = u32::from_be_bytes(buf[8..12].try_into()?) as usize;
        }

        if self.current_chunk.len() >= id_len {
            let rest = self.current_chunk.split_to(id_len);
            packet.id = std::str::from_utf8(&rest)?.to_string();
        } else {
            buf.clear();
            if self.current_chunk.len() > 0 { buf.extend_from_slice(&self.current_chunk); }
            loop {
                let op = self.stream.read_chunk(Self::MAX_CHUNK_SIZE).await?;
                if op == None { return Err(UnexpectedEOS) }
                self.current_chunk = op.unwrap();
                if self.current_chunk.len() + buf.len() >= id_len {
                    let rest = self.current_chunk.split_to(id_len - buf.len());
                    if buf.len() > 0 {
                        buf.extend_from_slice(&rest);
                        packet.id = std::str::from_utf8(&buf)?.to_string();
                    } else {
                        packet.id = std::str::from_utf8(&rest)?.to_string();
                    }
                    break;
                } else { buf.extend_from_slice(&self.current_chunk); }
            }
        }
        if self.current_chunk.len() >= payl_len {
            let rest = self.current_chunk.split_to(payl_len);
            packet.payload = std::str::from_utf8(&rest)?.to_string();
        } else {
            buf.clear();
            if self.current_chunk.len() > 0 { buf.extend_from_slice(&self.current_chunk); }
            loop {
                let op = self.stream.read_chunk(Self::MAX_CHUNK_SIZE).await?;
                if op == None { return Err(UnexpectedEOS) }
                self.current_chunk = op.unwrap();
                if self.current_chunk.len() + buf.len() >= payl_len {
                    let rest = self.current_chunk.split_to(payl_len - buf.len());
                    if buf.len() > 0 {
                        buf.extend_from_slice(&rest);
                        packet.payload = std::str::from_utf8(&buf)?.to_string();
                    } else {
                        packet.payload = std::str::from_utf8(&rest)?.to_string();
                    }
                    break;
                } else { buf.extend_from_slice(&self.current_chunk); }
            }
        }
        return Ok(Some(packet));
    }
}

pub struct IrohSendStream {
    stream: tokio::sync::Mutex<SendStream>
}

impl IrohSendStream {
    pub fn new(stream: SendStream) -> IrohSendStream {
        return IrohSendStream { stream: tokio::sync::Mutex::new(stream) }
    }

    pub async fn finish(&self) { self.stream.lock().await.finish(); }

    pub async fn send_packet(&self, packet: &IrohPacket) -> Result<(), SendIrohPacketError> {
        let mut buf: BytesMut = BytesMut::new();
        buf.put_u32(packet.flags);
        let id_len: u32 = packet.id.len().try_into()?;
        buf.put_u32(id_len);
        let payl_len: u32 = packet.payload.len().try_into()?;
        buf.put_u32(payl_len);
        buf.extend_from_slice(packet.id.as_bytes());
        buf.extend_from_slice(packet.payload.as_bytes());
        self.stream.lock().await.write_chunk(buf.freeze()).await?;
        Ok(())
    }
}

pub struct PacketSessionInfo<'a> {
    id: sonic_rs::LazyValue<'a>,
    closing: bool,
    closing_bith: bool,
    flags: u32
}

struct WebSocketPacketInfo {
    id_path: Box<sonic_rs::JsonPointer>,
    closing: bool,
    closing_both: bool,
    flags: u32
}
pub struct WebSocketPacketsDatabase {
    map: hashbrown::HashMap<String, WebSocketPacketInfo, RandomState>
}

impl WebSocketPacketsDatabase {
    pub fn new() -> Self {
        Self {
            map: hashbrown::HashMap::with_hasher(RandomState::default())
        }
    }

    pub fn add(&mut self,
        cmd: &str, ptr: &JsonPointer, closing: bool,
        closing_both: bool, flags: u32)
    {
        self.map.insert(format!("\"{}\"", cmd), WebSocketPacketInfo
        {
            id_path: ptr.to_vec().into_boxed_slice(),
            closing: closing, closing_both: closing_both, flags: flags
        });
    }

    pub fn get(&self, cmd: &str) -> Option<&WebSocketPacketInfo> {
        self.map.get(cmd)
    }
}

pub struct WebSocketPacketAnalyzer {
    db: Arc<WebSocketPacketsDatabase>
}

impl WebSocketPacketAnalyzer {
    pub fn new(db: Arc<WebSocketPacketsDatabase>) -> Self {
        Self { db: db }
    }

    pub fn get_info<'s>(&self, data: &'s str) -> Result<Option<PacketSessionInfo<'s>>, sonic_rs::Error> {
        let ret_cmd = sonic_rs::get(data, sonic_rs::pointer![0])?;
        let cmd = ret_cmd.as_raw_str();
        let Some(info) = self.db.get(cmd)
        else { return Ok(None) };
        let id = sonic_rs::get(data, &info.id_path)?;
        Ok(Some(PacketSessionInfo {
            id, closing: info.closing,
            closing_bith: info.closing_both,
            flags: info.flags}))
    }
}

//type IrohRecvStreamMap = dashmap::DashMap<String, RecvStream, ahash::RandomState>;
type IrohSendStreamMap = dashmap::DashMap<String, Arc<IrohSendStream>, ahash::RandomState>;

type AsyncWebSocket<T> = Mutex<WebSocketStream<T>>;
pub struct ConnectionBridge<T: Send + 'static> {
    connection: Connection,
    websocket: AsyncWebSocket<T>,
//    recv_streams: IrohRecvStreamMap,
    ephemeral_send_streams: IrohSendStreamMap,
    persistent_send_streams: IrohSendStreamMap,
    analyzer: Arc<WebSocketPacketAnalyzer>
}

pub enum ConnectionBridgeSendStreamOrId {
    SendStream(Arc<IrohSendStream>),
    StreamExternalId(String)
}

impl<T> ConnectionBridge<T> where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    pub fn new(conn: Connection, wsc: AsyncWebSocket<T>, analyzer: Arc<WebSocketPacketAnalyzer>) -> Self {
        Self { connection: conn,
            websocket: wsc,
            ephemeral_send_streams: IrohSendStreamMap::with_hasher(ahash::RandomState::new()),
            persistent_send_streams: IrohSendStreamMap::with_hasher(ahash::RandomState::new()),
            analyzer: analyzer }
    }

    pub fn is_ephemeral(&self, flags: u32) -> bool {
        return flags & IrohPacket::EPHEMERAL > 0;
    }

    pub fn is_persistent(&self, flags: u32) -> bool {
        return flags & IrohPacket::EPHEMERAL == 0;
    }

    pub fn get_send_streams_container(&self, flags: u32) -> &IrohSendStreamMap {
        if self.is_ephemeral(flags) { return &self.ephemeral_send_streams }
        return &self.persistent_send_streams
    }


    pub async fn get_or_open_send_stream(self: &Arc<Self>, id: &str,
        flags: u32) -> Result<Arc<IrohSendStream>, ConnectionError> {
        let ssmap = self.get_send_streams_container(flags);
        if let Some(r) = ssmap.get(id) {
            return Ok(r.value().clone())
        }

        self.clone().open_stream(id, flags).await
    }

    pub async fn remove_send_stream(self: &Arc<Self>, id: &str, flags: u32, finish: bool) {
        let ssmap = self.get_send_streams_container(flags);
        if finish {
            let ret = ssmap.get(id);
            if let Some(r) = ret {
                let iss = r.value();
                iss.finish().await;
            }
        }
        ssmap.remove(id);
    }

    pub async fn handle_recv_stream(
        &self,
        stream: RecvStream,
        ss_or_id: ConnectionBridgeSendStreamOrId) -> Result<(), GetIrohPacketError>
    {
        let mut irs: IrohRecvStream = IrohRecvStream::new(stream);
        let mut res: Result<(), GetIrohPacketError> = Ok(());
        let mut stream_id = "".to_string();
        let mut external_id: Option<String> = None;
        let mut iroh_send_stream: Option<Arc<IrohSendStream>> = None;
        match ss_or_id {
            ConnectionBridgeSendStreamOrId::StreamExternalId(s) => { stream_id = s; },
            ConnectionBridgeSendStreamOrId::SendStream(ss) => { iroh_send_stream = Some(ss); }
        };
        let mut first_packet = true;
        loop {
            let packet_result = irs.read_packet().await;
            let packet_op: Option<IrohPacket> = match packet_result {
                Ok(packet) => packet,
                Err(e) => { error!("Read packet error: {}", e); res = Err(e); break; }
            };
            match packet_op {
                None => { debug!("Stream closed."); break },
                Some(packet) => {
                    if first_packet && let Some(s) = iroh_send_stream.take() {
                        stream_id = packet.id; first_packet = false;
                        let ssmap = self.get_send_streams_container(packet.flags);
                        if ssmap.contains_key(&stream_id) {
                            error!("Another stream with id {} already registered!", stream_id);
                        }
                        ssmap.insert(stream_id.clone(), s);
                    } else {
                        if stream_id != packet.id {
                            error!("Packet id inequal to stream id: {} != {}", stream_id, packet.id);
                        }
                    }
                    self.websocket.lock().await.send(Message::text(packet.payload)).await;
                }
            };
        }
        res
    }

    pub async fn open_stream(self: Arc<Self>, id: &str, flags: u32) -> Result<Arc<IrohSendStream>, ConnectionError> {
        let (send, recv) = self.connection.open_bi().await?;
        let iss = Arc::new(IrohSendStream::new(send));
        let ssmap = self.get_send_streams_container(flags);
        ssmap.insert(id.to_string(), iss.clone());
        let self_clone = Arc::clone(&self);
        let arg = ConnectionBridgeSendStreamOrId::StreamExternalId(id.to_string());
        tokio::spawn(async move {
            self_clone.handle_recv_stream(recv, arg).await;
        });
        Ok(iss)
    }

    pub async fn handle_websocket(self: Arc<Self>) {
        let s2 = self.clone();
        let ws = &self.websocket;
        let analyzer = &self.analyzer;
        loop {
            let data_o = ws.lock().await.next().await;
            match data_o {
                None => { break },
                Some(res) => {
                    match res {
                        Err(e) => { error!("Error while reading packet from WebSocket: {}", e); break },
                        Ok(msg) => {
                            if msg.is_binary() || msg.is_text() {
                                if let Some(data) = msg.as_text() {
                                    let res_info = analyzer.get_info(data);
                                    match res_info {
                                        Err(_) => { break },
                                        Ok(o_info) => {
                                            let mut id: String = String::new();
                                            let mut flags: u32 = 0;
                                            let mut closing = false;
                                            if let Some(info) = o_info {
                                                id = info.id.to_string();
                                                flags = info.flags;
                                                closing = info.closing;
                                            }
                                            let iss_ret = self.get_or_open_send_stream(&id, flags).await;
                                            if let Ok(iss) = iss_ret {
                                                let packet = IrohPacket::new(flags, &id, data.to_string());
                                                let send_ret = iss.send_packet(&packet).await;
                                                if let Err(e) = send_ret {
                                                    error!("Error while sending packet to Iroh stream: {}", e);
                                                    closing = true;
                                                }
                                                if closing {
                                                    self.remove_send_stream(&id, flags, true).await;
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if msg.is_close() { break }
                        }
                    }
                }
            }
        }
    }
}
