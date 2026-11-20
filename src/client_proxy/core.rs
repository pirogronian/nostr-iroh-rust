
use std::sync::Arc;
use ahash;
use std::sync::atomic::*;

use dashmap::DashMap;
use iroh::tls;
use log::{error, warn, info, debug};

use sonic_rs::pointer;
use tokio_util::sync::CancellationToken;
use core::net::SocketAddr;
use tokio;
use tokio::net::{TcpListener, TcpStream};
use ahash::RandomState;
use tokio_rustls::TlsAcceptor;

use iroh::{EndpointAddr, SecretKey, endpoint::{BindError, Endpoint, presets}};
use tokio_websockets::{MaybeTlsStream, ServerBuilder};

use crate::{ALPN, ALPNs, ConnectionBridge, IrohPacket, BridgeSettings,
    WebSocketPacketAnalyzer, WebSocketPacketsDatabase, server_stream::ServerStream};

impl WebSocketPacketsDatabase {
    pub fn new_client_default() -> Self {
        let mut db = Self::new();

        db.add("EVENT", &pointer![1, "id"], false, false, IrohPacket::EPHEMERAL);
        db.add("REQ", &pointer![1], false, false, 0);
        db.add("CLOSE", &pointer![1], true, false, 0);

        return db;
    }
}

type ConnectionBridgesContainer = DashMap<SocketAddr, Arc<ConnectionBridge>, ahash::RandomState>;

struct BridgeGuard(Arc<ClientProxy>);

impl Drop for BridgeGuard {
    fn drop(&mut self) {
        self.0.decrease_bridges_num();
    }
}

pub struct ClientProxy {
    pub endpoint: Endpoint,
    remote_addr: EndpointAddr,
    listener: TcpListener,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    bridges: ConnectionBridgesContainer,
    analyzer: Arc<WebSocketPacketAnalyzer>,
    bridges_num: AtomicUsize,
    bridge_settings: Arc<BridgeSettings>,
    max_connections: AtomicUsize,
    token: CancellationToken
}

impl ClientProxy {
    pub fn new(endpoint: Endpoint, listener: TcpListener,
        tls_acceptor: Option<Arc<TlsAcceptor>>, remote_addr: EndpointAddr,
        bridge_settings: Arc<BridgeSettings>,
        max_connections: usize) -> Self
    {
        let db = Arc::new(WebSocketPacketsDatabase::new_client_default());
        let analyzer = Arc::new(WebSocketPacketAnalyzer::new(db));

        return Self {
            endpoint: endpoint,
            listener: listener,
            tls_acceptor: tls_acceptor,
            remote_addr: remote_addr,
            bridges: ConnectionBridgesContainer::with_hasher(ahash::RandomState::new()),
            analyzer: analyzer,
            bridges_num: AtomicUsize::new(0),
            bridge_settings: bridge_settings,
            max_connections: AtomicUsize::new(max_connections),
            token: CancellationToken::new()
        }
    }

    pub fn shutdown(&self) {
        self.token.cancel();
    }

    fn decrease_bridges_num(&self) {
        self.bridges_num.fetch_sub(1, Ordering::Release);
    }

    pub async fn start(self: Arc<Self>) {
        loop {
            let token = self.token.clone();
            let listen_o = tokio::select!{
                _ = self.token.cancelled() => { None }
                ret = self.listener.accept() => { Some(ret) }
            };
            if listen_o.is_none() { break }
            let listen_ret = listen_o.unwrap();
            match listen_ret {
                Err(e) => {
                    error!("Error while accepting TCP connection: {}", e);
                    break
                }
                Ok((tcp_stream, addr)) => {
                    let curr_num = self.bridges_num.fetch_add(1, Ordering::AcqRel);
                    let max_conn = self.max_connections.load(Ordering::Acquire);
                    if max_conn > 0 && max_conn < curr_num {
                        self.bridges_num.fetch_sub(1, Ordering::Release);
                        drop(tcp_stream);
                        continue
                    }

                    let self_copy = self.clone();
                    tokio::spawn(async move {
                        let _guard = BridgeGuard(self_copy.clone());
                        let maybe_tls = if let Some(tls_acceptor) = self_copy.tls_acceptor.clone() {
                            let ret = tls_acceptor.accept(tcp_stream).await;
                            match ret {
                                Err(e) => {
                                    error!("Error while accepting TLS stream: {e}");
                                    return
                                }
                                Ok(tls_stream) => {
                                    ServerStream::Tls(tls_stream)
                                }
                            }
                        } else {
                            ServerStream::Plain(tcp_stream)
                        };
                        let ws_ret = ServerBuilder::new().accept(maybe_tls).await;
                        match ws_ret {
                            Err(e) => {
                                error!("Error while upgrading connection to WebSocket: {}", e);
                                return
                            }
                            Ok((_req, stream)) => {
                                let ret = self_copy.endpoint.connect(self_copy.remote_addr.clone(), ALPN).await;
                                match ret {
                                    Err(e) => {
                                        error!("Error while connecting to remote endpoint: {}", e);
                                        return
                                    }
                                    Ok(conn) => {
                                        let cb = ConnectionBridge::new(conn,
                                            stream, self_copy.analyzer.clone(),
                                            self_copy.bridge_settings.clone(), &token);
                                        
                                        let cbp = Arc::new(cb);
                                        let handle1 = tokio::spawn(cbp.clone().handle_connection());
                                        let handle2 = tokio::spawn(cbp.clone().handle_websocket());
                                        
                                        self_copy.bridges.insert(addr.clone(), cbp.clone());

                                        tokio::select! {
                                            _ = handle1 => {}
                                            _ = handle2 => {}
                                        }

                                        self_copy.bridges.remove(&addr);
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    }
}
