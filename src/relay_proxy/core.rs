
use log::{debug, info, warn, error};
use iroh::{endpoint::{Endpoint}};
use http::Uri;
use ahash;
use std::sync::atomic::*;
use tokio_util::sync::CancellationToken;
use std::sync::Arc;
use dashmap::DashMap;
use sonic_rs::pointer;
use tokio_websockets::{ClientBuilder, Error};

use crate::{ALPNs, ConnectionBridge, IrohPacket, BridgeSettings,
    WebSocketPacketAnalyzer, WebSocketPacketsDatabase, WebSocketWrapper};

impl WebSocketPacketsDatabase {
    pub fn new_proxy_default() -> Self {
        let mut db = Self::new();

        db.add("EVENT", &pointer![1], false, false, 0);
        db.add("OK", &pointer![1], true, false, IrohPacket::EPHEMERAL);
        db.add("EOSE", &pointer![1], false, false, 0);
        db.add("CLOSED", &pointer![1], true, false, 0);

        return db;
    }
}

struct BridgeGuard(Arc<RelayProxy>);

impl Drop for BridgeGuard {
    fn drop(&mut self) {
        self.0.decrease_bridges_num();
    }
}

type ConnectionBridgesContainer = DashMap<usize, Arc<ConnectionBridge>, ahash::RandomState>;

pub struct RelayProxy {
    endpoint: Endpoint,
    remote_uri: Uri,
    analyzer: Arc<WebSocketPacketAnalyzer>,
    bridges: ConnectionBridgesContainer,
    bridges_num: AtomicUsize,
    bridge_settings: Arc<BridgeSettings>,
    max_connections: AtomicUsize,
    token: CancellationToken
}

impl RelayProxy {
    pub fn new(ep: Endpoint, remote_uri: Uri, bridge_settings: Arc<BridgeSettings>, max_connections: usize) -> Self {
        let db = Arc::new(WebSocketPacketsDatabase::new_proxy_default());
        let analyzer = Arc::new(WebSocketPacketAnalyzer::new(db));

        return Self {
            endpoint: ep,
            remote_uri: remote_uri,
            analyzer: analyzer,
            bridges: ConnectionBridgesContainer::with_hasher(ahash::RandomState::new()),
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
            let iroh_conn = match self.endpoint.accept().await {
                None => { info!("No more connection to accept, breaking."); break; }
                Some(inc) => {
                    match inc.await {
                        Err(e) => {
                            error!("Error while accepting connection: {}", e);
                            continue;
                        }
                        Ok(conn) => conn
                    }
                }
            };
            let curr_conn_num = self.bridges_num.fetch_add(1, Ordering::AcqRel);
            let max_conn_num = self.max_connections.load(Ordering::Acquire);
            if max_conn_num > 0 && curr_conn_num > max_conn_num {
                iroh_conn.close(1u32.into(), "Too many connections".as_bytes());
                self.bridges_num.fetch_sub(1, Ordering::Release);
                continue;
            }

            let self_copy = self.clone();
            tokio::spawn(async move{
                let _guard = BridgeGuard(self_copy.clone());

                
                let ws_conn = match ClientBuilder::from_uri(self_copy.remote_uri.clone()).connect().await {
                    Err(e) => {
                        error!("Error while connectiing to remote WebSocket: {}", e);
                        return
                    }
                    Ok((conn, _resp)) => conn
                };

                
                let cb = ConnectionBridge::new(
                    iroh_conn,
                    WebSocketWrapper::MaybeTls(ws_conn), self.analyzer.clone(), self.bridge_settings.clone(), &self.token);
            });
        }
    }
}
