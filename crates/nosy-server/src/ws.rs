//! Live updates. Events are coalesced server-side (every 50 ms at most) so a
//! burst of traffic becomes a handful of messages instead of thousands.

use std::{collections::HashMap, time::Duration};

use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
};
use nosy_model::{FlowSummary, WsEvent};
use tokio::sync::broadcast::error::RecvError;

use crate::state::AppState;

pub async fn handler(ws: WebSocketUpgrade, State(s): State<AppState>) -> Response {
    let rx = s.store.subscribe();
    ws.on_upgrade(move |socket| run(socket, rx))
}

#[derive(Default)]
struct Pending {
    flows: Vec<FlowSummary>,
    index: HashMap<i64, usize>,
    /// Non-flow events, in order; pending flows are flushed before each.
    out: Vec<WsEvent>,
}

impl Pending {
    fn push(&mut self, ev: WsEvent) {
        match ev {
            WsEvent::Flows { flows } => {
                for f in flows {
                    match self.index.get(&f.id) {
                        Some(&i) => self.flows[i] = f,
                        None => {
                            self.index.insert(f.id, self.flows.len());
                            self.flows.push(f);
                        }
                    }
                }
            }
            other => {
                self.flush_flows();
                self.out.push(other);
            }
        }
    }

    fn flush_flows(&mut self) {
        if !self.flows.is_empty() {
            self.index.clear();
            self.out.push(WsEvent::Flows {
                flows: std::mem::take(&mut self.flows),
            });
        }
    }

    fn is_empty(&self) -> bool {
        self.flows.is_empty() && self.out.is_empty()
    }

    fn reset(&mut self) {
        self.flows.clear();
        self.index.clear();
        self.out.clear();
    }
}

async fn run(mut socket: WebSocket, mut rx: tokio::sync::broadcast::Receiver<WsEvent>) {
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut pending = Pending::default();

    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(ev) => pending.push(ev),
                Err(RecvError::Lagged(_)) => {
                    pending.reset();
                    pending.out.push(WsEvent::Resync);
                }
                Err(RecvError::Closed) => break,
            },
            _ = tick.tick(), if !pending.is_empty() => {
                pending.flush_flows();
                for ev in pending.out.drain(..) {
                    let Ok(text) = serde_json::to_string(&ev) else { continue };
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        return;
                    }
                }
            }
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
        }
    }
}
