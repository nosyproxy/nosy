//! Encoding helpers shared by the server and the MCP bridge:
//! HTTP content-coding decompression and the Decoder's transformations.

pub mod compression;
pub mod transform;

pub use compression::{dechunk, decode_body};
pub use transform::{Op, TransformError, apply, detect, is_printable, smart_chain};
