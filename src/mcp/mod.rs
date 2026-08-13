//! MCP 2025-06-18 transport exposing protocol-compatible `recall` and
//! `remember` tools.

mod protocol;
mod server;
mod tools;

pub use protocol::{JsonRpcError, JsonRpcResponse};
pub use server::{McpServer, PROTOCOL_VERSION};
pub use tools::{recall_tool, remember_tool, tool_list};

#[cfg(test)]
mod tests;
