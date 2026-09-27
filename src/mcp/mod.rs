//! MCP stdio and Streamable HTTP transports for `recall` and `remember`.

pub mod http;
pub(crate) mod protocol;
pub mod scopes;
mod server;
mod telemetry;
mod tools;

pub use protocol::{JsonRpcError, JsonRpcResponse, MODERN_PROTOCOL_VERSION};
pub use server::{MAX_MCP_FRAME_BYTES, McpServer, PROTOCOL_VERSION, REQUEST_DEADLINE};
pub use tools::{
    recall_tool, recall_tool_for, recall_tool_for_surfaces, remember_tool, remember_tool_for,
    tool_list, tool_list_for, tool_list_for_surfaces,
};

#[cfg(test)]
mod tests;
