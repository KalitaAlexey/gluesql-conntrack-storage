use std::net::IpAddr;

use conntrack::model::Flow;
use enum_all_variants::AllVariants;
use gluesql::core::ast::{ColumnDef, DataType};
use gluesql::core::data::Value;

#[derive(AllVariants, Clone, Copy, Debug)]
pub(crate) enum Column {
    Id,
    OrigSrc,
    OrigDst,
    OrigProtoNum,
    OrigProtoSrcPort,
    OrigProtoDstPort,
    ReplySrc,
    ReplyDst,
    ReplyProtoNum,
    ReplyProtoSrcPort,
    ReplyProtoDstPort,
}

impl Column {
    pub(crate) fn add_field(&self, flow: &Flow, fields: &mut Vec<Value>) {
        fn add_field<T, F>(value: Option<T>, convert: F, fields: &mut Vec<Value>)
        where
            F: FnOnce(T) -> Value,
        {
            fields.push(value.map(convert).unwrap_or(Value::Null));
        }

        fn add_ip_addr(value: Option<IpAddr>, fields: &mut Vec<Value>) {
            add_field(value, Value::Inet, fields);
        }

        fn add_u8(value: Option<u8>, fields: &mut Vec<Value>) {
            add_field(value, Value::U8, fields);
        }

        fn add_u16(value: Option<u16>, fields: &mut Vec<Value>) {
            add_field(value, Value::U16, fields);
        }

        fn add_u32(value: Option<u32>, fields: &mut Vec<Value>) {
            add_field(value, Value::U32, fields);
        }

        match (self, flow) {
            (Column::Id, flow) => {
                add_u32(flow.id, fields);
            }
            (Column::OrigSrc, Flow { origin: flow, .. })
            | (Column::ReplySrc, Flow { reply: flow, .. }) => {
                add_ip_addr(flow.as_ref().and_then(|x| x.src), fields);
            }
            (Column::OrigDst, Flow { origin: flow, .. })
            | (Column::ReplyDst, Flow { reply: flow, .. }) => {
                add_ip_addr(flow.as_ref().and_then(|x| x.dst), fields);
            }
            (Column::OrigProtoNum, Flow { origin: flow, .. })
            | (Column::ReplyProtoNum, Flow { reply: flow, .. }) => add_u8(
                flow.as_ref()
                    .and_then(|x| x.proto.as_ref())
                    .and_then(|x| x.number)
                    .map(u8::from),
                fields,
            ),
            (Column::OrigProtoSrcPort, Flow { origin: flow, .. })
            | (Column::ReplyProtoSrcPort, Flow { reply: flow, .. }) => {
                add_u16(
                    flow.as_ref()
                        .and_then(|x| x.proto.as_ref())
                        .and_then(|x| x.src_port),
                    fields,
                );
            }
            (Column::OrigProtoDstPort, Flow { origin: flow, .. })
            | (Column::ReplyProtoDstPort, Flow { reply: flow, .. }) => {
                add_u16(
                    flow.as_ref()
                        .and_then(|x| x.proto.as_ref())
                        .and_then(|x| x.dst_port),
                    fields,
                );
            }
        }
    }

    pub(crate) fn def(&self) -> ColumnDef {
        let data_type = match self {
            Column::Id => DataType::Uint32,
            Column::OrigSrc | Column::OrigDst | Column::ReplySrc | Column::ReplyDst => {
                DataType::Inet
            }
            Column::OrigProtoNum | Column::ReplyProtoNum => DataType::Uint8,
            Column::OrigProtoSrcPort
            | Column::OrigProtoDstPort
            | Column::ReplyProtoSrcPort
            | Column::ReplyProtoDstPort => DataType::Uint16,
        };
        ColumnDef {
            name: self.name().to_owned(),
            data_type,
            nullable: true,
            default: None,
            unique: None,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        match self {
            Column::Id => "id",
            Column::OrigSrc => "orig_ipv4_src",
            Column::OrigDst => "orig_ipv4_dst",
            Column::OrigProtoNum => "orig_l4_proto",
            Column::OrigProtoSrcPort => "orig_l4_src_port",
            Column::OrigProtoDstPort => "orig_l4_dst_port",
            Column::ReplySrc => "reply_ipv4_src",
            Column::ReplyDst => "reply_ipv4_dst",
            Column::ReplyProtoNum => "reply_l4_proto",
            Column::ReplyProtoSrcPort => "reply_l4_src_port",
            Column::ReplyProtoDstPort => "reply_l4_dst_port",
        }
    }
}
