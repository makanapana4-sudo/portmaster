use crate::dns_cache::{DnsQueryKey, DnsResponseMetadata};
use std::fmt::Write as _;

/// DNS header length as defined by RFC 1035.
pub const DNS_HEADER_SIZE: usize = 12;

const MAX_DNS_NAME_WIRE_LENGTH: usize = 255;
const MAX_COMPRESSION_JUMPS: usize = 128;

/// Errors returned while parsing DNS wire messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsWireError {
    TruncatedHeader,
    TruncatedName,
    TruncatedQuestion,
    TruncatedRecord,
    InvalidLabelType,
    InvalidCompressionPointer,
    CompressionLoop,
    CompressionLimitExceeded,
    NameTooLong,
    LengthOverflow,
}

impl std::fmt::Display for DnsWireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader => formatter.write_str("DNS message header is truncated"),
            Self::TruncatedName => formatter.write_str("DNS name is truncated"),
            Self::TruncatedQuestion => formatter.write_str("DNS question is truncated"),
            Self::TruncatedRecord => formatter.write_str("DNS resource record is truncated"),
            Self::InvalidLabelType => formatter.write_str("DNS name contains an invalid label type"),
            Self::InvalidCompressionPointer => {
                formatter.write_str("DNS compression pointer is invalid")
            }
            Self::CompressionLoop => formatter.write_str("DNS name contains a compression loop"),
            Self::CompressionLimitExceeded => {
                formatter.write_str("DNS name exceeds the compression jump limit")
            }
            Self::NameTooLong => formatter.write_str("DNS name exceeds 255 wire bytes"),
            Self::LengthOverflow => formatter.write_str("DNS record length overflowed"),
        }
    }
}

impl std::error::Error for DnsWireError {}

/// One DNS question from the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: u16,
    pub class: u16,
}

impl DnsQuestion {
    pub fn cache_key(&self) -> Result<DnsQueryKey, crate::dns_cache::DnsCacheConfigError> {
        DnsQueryKey::new(&self.name, self.record_type)
    }
}

/// Parsed DNS header, first question, section counts and minimum record TTL.
///
/// The minimum TTL covers answer, authority and additional records, matching
/// the current Portmaster resolver's cache-cleaning behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessageMetadata {
    pub id: u16,
    pub flags: u16,
    pub response_code: u16,
    pub question_count: usize,
    pub answer_count: usize,
    pub authority_count: usize,
    pub additional_count: usize,
    pub first_question: Option<DnsQuestion>,
    pub minimum_record_ttl_secs: Option<u32>,
}

impl DnsMessageMetadata {
    /// Converts parsed response properties into the input expected by the DNS
    /// cache's existing TTL policy.
    #[must_use]
    pub const fn cache_metadata(
        &self,
        is_connectivity_domain: bool,
        online: bool,
    ) -> DnsResponseMetadata {
        DnsResponseMetadata {
            rcode: self.response_code,
            answer_count: self.answer_count,
            minimum_record_ttl_secs: self.minimum_record_ttl_secs,
            is_connectivity_domain,
            online,
        }
    }

    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }
}

/// Parses a DNS message without allocating or copying its resource records.
///
/// Domain labels are returned in lowercase ASCII form with a trailing dot.
/// Reserved and non-printable label bytes are represented using the
/// conventional three-digit decimal escape form (for example, \\046).
pub fn parse_dns_message(packet: &[u8]) -> Result<DnsMessageMetadata, DnsWireError> {
    if packet.len() < DNS_HEADER_SIZE {
        return Err(DnsWireError::TruncatedHeader);
    }

    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    let question_count = usize::from(read_u16(packet, 4)?);
    let answer_count = usize::from(read_u16(packet, 6)?);
    let authority_count = usize::from(read_u16(packet, 8)?);
    let additional_count = usize::from(read_u16(packet, 10)?);

    let mut offset = DNS_HEADER_SIZE;
    let mut first_question = None;

    for index in 0..question_count {
        let (name, next_offset) = decode_name(packet, offset)?;
        offset = next_offset;

        let question_end = offset
            .checked_add(4)
            .ok_or(DnsWireError::LengthOverflow)?;
        if question_end > packet.len() {
            return Err(DnsWireError::TruncatedQuestion);
        }

        let question = DnsQuestion {
            name,
            record_type: read_u16(packet, offset)?,
            class: read_u16(packet, offset + 2)?,
        };
        if index == 0 {
            first_question = Some(question);
        }
        offset = question_end;
    }

    let record_count = answer_count
        .checked_add(authority_count)
        .and_then(|count| count.checked_add(additional_count))
        .ok_or(DnsWireError::LengthOverflow)?;

    let mut minimum_record_ttl_secs = None;
    for _ in 0..record_count {
        let record = parse_record(packet, offset)?;
        minimum_record_ttl_secs = Some(
            minimum_record_ttl_secs
                .map_or(record.ttl_secs, |current: u32| current.min(record.ttl_secs)),
        );
        offset = record.next_offset;
    }

    Ok(DnsMessageMetadata {
        id,
        flags,
        response_code: flags & 0x000f,
        question_count,
        answer_count,
        authority_count,
        additional_count,
        first_question,
        minimum_record_ttl_secs,
    })
}

/// Rewrites every answer, authority and additional record TTL in-place.
///
/// The complete packet is validated before any bytes are changed. The record
/// count returned is the number of resource records whose TTL field was
/// rewritten. No DNS record arrays or replacement packet are allocated.
pub fn rewrite_resource_record_ttls(
    packet: &mut [u8],
    ttl_secs: u32,
) -> Result<usize, DnsWireError> {
    let metadata = parse_dns_message(packet)?;
    let mut offset = DNS_HEADER_SIZE;

    for _ in 0..metadata.question_count {
        let (_, next_offset) = decode_name(packet, offset)?;
        offset = next_offset
            .checked_add(4)
            .ok_or(DnsWireError::LengthOverflow)?;
    }

    let record_count = metadata.answer_count
        + metadata.authority_count
        + metadata.additional_count;
    let ttl_bytes = ttl_secs.to_be_bytes();

    for _ in 0..record_count {
        let record = parse_record(packet, offset)?;
        packet[record.ttl_offset..record.ttl_offset + 4].copy_from_slice(&ttl_bytes);
        offset = record.next_offset;
    }

    Ok(record_count)
}

struct ParsedRecord {
    ttl_secs: u32,
    ttl_offset: usize,
    next_offset: usize,
}

fn parse_record(packet: &[u8], start: usize) -> Result<ParsedRecord, DnsWireError> {
    let (_, name_end) = decode_name(packet, start)?;
    let fixed_end = name_end
        .checked_add(10)
        .ok_or(DnsWireError::LengthOverflow)?;
    if fixed_end > packet.len() {
        return Err(DnsWireError::TruncatedRecord);
    }

    let ttl_offset = name_end + 4;
    let ttl_secs = read_u32(packet, ttl_offset)?;
    let data_length = usize::from(read_u16(packet, name_end + 8)?);
    let next_offset = fixed_end
        .checked_add(data_length)
        .ok_or(DnsWireError::LengthOverflow)?;

    if next_offset > packet.len() {
        return Err(DnsWireError::TruncatedRecord);
    }

    Ok(ParsedRecord {
        ttl_secs,
        ttl_offset,
        next_offset,
    })
}

fn decode_name(packet: &[u8], start: usize) -> Result<(String, usize), DnsWireError> {
    let mut cursor = start;
    let mut resume_offset = None;
    let mut jumps = 0;
    let mut visited = [usize::MAX; MAX_COMPRESSION_JUMPS];
    let mut wire_length = 1;
    let mut output = String::new();

    loop {
        let length = *packet.get(cursor).ok_or(DnsWireError::TruncatedName)?;

        match length & 0xc0 {
            0xc0 => {
                let second_offset = cursor
                    .checked_add(1)
                    .ok_or(DnsWireError::LengthOverflow)?;
                let second = *packet
                    .get(second_offset)
                    .ok_or(DnsWireError::TruncatedName)?;
                let target = (usize::from(length & 0x3f) << 8) | usize::from(second);

                if target >= cursor || target >= packet.len() {
                    return Err(DnsWireError::InvalidCompressionPointer);
                }
                if jumps >= MAX_COMPRESSION_JUMPS {
                    return Err(DnsWireError::CompressionLimitExceeded);
                }
                if visited[..jumps].contains(&target) {
                    return Err(DnsWireError::CompressionLoop);
                }

                visited[jumps] = target;
                jumps += 1;
                resume_offset.get_or_insert(cursor + 2);
                cursor = target;
            }
            0x00 => {
                cursor += 1;
                if length == 0 {
                    let next_offset = resume_offset.unwrap_or(cursor);
                    output.push('.');
                    return Ok((output, next_offset));
                }

                if length > 63 {
                    return Err(DnsWireError::InvalidLabelType);
                }

                let label_length = usize::from(length);
                wire_length = wire_length
                    .checked_add(1 + label_length)
                    .ok_or(DnsWireError::LengthOverflow)?;
                if wire_length > MAX_DNS_NAME_WIRE_LENGTH {
                    return Err(DnsWireError::NameTooLong);
                }

                let label_end = cursor
                    .checked_add(label_length)
                    .ok_or(DnsWireError::LengthOverflow)?;
                let label = packet
                    .get(cursor..label_end)
                    .ok_or(DnsWireError::TruncatedName)?;

                if !output.is_empty() {
                    output.push('.');
                }
                append_escaped_label(&mut output, label);
                cursor = label_end;
            }
            _ => return Err(DnsWireError::InvalidLabelType),
        }
    }
}

fn append_escaped_label(output: &mut String, label: &[u8]) {
    for byte in label {
        match *byte {
            b'.' | b'\\' => {
                let _ = write!(output, "\\{:03}", byte);
            }
            0x21..=0x7e => output.push(char::from(byte.to_ascii_lowercase())),
            _ => {
                let _ = write!(output, "\\{:03}", byte);
            }
        }
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, DnsWireError> {
    let end = offset.checked_add(2).ok_or(DnsWireError::LengthOverflow)?;
    let bytes = packet
        .get(offset..end)
        .ok_or(DnsWireError::TruncatedHeader)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, DnsWireError> {
    let end = offset.checked_add(4).ok_or(DnsWireError::LengthOverflow)?;
    let bytes = packet
        .get(offset..end)
        .ok_or(DnsWireError::TruncatedRecord)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn example_message() -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // standard response, no error
            0, 1, // questions
            0, 1, // answers
            0, 1, // authority
            0, 1, // additional
            7, b'E', b'x', b'A', b'M', b'p', b'l', b'e',
            3, b'C', b'o', b'M', 0, // example.com
        ];
        push_u16(&mut packet, 1); // A
        push_u16(&mut packet, 1); // IN

        // Answer owner is compressed to the question name.
        packet.extend_from_slice(&[0xc0, 0x0c]);
        push_u16(&mut packet, 1);
        push_u16(&mut packet, 1);
        push_u32(&mut packet, 30);
        push_u16(&mut packet, 4);
        packet.extend_from_slice(&[1, 2, 3, 4]);

        // Authority NS record, also compressed; TTL is the minimum.
        packet.extend_from_slice(&[0xc0, 0x0c]);
        push_u16(&mut packet, 2);
        push_u16(&mut packet, 1);
        push_u32(&mut packet, 15);
        push_u16(&mut packet, 2);
        packet.extend_from_slice(&[0xc0, 0x0c]);

        // Additional A record for the root name.
        packet.push(0);
        push_u16(&mut packet, 1);
        push_u16(&mut packet, 1);
        push_u32(&mut packet, 60);
        push_u16(&mut packet, 4);
        packet.extend_from_slice(&[8, 8, 8, 8]);

        packet
    }

    #[test]
    fn parses_question_and_minimum_ttl_across_all_record_sections() {
        let packet = example_message();
        let metadata = parse_dns_message(&packet).unwrap();

        assert_eq!(metadata.id, 0x1234);
        assert!(metadata.is_response());
        assert!(!metadata.is_truncated());
        assert_eq!(metadata.response_code, 0);
        assert_eq!(metadata.question_count, 1);
        assert_eq!(metadata.answer_count, 1);
        assert_eq!(metadata.authority_count, 1);
        assert_eq!(metadata.additional_count, 1);
        assert_eq!(
            metadata.first_question,
            Some(DnsQuestion {
                name: "example.com.".to_owned(),
                record_type: 1,
                class: 1,
            })
        );
        assert_eq!(metadata.minimum_record_ttl_secs, Some(15));

        let key = metadata.first_question.unwrap().cache_key().unwrap();
        assert_eq!(key, DnsQueryKey::new("example.com", 1).unwrap());

        let cache_metadata = metadata.cache_metadata(false, true);
        assert_eq!(cache_metadata.answer_count, 1);
        assert_eq!(cache_metadata.minimum_record_ttl_secs, Some(15));
    }

    #[test]
    fn rewrites_ttls_in_all_resource_record_sections() {
        let mut packet = example_message();
        let count = rewrite_resource_record_ttls(&mut packet, 17).unwrap();

        assert_eq!(count, 3);
        assert_eq!(parse_dns_message(&packet).unwrap().minimum_record_ttl_secs, Some(17));
    }

    #[test]
    fn rejects_truncated_header_and_record_data() {
        assert_eq!(
            parse_dns_message(&[0; DNS_HEADER_SIZE - 1]).err(),
            Some(DnsWireError::TruncatedHeader)
        );

        let mut packet = example_message();
        let final_rdlength_offset = packet.len() - 6;
        packet[final_rdlength_offset..final_rdlength_offset + 2]
            .copy_from_slice(&100_u16.to_be_bytes());

        assert_eq!(
            parse_dns_message(&packet).err(),
            Some(DnsWireError::TruncatedRecord)
        );
    }

    #[test]
    fn rejects_self_referencing_compression_pointer() {
        let mut packet = vec![0; DNS_HEADER_SIZE];
        packet[4..6].copy_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c]);

        assert_eq!(
            parse_dns_message(&packet).err(),
            Some(DnsWireError::InvalidCompressionPointer)
        );
    }

    #[test]
    fn handles_empty_question_section() {
        let packet = vec![0; DNS_HEADER_SIZE];
        let metadata = parse_dns_message(&packet).unwrap();

        assert_eq!(metadata.question_count, 0);
        assert_eq!(metadata.first_question, None);
        assert_eq!(metadata.minimum_record_ttl_secs, None);
    }

    #[test]
    fn malformed_packet_is_not_partially_rewritten() {
        let mut packet = example_message();
        let original = packet.clone();
        let last = packet.len() - 1;
        packet.truncate(last);

        let before_rewrite = packet.clone();
        assert!(rewrite_resource_record_ttls(&mut packet, 17).is_err());
        assert_eq!(packet, before_rewrite);
        assert_ne!(packet, original);
    }


    #[test]
    fn inserts_wire_response_and_prepares_client_copy_with_ttls() {
        let packet = example_message();
        let mut cache = crate::dns_cache::DnsCache::new(
            8,
            crate::dns_cache::DnsCachePolicy::default(),
        )
        .unwrap();

        assert!(cache
            .insert_dns_wire_response(packet.clone(), false, true, false, 10_000)
            .unwrap());

        let question = DnsQueryKey::new("example.com", 1).unwrap();
        let entry = cache.lookup(&question, 10_001, false, false).unwrap().entry;
        assert_eq!(parse_dns_message(entry.payload()).unwrap().minimum_record_ttl_secs, Some(15));

        let client_response = entry.prepare_client_response().unwrap();
        assert_eq!(
            parse_dns_message(&client_response).unwrap().minimum_record_ttl_secs,
            Some(17)
        );
        assert_eq!(parse_dns_message(&packet).unwrap().minimum_record_ttl_secs, Some(15));
    }

    #[test]
    fn wire_cache_rejects_queries_and_truncated_responses() {
        let mut cache = crate::dns_cache::DnsCache::new(
            4,
            crate::dns_cache::DnsCachePolicy::default(),
        )
        .unwrap();

        let query = {
            let mut packet = example_message();
            packet[2] = 0;
            packet[3] = 0;
            packet
        };
        assert_eq!(
            cache.insert_dns_wire_response(query, false, true, false, 1),
            Err(crate::dns_cache::DnsWireCacheError::NotAResponse)
        );

        let truncated = {
            let mut packet = example_message();
            packet[2] |= 0x02;
            packet
        };
        assert_eq!(
            cache.insert_dns_wire_response(truncated, false, true, false, 1),
            Err(crate::dns_cache::DnsWireCacheError::TruncatedResponse)
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn escapes_reserved_label_bytes() {
        let mut packet = vec![0; DNS_HEADER_SIZE];
        packet[4..6].copy_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&[3, b'a', b'.', b'b', 0]);
        push_u16(&mut packet, 1);
        push_u16(&mut packet, 1);

        let metadata = parse_dns_message(&packet).unwrap();
        assert_eq!(
            metadata.first_question.unwrap().name,
            "a\\046b."
        );
    }
}
