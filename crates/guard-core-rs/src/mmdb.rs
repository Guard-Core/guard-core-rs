//! A minimal, dependency-free `MaxMind MMDB` reader.
//!
//! The module implements the subset of the
//! [MaxMind DB file format](https://maxmind.github.io/MaxMind-DB/) the
//! engine needs for geo blocking, mirroring the PHP family's hand-written
//! decoder (`guard-core-php/src/GeoIp/MmdbReader.php` + `MmdbDecoder.php`)
//! and standing in for the reference's `maxminddb` Python library
//! (`guard_core/handlers/ipinfo_handler.py` reads the `country` key of the
//! ipinfo `country_asn.mmdb` record map; this module reads the same key).
//!
//! The download side already ships: [`crate::cloud_fetch::CloudFetcher::fetch_geo_database`]
//! fetches the `country_asn.mmdb` bytes; this module is what parses them:
//!
//! - the metadata block (located by the `\xAB\xCD\xEFMaxMind.com` marker,
//!   decoded as a data-section map),
//! - a binary search over the record-size 24/28/32 search tree (IPv4 and
//!   IPv6 trees, the IPv4-in-IPv6 mapped prefix included),
//! - a full data-section decoder (pointers, extended types, maps, arrays,
//!   strings, doubles, floats, unsigned integers, int32, booleans).
//!
//! Only well-formed databases are supported; any structural surprise is an
//! [`MmdbError`] so the host can fail soft exactly like the PHP reader's
//! `MmdbError` and the reference's missing-database soft path.
//!
//! Two deliberate divergences from the PHP sibling (both spec-correct
//! here): the extended-type size stays in the FIRST control byte's five
//! bits (the PHP decoder takes it from the type byte's low three bits,
//! which misreads extended-type payloads of 8-28 bytes), and pointer
//! sizes 1/2 add their spec offsets (2048 / 526336, which the PHP decoder
//! drops, misreading 19-bit and 27-bit pointers). The decoder is verified
//! against generated fixtures covering both paths.
//!
//! The reader implements [`GeoIpHandler`](guard_core_engine::geo::GeoIpHandler)
//! (resolving the record map's `country` ISO code), so it plugs straight
//! into a [`GeoStage`](crate::geo::GeoStage):
//!
//! ```
//! use guard_core_rs::mmdb::Mmdb;
//!
//! // A generated two-node IPv4 test fixture (layout documented in
//! // `mmdb::test_fixtures`): 192.0.2.0/24 -> {"country": "US"},
//! // everything else -> not found.
//! let bytes = guard_core_rs::mmdb::test_fixtures::country_fixture();
//! let mmdb = Mmdb::from_bytes(&bytes).expect("valid fixture");
//!
//! assert_eq!(
//!     mmdb.lookup_country("192.0.2.9".parse().expect("ip")).expect("lookup"),
//!     Some("US".to_owned())
//! );
//! assert_eq!(
//!     mmdb.lookup_country("198.51.100.9".parse().expect("ip")).expect("lookup"),
//!     None
//! );
//! ```

use std::fmt;
use std::net::IpAddr;

use guard_core_engine::geo::GeoIpHandler;

/// The metadata marker that ends the search tree
/// (`METADATA_MARKER` in the PHP reader; the `MaxMind` spec's
/// "metadata section marker" constant).
const METADATA_MARKER: &[u8; 14] = b"\xAB\xCD\xEFMaxMind.com";

/// The 16-byte separator between the search tree and the data section
/// (`DATA_SEPARATOR_SIZE`; the spec's null-byte + data-section-separator).
const DATA_SEPARATOR_SIZE: usize = 16;

/// One decoded MMDB value (the subset of the spec's data types the
/// country databases carry).
#[derive(Debug, Clone, PartialEq)]
pub enum MmdbValue {
    /// UTF-8 string (type 2).
    String(String),
    /// Opaque bytes (type 4).
    Bytes(Vec<u8>),
    /// IEEE 754 double (type 3).
    Double(f64),
    /// IEEE 754 float (type 15).
    Float(f32),
    /// Unsigned integer (types 5, 6, 9, 10, up to uint128).
    UInt(u128),
    /// Signed 32-bit integer (type 8).
    Int(i32),
    /// Boolean (type 14).
    Bool(bool),
    /// Map (type 7); insertion order preserved.
    Map(Vec<(String, Self)>),
    /// Array (type 11).
    Array(Vec<Self>),
}

impl MmdbValue {
    /// The value of `key` when this value is a map (first match wins).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Map(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// The string content of this value (`String` only).
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

/// A structural MMDB failure (the PHP reader's `MmdbError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmdbError(pub String);

impl fmt::Display for MmdbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for MmdbError {}

/// The parsed reader: the database bytes plus the metadata block's three
/// routing fields (the PHP reader's private state).
#[derive(Debug, Clone)]
pub struct Mmdb {
    data: Vec<u8>,
    node_count: usize,
    record_size: u32,
    ip_version: u32,
    /// The data section's absolute start: the tree (two records per node,
    /// each `record_size / 8` bytes) plus the 16-byte separator.
    data_section_start: usize,
}

impl Mmdb {
    /// Parse an in-memory database (`MmdbReader::__construct`).
    ///
    /// # Errors
    ///
    /// [`MmdbError`] when the bytes are not an MMDB database, the metadata
    /// is malformed, or the record size is not 24/28/32.
    pub fn from_bytes(data: &[u8]) -> Result<Self, MmdbError> {
        let marker = data
            .windows(METADATA_MARKER.len())
            .rposition(|window| window == METADATA_MARKER)
            .ok_or_else(|| MmdbError("not an MMDB database".to_owned()))?;

        let metadata_start = marker + METADATA_MARKER.len();
        let metadata = Decoder::new(data, metadata_start).decode()?;
        let read_usize = |key: &str| -> Result<usize, MmdbError> {
            match metadata.get(key) {
                Some(MmdbValue::UInt(value)) if *value <= usize::MAX as u128 => Ok(*value as usize),
                _ => Err(MmdbError(format!("malformed MMDB metadata: missing {key}"))),
            }
        };
        let node_count = read_usize("node_count")?;
        let record_size = u32::try_from(read_usize("record_size")?)
            .map_err(|_| MmdbError("malformed MMDB metadata: record_size".to_owned()))?;
        let ip_version = read_usize("ip_version")?;
        if !matches!(record_size, 24 | 28 | 32) {
            return Err(MmdbError(format!(
                "unsupported MMDB record size {record_size}"
            )));
        }

        let record_bytes = (record_size / 8) as usize;
        let tree_size = node_count * record_bytes * 2;
        Ok(Self {
            data: data.to_vec(),
            node_count,
            record_size,
            ip_version: u32::try_from(ip_version)
                .map_err(|_| MmdbError("malformed MMDB metadata: ip_version".to_owned()))?,
            data_section_start: tree_size + DATA_SEPARATOR_SIZE,
        })
    }

    /// Read a database file (`MmdbReader::__construct` with
    /// `file_get_contents`).
    ///
    /// # Errors
    ///
    /// [`MmdbError`] when the file cannot be read or does not parse.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, MmdbError> {
        let data = std::fs::read(path.as_ref())
            .map_err(|error| MmdbError(format!("unable to read MMDB file: {error}")))?;
        Self::from_bytes(&data)
    }

    /// The metadata node count (the reference `entry_count`).
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.node_count
    }

    /// The metadata `ip_version` (4 or 6).
    #[must_use]
    pub const fn ip_version(&self) -> u32 {
        self.ip_version
    }

    /// The decoded record map for `ip`, `None` when the address falls
    /// outside the database (`MmdbReader::lookup`).
    ///
    /// # Errors
    ///
    /// [`MmdbError`] when the search tree is truncated.
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<MmdbValue>, MmdbError> {
        let packed = pack_address(ip, self.ip_version)?;
        let record_bytes = (self.record_size / 8) as usize;

        let mut node = 0usize;
        let total_bits = packed.len() * 8;
        for bit_index in 0..total_bits {
            if node >= self.node_count {
                break;
            }
            let bit = (packed[bit_index >> 3] >> (7 - (bit_index & 7))) & 1;
            node = self.read_node_record(node, bit == 1, record_bytes)?;
        }

        if node == self.node_count {
            return Ok(None); // not found
        }
        if node > self.node_count {
            // The record is a data-section pointer: the value minus the
            // node count minus the separator is the offset into the data
            // section, which starts at `tree_size + 16`.
            let offset = node - self.node_count - DATA_SEPARATOR_SIZE;
            let decoded = Decoder::new(&self.data, self.data_section_start).decode_at(offset)?;
            return Ok(Some(decoded));
        }
        Ok(None) // a middle-of-tree node with no record: not found
    }

    /// The record map's `country` ISO 3166-1 alpha-2 code, the field the
    /// reference `IPInfoManager.get_country` reads
    /// (`result.get("country")`).
    ///
    /// # Errors
    ///
    /// [`MmdbError`] when the search tree is truncated.
    pub fn lookup_country(&self, ip: IpAddr) -> Result<Option<String>, MmdbError> {
        let Some(record) = self.lookup(ip)? else {
            return Ok(None);
        };
        Ok(record
            .get("country")
            .and_then(MmdbValue::as_str)
            .map(str::to_owned))
    }

    /// One node record (`readNodeRecord`): the left (bit 0) or right
    /// (bit 1) record of `node`, big-endian over `record_bytes` bytes.
    fn read_node_record(
        &self,
        node: usize,
        right: bool,
        record_bytes: usize,
    ) -> Result<usize, MmdbError> {
        let offset = node * record_bytes * 2 + usize::from(right) * record_bytes;
        let bytes = self
            .data
            .get(offset..offset + record_bytes)
            .ok_or_else(|| MmdbError("truncated MMDB search tree".to_owned()))?;
        let mut value = 0usize;
        for byte in bytes {
            value = (value << 8) | usize::from(*byte);
        }
        Ok(value)
    }
}

impl GeoIpHandler for Mmdb {
    fn get_country(&self, ip: IpAddr) -> Option<String> {
        // Fail soft: an unreadable database answers "unresolved", the
        // reference's missing-file path, instead of poisoning the gate.
        self.lookup_country(ip).unwrap_or(None)
    }
}

/// Pack an address for the tree walk: 4 bytes for an IPv4 database, 16 for
/// an IPv6 database, and the IPv4-mapped prefix
/// (`::ffff:0:0/96`, 12 zero bytes) when an IPv4 address walks an IPv6
/// tree (the `MaxMind` convention, the PHP reader's `str_repeat`).
fn pack_address(ip: IpAddr, ip_version: u32) -> Result<Vec<u8>, MmdbError> {
    match (ip, ip_version) {
        (IpAddr::V4(v4), 4) => Ok(v4.octets().to_vec()),
        (IpAddr::V4(v4), 6) => {
            let mut packed = vec![0u8; 12];
            packed.extend_from_slice(&v4.octets());
            Ok(packed)
        }
        (IpAddr::V6(v6), 6) => Ok(v6.octets().to_vec()),
        (IpAddr::V6(_), 4) => Err(MmdbError(
            "IPv6 address against an IPv4-only database".to_owned(),
        )),
        (_, version) => Err(MmdbError(format!("unsupported MMDB ip_version {version}"))),
    }
}

/// The data-section decoder over a fixed byte buffer
/// (`MmdbDecoder`): the control byte carries the type in its top three
/// bits and the size in its bottom five; type 0 is the extended-type
/// marker (the next byte holds type minus 7 in its top five bits and the
/// size in its bottom three) and type 1 is a pointer (the size field is
/// repurposed: top two bits select the additional byte width, bottom
/// three bits start the value).
struct Decoder<'a> {
    data: &'a [u8],
    base: usize,
}

impl<'a> Decoder<'a> {
    const fn new(data: &'a [u8], base: usize) -> Self {
        Self { data, base }
    }

    /// Decode the value at the decoder base (`decode`).
    fn decode(&self) -> Result<MmdbValue, MmdbError> {
        self.decode_at(0)
    }

    /// Decode the value at `offset` relative to the decoder base
    /// (`decodeAt`).
    fn decode_at(&self, offset: usize) -> Result<MmdbValue, MmdbError> {
        let mut cursor = 0usize;
        self.read_value(self.base + offset, &mut cursor)
    }

    #[allow(clippy::too_many_lines)] // the decoder arms mirror the spec's type table
    fn read_value(&self, start: usize, cursor: &mut usize) -> Result<MmdbValue, MmdbError> {
        let mut offset = start;
        let ctrl = self.byte_at(offset)?;
        offset += 1;
        let mut size = usize::from(ctrl & 0x1f);
        let kind = match ctrl >> 5 {
            0 => {
                // Extended type: the next byte carries the type (minus 7);
                // the payload size stays in the first control byte's five
                // bits (the spec's `00000011 00000011` uint128 example).
                let extended = self.byte_at(offset)?;
                offset += 1;
                usize::from(extended) + 7
            }
            other => usize::from(other),
        };

        if kind == 1 {
            // Pointer record (`001SSVVV`): the two S bits pick the width
            // and the value offset (0 / 2048 / 526336 / raw 32-bit), the
            // three V bits start the value; only the pointer bytes are
            // consumed from the stream and the aliased value is decoded
            // in place.
            let size_bits = (size >> 3) & 0x3;
            let width = size_bits + 1;
            let mut value = size & 0x7;
            for _ in 0..width {
                value = (value << 8) | usize::from(self.byte_at(offset)?);
                offset += 1;
            }
            value += match size_bits {
                1 => 2048,
                2 => 526_336,
                _ => 0,
            };
            *cursor = offset;
            let mut pointer_cursor = 0usize;
            return self.read_value(self.base + value, &mut pointer_cursor);
        }

        if size >= 29 {
            // The size field is exhausted: the extension bytes are added
            // to the spec's fixed base (29 + byte, 285 + u16,
            // 65821 + u24).
            let (width, base) = match size {
                29 => (1usize, 29usize),
                30 => (2, 285),
                _ => (3, 65_821),
            };
            let mut extension = 0usize;
            for _ in 0..width {
                extension = (extension << 8) | usize::from(self.byte_at(offset)?);
                offset += 1;
            }
            size = base + extension;
        }

        let value = match kind {
            2 | 4 => {
                // String / bytes.
                let bytes = self.slice(offset, size)?;
                offset += size;
                if kind == 2 {
                    MmdbValue::String(
                        String::from_utf8(bytes.to_vec())
                            .map_err(|_| MmdbError("invalid UTF-8 string".to_owned()))?,
                    )
                } else {
                    MmdbValue::Bytes(bytes.to_vec())
                }
            }
            3 => {
                let bytes = self.slice(offset, 8)?;
                offset += 8;
                MmdbValue::Double(f64::from_be_bytes(bytes.try_into().expect("8 bytes")))
            }
            15 => {
                let bytes = self.slice(offset, 4)?;
                offset += 4;
                MmdbValue::Float(f32::from_be_bytes(bytes.try_into().expect("4 bytes")))
            }
            5 | 6 | 9 | 10 => {
                let bytes = self.slice(offset, size)?;
                offset += size;
                let mut value = 0u128;
                for byte in bytes {
                    value = (value << 8) | u128::from(*byte);
                }
                MmdbValue::UInt(value)
            }
            8 => {
                let bytes = self.slice(offset, size)?;
                offset += size;
                let mut value = 0u32;
                for byte in bytes {
                    value = (value << 8) | u32::from(*byte);
                }
                // Sign-extended 32 bit (the spec's int32).
                MmdbValue::Int(value.cast_signed())
            }
            7 => {
                let mut map = Vec::new();
                for _ in 0..size {
                    let key = self.read_value(offset, &mut offset)?;
                    let value = self.read_value(offset, &mut offset)?;
                    map.push((key.as_str().unwrap_or_default().to_owned(), value));
                }
                MmdbValue::Map(map)
            }
            11 => {
                let mut array = Vec::new();
                for _ in 0..size {
                    array.push(self.read_value(offset, &mut offset)?);
                }
                MmdbValue::Array(array)
            }
            14 => MmdbValue::Bool(size == 1),
            other => {
                return Err(MmdbError(format!("unsupported MMDB data type {other}")));
            }
        };
        *cursor = offset;
        Ok(value)
    }

    fn byte_at(&self, offset: usize) -> Result<u8, MmdbError> {
        self.data
            .get(offset)
            .copied()
            .ok_or_else(|| MmdbError("truncated MMDB data section".to_owned()))
    }

    fn slice(&self, offset: usize, size: usize) -> Result<&'a [u8], MmdbError> {
        self.data
            .get(offset..offset + size)
            .ok_or_else(|| MmdbError("truncated MMDB data section".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::{Value, build_database, country_fixture, dual_version_fixture};
    use super::{Mmdb, MmdbError, MmdbValue};
    use std::net::IpAddr;
    use std::str::FromStr;

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    #[test]
    fn parses_the_metadata_block() {
        let mmdb = Mmdb::from_bytes(&country_fixture()).expect("valid fixture");
        // A /24 route is a 24-deep node chain (root + 23 children).
        assert_eq!(mmdb.node_count(), 24);
        assert_eq!(mmdb.ip_version(), 4);
    }

    #[test]
    fn rejects_non_mmdb_bytes() {
        assert_eq!(
            Mmdb::from_bytes(b"definitely not a database").unwrap_err(),
            MmdbError("not an MMDB database".to_owned())
        );
    }

    #[test]
    fn rejects_truncated_bytes_after_the_marker() {
        // The marker present, but nothing after it.
        let mut bytes = country_fixture();
        bytes.truncate(bytes.len() - 10);
        assert!(Mmdb::from_bytes(&bytes).is_err());
    }

    #[test]
    fn resolves_the_country_record_inside_the_prefix() {
        let mmdb = Mmdb::from_bytes(&country_fixture()).expect("valid fixture");
        assert_eq!(
            mmdb.lookup_country(ip("192.0.2.9")).expect("lookup"),
            Some("US".to_owned())
        );
        // The last address of the prefix resolves too.
        assert_eq!(
            mmdb.lookup_country(ip("192.0.2.255")).expect("lookup"),
            Some("US".to_owned())
        );
    }

    #[test]
    fn addresses_outside_the_database_are_not_found() {
        let mmdb = Mmdb::from_bytes(&country_fixture()).expect("valid fixture");
        assert_eq!(
            mmdb.lookup_country(ip("198.51.100.9")).expect("lookup"),
            None
        );
        assert_eq!(mmdb.lookup_country(ip("127.0.0.1")).expect("lookup"), None);
    }

    #[test]
    fn reads_the_full_record_map() {
        let mmdb = Mmdb::from_bytes(&country_fixture()).expect("valid fixture");
        let record = mmdb
            .lookup(ip("192.0.2.1"))
            .expect("lookup")
            .expect("record");
        assert_eq!(
            record.get("country").and_then(MmdbValue::as_str),
            Some("US")
        );
        assert_eq!(record.get("as_num"), Some(&MmdbValue::UInt(65_512)));
        assert!(record.get("missing").is_none());
    }

    #[test]
    fn ipv4_in_an_ipv6_database_walks_the_mapped_prefix() {
        let mmdb = Mmdb::from_bytes(&dual_version_fixture()).expect("valid fixture");
        assert_eq!(
            mmdb.lookup_country(ip("192.0.2.9")).expect("lookup"),
            Some("US".to_owned())
        );
        assert_eq!(
            mmdb.lookup_country(ip("2001:db8::1")).expect("lookup"),
            Some("DE".to_owned())
        );
        assert_eq!(
            mmdb.lookup_country(ip("2001:db9::1")).expect("lookup"),
            None
        );
        // An IPv6 database rejects nothing here; the mapped prefix covers
        // IPv4, other v6 space falls through to not found.
    }

    #[test]
    fn ipv6_against_an_ipv4_database_is_an_error() {
        let mmdb = Mmdb::from_bytes(&country_fixture()).expect("valid fixture");
        assert!(mmdb.lookup(ip("2001:db8::1")).is_err());
    }

    #[test]
    fn every_record_size_walks_the_same_tree() {
        for record_size in [24u32, 28, 32] {
            let bytes = build_database(
                record_size,
                4,
                &[("192.0.2.0/24", vec![("country", Value::Str("US"))])],
            );
            let mmdb = Mmdb::from_bytes(&bytes).expect("valid fixture");
            assert_eq!(
                mmdb.lookup_country(ip("192.0.2.1")).expect("lookup"),
                Some("US".to_owned()),
                "record size {record_size}"
            );
        }
    }

    #[test]
    fn large_strings_use_the_extended_size_encoding() {
        // A record whose string value exceeds 28 bytes exercises the
        // size 29/30/31 extension path.
        let long_iso_note = "x".repeat(400);
        let mut entries: Vec<(&str, Value)> = Vec::new();
        entries.push(("country", Value::Str("US")));
        // The fixture vocabulary is &'static str only, so the long value
        // rides a leaked allocation.
        let leaked: &'static str = Box::leak(long_iso_note.into_boxed_str());
        entries.push(("note", Value::Str(leaked)));
        let bytes = build_database(24, 4, &[("192.0.2.0/24", entries)]);
        let mmdb = Mmdb::from_bytes(&bytes).expect("valid fixture");
        let record = mmdb
            .lookup(ip("192.0.2.1"))
            .expect("lookup")
            .expect("record");
        match record.get("note") {
            Some(MmdbValue::String(value)) => assert_eq!(value.len(), 400),
            other => panic!("expected the long string, got {other:?}"),
        }
    }

    #[test]
    fn pointers_alias_their_target_value() {
        // The pointer fixture aliases the second network's record onto the
        // first through a data-section pointer.
        let bytes = super::test_fixtures::pointer_fixture();
        let mmdb = Mmdb::from_bytes(&bytes).expect("valid fixture");
        assert_eq!(
            mmdb.lookup_country(ip("192.0.2.1")).expect("lookup"),
            Some("US".to_owned())
        );
        assert_eq!(
            mmdb.lookup_country(ip("198.51.100.1")).expect("lookup"),
            Some("US".to_owned())
        );
    }

    #[test]
    fn the_geo_handler_seam_fails_soft() {
        let mmdb = Mmdb::from_bytes(&country_fixture()).expect("valid fixture");
        assert_eq!(
            guard_core_engine::geo::GeoIpHandler::get_country(&mmdb, ip("192.0.2.9")),
            Some("US".to_owned())
        );
        assert_eq!(
            guard_core_engine::geo::GeoIpHandler::get_country(&mmdb, ip("10.0.0.1")),
            None
        );
    }
}

/// Deterministic MMDB fixtures for the test suite and doc examples.
///
/// The ecosystem ships no test database file (`MaxMind`'s test databases
/// carry a share-alike license), so the fixtures are generated here; the
/// byte layout this module writes IS the documented source of every test
/// database used in this suite.
pub mod test_fixtures {
    /// A minimal IPv4 database: `192.0.2.0/24 -> {"country": "US",
    /// "as_num": 64512}`, everything else not found.
    #[must_use]
    pub fn country_fixture() -> Vec<u8> {
        build_database(
            24,
            4,
            &[(
                "192.0.2.0/24",
                vec![
                    ("country", Value::Str("US")),
                    ("as_num", Value::UInt(65_512)),
                ],
            )],
        )
    }

    /// An IPv6 database carrying an IPv4 record (resolved through the
    /// mapped prefix) and an IPv6 one.
    #[must_use]
    pub fn dual_version_fixture() -> Vec<u8> {
        build_database(
            32,
            6,
            &[
                ("192.0.2.0/24", vec![("country", Value::Str("US"))]),
                ("2001:db8::/32", vec![("country", Value::Str("DE"))]),
            ],
        )
    }

    /// A database whose second network aliases the first record through a
    /// data-section pointer.
    #[must_use]
    pub fn pointer_fixture() -> Vec<u8> {
        let first = ("192.0.2.0/24", vec![("country", Value::Str("US"))]);
        let second = ("198.51.100.0/24", vec![("country", Value::Str("US"))]);
        // Both records encode identically, so the writer emits the second
        // as a pointer to the first (the dedup pass below).
        build_database(24, 4, &[first, second])
    }

    /// The fixture record value vocabulary.
    #[derive(Clone)]
    pub enum Value {
        /// A string field.
        Str(&'static str),
        /// An unsigned integer field.
        UInt(u128),
    }

    /// A minimal big-endian byte writer over the spec's encodings.
    struct Writer {
        bytes: Vec<u8>,
    }

    impl Writer {
        const fn new() -> Self {
            Self { bytes: Vec::new() }
        }

        fn push(&mut self, bytes: &[u8]) {
            self.bytes.extend_from_slice(bytes);
        }

        fn string(&mut self, value: &str) {
            self.payload(2, value.len());
            self.push(value.as_bytes());
        }

        fn uint(&mut self, value: u128) {
            let be = value.to_be_bytes();
            let first = be
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(be.len() - 1);
            let payload = &be[first..];
            let kind = match payload.len() {
                0..=2 => 5u8, // uint16
                3..=4 => 6,   // uint32
                5..=8 => 9,   // uint64
                _ => 10,      // uint128
            };
            self.payload(kind, payload.len());
            self.push(payload);
        }

        fn map(&mut self, entries: usize) {
            self.payload(7, entries);
        }

        /// Write the control byte(s) per the spec: the first control byte
        /// always carries the size in its five low bits (with the 29/30/31
        /// escape), and extended types (>= 7) add a second byte holding
        /// the type minus 7.
        fn payload(&mut self, kind: u8, size: usize) {
            let header = |bytes: &mut Vec<u8>, size: u8| {
                if kind >= 7 {
                    bytes.push(size);
                    bytes.push(kind - 7);
                } else {
                    bytes.push((kind << 5) | size);
                }
            };
            if size < 29 {
                header(&mut self.bytes, size as u8);
            } else {
                // The escape: 29 + byte, 285 + u16, 65821 + u24.
                let (escape, width, extension) = if size - 29 < 256 {
                    (29u8, 1usize, size - 29)
                } else if size - 285 < 65_536 {
                    (30, 2, size - 285)
                } else {
                    (31, 3, size - 65_821)
                };
                header(&mut self.bytes, escape);
                for index in 0..width {
                    self.bytes
                        .push(((extension >> (8 * (width - 1 - index))) & 0xff) as u8);
                }
            }
        }
    }

    /// Build the fixture database.
    ///
    /// `record_size`-bit tree, `ip_version` address family, one record per
    /// network (insertion order preserved; identical records are
    /// deduplicated through a data-section pointer, exercising the pointer
    /// decode path).
    ///
    /// # Panics
    ///
    /// On a malformed fixture description (never on the shipped fixtures).
    #[must_use]
    #[allow(clippy::too_many_lines)] // one linear pass per fixture concern
    pub fn build_database(
        record_size: u32,
        ip_version: u32,
        networks: &[(&str, Vec<(&str, Value)>)],
    ) -> Vec<u8> {
        // The tree: each node's left/right edge is either another node, a
        // record leaf, or missing (serialized as the not-found sentinel).
        #[derive(Default, Clone, Copy)]
        enum Edge {
            #[default]
            Missing,
            Node(usize),
            Record(usize),
        }
        #[derive(Default)]
        struct Node {
            left: Edge,
            right: Edge,
        }
        assert!(matches!(record_size, 24 | 28 | 32), "fixture record size");
        assert!(ip_version == 4 || ip_version == 6, "fixture ip version");
        let record_bytes = (record_size / 8) as usize;
        let total_bits = if ip_version == 4 { 32 } else { 128 };

        // Each network as a bit vector plus its prefix length.
        let mut routes: Vec<(Vec<bool>, usize, usize)> = Vec::new();
        for (record_id, (network, _)) in networks.iter().enumerate() {
            let (addr, prefix) = network.split_once('/').expect("fixture cidr");
            let prefix: usize = prefix.parse().expect("fixture prefix");
            assert!(prefix > 0 && prefix <= total_bits, "fixture prefix");
            let ip: std::net::IpAddr = addr.parse().expect("fixture ip");
            let (mut bits, offset): (Vec<bool>, usize) = match ip {
                std::net::IpAddr::V4(v4) => (
                    v4.octets()
                        .iter()
                        .flat_map(|byte| (0..8).map(move |bit| (byte >> (7 - bit)) & 1 == 1))
                        .collect(),
                    0,
                ),
                std::net::IpAddr::V6(v6) => (
                    v6.octets()
                        .iter()
                        .flat_map(|byte| (0..8).map(move |bit| (byte >> (7 - bit)) & 1 == 1))
                        .collect(),
                    0,
                ),
            };
            // An IPv4 route in an IPv6 database walks the IPv4-mapped
            // prefix: 96 zero bits ahead of the address bits.
            if ip_version == 6 && ip.is_ipv4() {
                let mut mapped = vec![false; 96];
                mapped.extend_from_slice(&bits);
                bits = mapped;
            }
            let prefix = prefix + offset;
            routes.push((bits, prefix, record_id));
        }

        let mut nodes: Vec<Node> = vec![Node::default()];
        for (bits, prefix, record_id) in &routes {
            let mut node = 0usize;
            for (bit_index, right) in bits.iter().enumerate().take(*prefix) {
                let right = *right;
                let last = bit_index + 1 == *prefix;
                if last {
                    let edge = if right {
                        &mut nodes[node].right
                    } else {
                        &mut nodes[node].left
                    };
                    assert!(
                        matches!(edge, Edge::Missing),
                        "fixture routes must not overlap"
                    );
                    *edge = Edge::Record(*record_id);
                    break;
                }
                let next = if right {
                    match nodes[node].right {
                        Edge::Node(next) => next,
                        Edge::Missing => {
                            let next = nodes.len();
                            nodes.push(Node::default());
                            nodes[node].right = Edge::Node(next);
                            next
                        }
                        Edge::Record(_) => panic!("fixture routes must not overlap"),
                    }
                } else {
                    match nodes[node].left {
                        Edge::Node(next) => next,
                        Edge::Missing => {
                            let next = nodes.len();
                            nodes.push(Node::default());
                            nodes[node].left = Edge::Node(next);
                            next
                        }
                        Edge::Record(_) => panic!("fixture routes must not overlap"),
                    }
                };
                node = next;
            }
        }

        // The data section: each distinct record encoded once, back to
        // back; identical records share an offset (the pointer dedup).
        let node_count = nodes.len();
        let mut encoded_records: Vec<Vec<u8>> = Vec::new();
        let mut record_offsets: Vec<Option<usize>> = vec![None; networks.len()];
        for (index, (_, entries)) in networks.iter().enumerate() {
            let mut writer = Writer::new();
            writer.map(entries.len());
            for (key, value) in entries {
                writer.string(key);
                match value {
                    Value::Str(text) => writer.string(text),
                    Value::UInt(number) => writer.uint(*number),
                }
            }
            // Identical records alias through a data-section pointer.
            let shared = encoded_records
                .iter()
                .position(|prior| *prior == writer.bytes);
            let offset = if let Some(prior) = shared {
                record_offsets[prior].expect("first encoding")
            } else {
                let offset = encoded_records.iter().map(Vec::len).sum();
                encoded_records.push(writer.bytes);
                offset
            };
            record_offsets[index] = Some(offset);
        }
        let mut data = Writer::new();
        for record in &encoded_records {
            data.push(record);
        }

        // Serialize the tree, then the 16-byte separator, then the data.
        let tree_size = node_count * record_bytes * 2;
        let mut out = Vec::with_capacity(tree_size + 16 + data.bytes.len());
        for node in &nodes {
            for edge in [node.left, node.right] {
                let value = match edge {
                    Edge::Missing => node_count,
                    Edge::Node(next) => next,
                    Edge::Record(record_id) => {
                        node_count + 16 + record_offsets[record_id].expect("encoded")
                    }
                };
                for index in 0..record_bytes {
                    out.push(((value >> (8 * (record_bytes - 1 - index))) & 0xff) as u8);
                }
            }
        }
        assert_eq!(out.len(), tree_size, "fixture tree layout");
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&data.bytes);

        // Metadata map: the three routing fields plus a version pair the
        // decoder ignores.
        let mut meta = Writer::new();
        meta.map(5);
        meta.string("node_count");
        meta.uint(node_count as u128);
        meta.string("record_size");
        meta.uint(u128::from(record_size));
        meta.string("ip_version");
        meta.uint(u128::from(ip_version));
        meta.string("binary_format_major_version");
        meta.uint(2);
        meta.string("binary_format_minor_version");
        meta.uint(0);
        out.push(0xAB);
        out.push(0xCD);
        out.push(0xEF);
        out.extend_from_slice(b"MaxMind.com");
        out.extend_from_slice(&meta.bytes);
        out
    }
}
