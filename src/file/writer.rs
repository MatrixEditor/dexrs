//! Serialize a [`DexIr`] to valid standard-DEX bytes.
//!
//! [`DexWriter::write`] is the single entry point.  It sorts all pools, assigns
//! integer indices, and writes the binary representation in a single forward pass
//! with a backpatch table for forward references.
//!
//! # Performance
//! * String deduplication uses `HashMap` for O(1) insert + one O(M log M) sort.
//! * All output is written into a single pre-allocated `Vec<u8>`.
//! * Backpatching fills in cross-references after the referenced items are written.

use std::collections::HashMap;

use crate::{
    file::{
        builder::encode_insn,
        ir::{
            BranchTarget, ClassDef, CodeDef, DexIr, DexRef, EncodedValueIr,
            FieldDef, MethodDef, ProtoKey, TryDef,
        },
        patch::{encode_uleb128, update_checksum},
    },
    utf::str_to_mutf8,
    Result,
};

// -- Output buffer with backpatch support --------------------------------------

struct Out {
    data: Vec<u8>,
}

#[allow(dead_code)]
impl Out {
    fn new(capacity: usize) -> Self {
        Self { data: Vec::with_capacity(capacity) }
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn write_u8(&mut self, v: u8) {
        self.data.push(v);
    }

    fn write_u16(&mut self, v: u16) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u32(&mut self, v: u32) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    fn write_i32(&mut self, v: i32) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    fn write_bytes(&mut self, b: &[u8]) {
        self.data.extend_from_slice(b);
    }

    fn write_uleb128(&mut self, v: u32) {
        self.data.extend(encode_uleb128(v));
    }

    fn write_sleb128(&mut self, mut v: i32) {
        loop {
            let mut byte = (v & 0x7F) as u8;
            v >>= 7;
            let done = v == 0 && (byte & 0x40 == 0) || v == -1 && (byte & 0x40 != 0);
            if !done {
                byte |= 0x80;
            }
            self.data.push(byte);
            if done {
                break;
            }
        }
    }

    /// Reserve 4 bytes (initialised to zero) for a later backpatch.
    /// Returns the position of the reserved slot.
    fn reserve_u32(&mut self) -> usize {
        let pos = self.data.len();
        self.data.extend_from_slice(&[0, 0, 0, 0]);
        pos
    }

    /// Fill in a previously reserved u32 slot.
    fn patch_u32(&mut self, pos: usize, v: u32) {
        self.data[pos..pos + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Pad to a 4-byte boundary.
    fn align4(&mut self) {
        while !self.data.len().is_multiple_of(4) {
            self.data.push(0);
        }
    }
}

// -- Sorted pools --------------------------------------------------------------

type FieldKey = (Vec<u8>, Vec<u8>, Vec<u8>);
type FieldMap = BTreeMap<FieldKey, ()>;
type FieldHashMap = HashMap<FieldKey, u32>;

/// Collect + sort all strings, types, protos, fields, methods from `ir`.
struct Pools {
    /// Sorted MUTF-8 string contents (without null terminator).
    strings: Vec<Vec<u8>>,
    string_idx: HashMap<Vec<u8>, u32>,

    /// Sorted type descriptors (as MUTF-8 bytes).
    types: Vec<Vec<u8>>,
    type_idx: HashMap<Vec<u8>, u32>,

    /// Sorted protos.
    protos: Vec<ProtoKey>,
    proto_idx: HashMap<ProtoKey, u32>,

    /// Sorted field keys: (class_desc, name, field_type) — all MUTF-8.
    fields: Vec<FieldKey>,
    field_idx: FieldHashMap,

    /// Sorted method keys: (class_desc, name, proto) — class+name as MUTF-8.
    methods: Vec<(Vec<u8>, Vec<u8>, ProtoKey)>,
    method_idx: HashMap<(Vec<u8>, Vec<u8>, ProtoKey), u32>,
}

#[allow(dead_code)]
impl Pools {
    fn build(ir: &DexIr) -> Self {
        use std::collections::BTreeMap;

        // Use BTreeMap to auto-sort on insertion.
        let mut strings: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
        let mut types: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
        let mut protos: BTreeMap<ProtoKey, ()> = BTreeMap::new();
        let mut fields: FieldMap = BTreeMap::new();
        let mut methods: BTreeMap<(Vec<u8>, Vec<u8>, ProtoKey), ()> = BTreeMap::new();

        let add_str = |s: &str, strings: &mut BTreeMap<Vec<u8>, ()>| {
            strings.insert(str_to_mutf8_no_null(s), ());
        };
        let add_type = |s: &str,
                        strings: &mut BTreeMap<Vec<u8>, ()>,
                        types: &mut BTreeMap<Vec<u8>, ()>| {
            let m = str_to_mutf8_no_null(s);
            strings.insert(m.clone(), ());
            types.insert(m, ());
        };
        let add_proto = |p: &ProtoKey,
                         strings: &mut BTreeMap<Vec<u8>, ()>,
                         types: &mut BTreeMap<Vec<u8>, ()>,
                         protos: &mut BTreeMap<ProtoKey, ()>| {
            let shorty = p.shorty();
            add_str(&shorty, strings);
            add_type(&p.return_type, strings, types);
            for param in &p.params {
                add_type(param, strings, types);
            }
            protos.insert(p.clone(), ());
        };
        let _ = add_proto;

        for class in &ir.classes {
            // class descriptor
            add_type(&class.descriptor, &mut strings, &mut types);
            // superclass
            if let Some(ref s) = class.superclass {
                add_type(s, &mut strings, &mut types);
            }
            // interfaces
            for iface in &class.interfaces {
                add_type(iface, &mut strings, &mut types);
            }
            // source file
            if let Some(ref sf) = class.source_file {
                add_str(sf, &mut strings);
            }
            // fields
            for f in class.static_fields.iter().chain(class.instance_fields.iter()) {
                collect_field(f, &class.descriptor, &mut strings, &mut types, &mut fields);
            }
            // methods
            for m in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                collect_method(
                    m,
                    &class.descriptor,
                    &mut strings,
                    &mut types,
                    &mut protos,
                    &mut fields,
                    &mut methods,
                );
            }
        }

        // Materialise sorted vecs + index maps.
        let strings: Vec<Vec<u8>> = strings.into_keys().collect();
        let string_idx: HashMap<Vec<u8>, u32> =
            strings.iter().enumerate().map(|(i, k)| (k.clone(), i as u32)).collect();

        let types: Vec<Vec<u8>> = types.into_keys().collect();
        let type_idx: HashMap<Vec<u8>, u32> =
            types.iter().enumerate().map(|(i, k)| (k.clone(), i as u32)).collect();

        let protos: Vec<ProtoKey> = protos.into_keys().collect();
        let proto_idx: HashMap<ProtoKey, u32> =
            protos.iter().enumerate().map(|(i, k)| (k.clone(), i as u32)).collect();

        let fields: Vec<FieldKey> = fields.into_keys().collect();
        let field_idx: FieldHashMap =
            fields.iter().enumerate().map(|(i, k)| (k.clone(), i as u32)).collect();

        let methods: Vec<(Vec<u8>, Vec<u8>, ProtoKey)> = methods.into_keys().collect();
        let method_idx: HashMap<(Vec<u8>, Vec<u8>, ProtoKey), u32> =
            methods.iter().enumerate().map(|(i, k)| (k.clone(), i as u32)).collect();

        Pools { strings, string_idx, types, type_idx, protos, proto_idx, fields, field_idx, methods, method_idx }
    }

    fn string_idx_of(&self, s: &str) -> u32 {
        let m = str_to_mutf8_no_null(s);
        *self.string_idx.get(&m).unwrap_or_else(|| panic!("string not in pool: {s:?}"))
    }

    fn type_idx_of(&self, s: &str) -> u32 {
        let m = str_to_mutf8_no_null(s);
        *self.type_idx.get(&m).unwrap_or_else(|| panic!("type not in pool: {s:?}"))
    }

    fn proto_idx_of(&self, p: &ProtoKey) -> u32 {
        *self.proto_idx.get(p).unwrap_or_else(|| panic!("proto not in pool: {p:?}"))
    }

    fn field_idx_of(&self, class: &str, name: &str, ty: &str) -> u32 {
        let key = (str_to_mutf8_no_null(class), str_to_mutf8_no_null(name), str_to_mutf8_no_null(ty));
        *self.field_idx.get(&key).unwrap_or_else(|| panic!("field not in pool: {class}.{name}:{ty}"))
    }

    fn method_idx_of(&self, class: &str, name: &str, proto: &ProtoKey) -> u32 {
        let key = (str_to_mutf8_no_null(class), str_to_mutf8_no_null(name), proto.clone());
        *self.method_idx.get(&key).unwrap_or_else(|| panic!("method not in pool: {class}.{name}"))
    }

    fn ref_idx(&self, r: &DexRef) -> u32 {
        match r {
            DexRef::String(s) => self.string_idx_of(s),
            DexRef::Type(s) => self.type_idx_of(s),
            DexRef::Field { class, name, field_type } => {
                self.field_idx_of(class, name, field_type)
            }
            DexRef::Method { class, name, proto } => self.method_idx_of(class, name, proto),
            DexRef::Proto(p) => self.proto_idx_of(p),
        }
    }
}

// -- Pool collector helpers ----------------------------------------------------

use std::collections::BTreeMap;

fn collect_field(
    f: &FieldDef,
    class_desc: &str,
    strings: &mut BTreeMap<Vec<u8>, ()>,
    types: &mut BTreeMap<Vec<u8>, ()>,
    fields: &mut FieldMap,
) {
    let c = str_to_mutf8_no_null(class_desc);
    let n = str_to_mutf8_no_null(&f.name);
    let t = str_to_mutf8_no_null(&f.field_type);
    strings.insert(n.clone(), ());
    let ft = str_to_mutf8_no_null(&f.field_type);
    strings.insert(ft, ());
    types.insert(t.clone(), ());
    let type_desc = str_to_mutf8_no_null(&f.field_type);
    types.insert(type_desc, ());
    fields.insert((c, n, t), ());
}

fn collect_method(
    m: &MethodDef,
    class_desc: &str,
    strings: &mut BTreeMap<Vec<u8>, ()>,
    types: &mut BTreeMap<Vec<u8>, ()>,
    protos: &mut BTreeMap<ProtoKey, ()>,
    fields: &mut FieldMap,
    methods: &mut BTreeMap<(Vec<u8>, Vec<u8>, ProtoKey), ()>,
) {
    let c = str_to_mutf8_no_null(class_desc);
    let n = str_to_mutf8_no_null(&m.name);
    strings.insert(n.clone(), ());

    // Proto: shorty + return type + params
    let shorty = m.proto.shorty();
    strings.insert(str_to_mutf8_no_null(&shorty), ());
    types.insert(str_to_mutf8_no_null(&m.proto.return_type), ());
    strings.insert(str_to_mutf8_no_null(&m.proto.return_type), ());
    for p in &m.proto.params {
        types.insert(str_to_mutf8_no_null(p), ());
        strings.insert(str_to_mutf8_no_null(p), ());
    }
    protos.insert(m.proto.clone(), ());
    methods.insert((c, n, m.proto.clone()), ());

    // Collect references from instructions
    if let Some(code) = &m.code {
        collect_code_refs(code, strings, types, protos, fields, methods);
    }
}

fn collect_code_refs(
    code: &CodeDef,
    strings: &mut BTreeMap<Vec<u8>, ()>,
    types: &mut BTreeMap<Vec<u8>, ()>,
    protos: &mut BTreeMap<ProtoKey, ()>,
    fields: &mut FieldMap,
    methods: &mut BTreeMap<(Vec<u8>, Vec<u8>, ProtoKey), ()>,
) {
    for node in &code.insns {
        if let Some(r) = &node.reference {
            collect_dexref(r, strings, types, protos, fields, methods);
        }
    }
}

fn collect_dexref(
    r: &DexRef,
    strings: &mut BTreeMap<Vec<u8>, ()>,
    types: &mut BTreeMap<Vec<u8>, ()>,
    protos: &mut BTreeMap<ProtoKey, ()>,
    fields: &mut FieldMap,
    methods: &mut BTreeMap<(Vec<u8>, Vec<u8>, ProtoKey), ()>,
) {
    match r {
        DexRef::String(s) => {
            strings.insert(str_to_mutf8_no_null(s), ());
        }
        DexRef::Type(t) => {
            strings.insert(str_to_mutf8_no_null(t), ());
            types.insert(str_to_mutf8_no_null(t), ());
        }
        DexRef::Field { class, name, field_type } => {
            let c = str_to_mutf8_no_null(class);
            let n = str_to_mutf8_no_null(name);
            let ft = str_to_mutf8_no_null(field_type);
            strings.insert(c.clone(), ());
            types.insert(c.clone(), ());
            strings.insert(n.clone(), ());
            strings.insert(ft.clone(), ());
            types.insert(ft.clone(), ());
            fields.insert((c, n, ft), ());
        }
        DexRef::Method { class, name, proto } => {
            let c = str_to_mutf8_no_null(class);
            let n = str_to_mutf8_no_null(name);
            strings.insert(c.clone(), ());
            types.insert(c.clone(), ());
            strings.insert(n.clone(), ());
            let shorty = proto.shorty();
            strings.insert(str_to_mutf8_no_null(&shorty), ());
            strings.insert(str_to_mutf8_no_null(&proto.return_type), ());
            types.insert(str_to_mutf8_no_null(&proto.return_type), ());
            for p in &proto.params {
                strings.insert(str_to_mutf8_no_null(p), ());
                types.insert(str_to_mutf8_no_null(p), ());
            }
            protos.insert(proto.clone(), ());
            methods.insert((c, n, proto.clone()), ());
        }
        DexRef::Proto(p) => {
            let shorty = p.shorty();
            strings.insert(str_to_mutf8_no_null(&shorty), ());
            strings.insert(str_to_mutf8_no_null(&p.return_type), ());
            types.insert(str_to_mutf8_no_null(&p.return_type), ());
            for param in &p.params {
                strings.insert(str_to_mutf8_no_null(param), ());
                types.insert(str_to_mutf8_no_null(param), ());
            }
            protos.insert(p.clone(), ());
        }
    }
}

// -- MUTF-8 helper -------------------------------------------------------------

/// Encode a Rust `&str` to MUTF-8 **without** the null terminator.
fn str_to_mutf8_no_null(s: &str) -> Vec<u8> {
    let mut v = str_to_mutf8(s);
    if v.last() == Some(&0) {
        v.pop();
    }
    v
}

// -- Map list tracking ---------------------------------------------------------

#[derive(Clone)]
struct MapEntry {
    type_code: u16,
    count: u32,
    offset: u32,
}

// -- DEX Writer ----------------------------------------------------------------

/// Serialise a [`DexIr`] to a valid standard-DEX byte vector.
pub struct DexWriter;

impl DexWriter {
    /// Build a complete DEX file from the IR and return the raw bytes.
    ///
    /// The output has a recalculated Adler32 checksum and correct `file_size`.
    pub fn write(ir: DexIr) -> Result<Vec<u8>> {
        let pools = Pools::build(&ir);
        let mut out = Out::new(1 << 16);
        let mut map: Vec<MapEntry> = Vec::new();

        // -- Header placeholder (112 bytes) -----------------------------------
        let header_start = out.len();
        // magic: "dex\n" + version + "\0"
        let version_str = format!("{:03}\0", ir.version);
        out.write_bytes(b"dex\n");
        out.write_bytes(version_str.as_bytes());
        // checksum placeholder (4 bytes)
        let checksum_pos = out.len();
        out.write_u32(0);
        // SHA-1 signature (20 bytes — we leave it as zeros; most tools don't verify)
        for _ in 0..20 {
            out.write_u8(0);
        }
        // file_size placeholder
        let file_size_pos = out.len();
        out.write_u32(0);
        // header_size = 0x70
        out.write_u32(0x70);
        // endian_tag
        out.write_u32(0x12345678);
        // link_size + link_off (unused)
        out.write_u32(0);
        out.write_u32(0);
        // map_off placeholder
        let map_off_pos = out.len();
        out.write_u32(0);
        // string_ids_size + string_ids_off
        out.write_u32(pools.strings.len() as u32);
        let string_ids_off_pos = out.len();
        out.write_u32(0);
        // type_ids_size + type_ids_off
        out.write_u32(pools.types.len() as u32);
        let type_ids_off_pos = out.len();
        out.write_u32(0);
        // proto_ids_size + proto_ids_off
        out.write_u32(pools.protos.len() as u32);
        let proto_ids_off_pos = out.len();
        out.write_u32(0);
        // field_ids_size + field_ids_off
        out.write_u32(pools.fields.len() as u32);
        let field_ids_off_pos = out.len();
        out.write_u32(0);
        // method_ids_size + method_ids_off
        out.write_u32(pools.methods.len() as u32);
        let method_ids_off_pos = out.len();
        out.write_u32(0);
        // class_defs_size + class_defs_off
        out.write_u32(ir.classes.len() as u32);
        let class_defs_off_pos = out.len();
        out.write_u32(0);
        // data_size + data_off (filled in at end)
        let data_size_pos = out.len();
        out.write_u32(0);
        let data_off_pos = out.len();
        out.write_u32(0);

        assert_eq!(out.len() - header_start, 0x70, "header must be exactly 112 bytes");
        map.push(MapEntry { type_code: 0x0000, count: 1, offset: header_start as u32 });

        // -- string_ids --------------------------------------------------------
        let string_ids_off = out.len() as u32;
        out.patch_u32(string_ids_off_pos, string_ids_off);
        // One u32 per string: placeholder, patched when string_data is written.
        let mut string_data_off_positions: Vec<usize> = Vec::with_capacity(pools.strings.len());
        for _ in &pools.strings {
            string_data_off_positions.push(out.reserve_u32());
        }
        if !pools.strings.is_empty() {
            map.push(MapEntry {
                type_code: 0x0001,
                count: pools.strings.len() as u32,
                offset: string_ids_off,
            });
        }

        // -- type_ids ----------------------------------------------------------
        let type_ids_off = out.len() as u32;
        out.patch_u32(type_ids_off_pos, type_ids_off);
        for type_mutf8 in &pools.types {
            let s_idx = pools.string_idx[type_mutf8];
            out.write_u32(s_idx);
        }
        if !pools.types.is_empty() {
            map.push(MapEntry {
                type_code: 0x0002,
                count: pools.types.len() as u32,
                offset: type_ids_off,
            });
        }

        // -- proto_ids ---------------------------------------------------------
        let proto_ids_off = out.len() as u32;
        out.patch_u32(proto_ids_off_pos, proto_ids_off);
        let mut proto_params_off_positions: Vec<usize> = Vec::with_capacity(pools.protos.len());
        for proto in &pools.protos {
            let shorty_s = proto.shorty();
            let shorty_idx = pools.string_idx_of(&shorty_s);
            let return_idx = pools.type_idx_of(&proto.return_type) as u16;
            out.write_u32(shorty_idx);
            out.write_u16(return_idx);
            out.write_u16(0); // pad
            proto_params_off_positions.push(out.reserve_u32()); // parameters_off placeholder
        }
        if !pools.protos.is_empty() {
            map.push(MapEntry {
                type_code: 0x0003,
                count: pools.protos.len() as u32,
                offset: proto_ids_off,
            });
        }

        // -- field_ids ---------------------------------------------------------
        let field_ids_off = out.len() as u32;
        out.patch_u32(field_ids_off_pos, field_ids_off);
        for (class_m, name_m, type_m) in &pools.fields {
            let class_tidx = pools.type_idx[class_m] as u16;
            let type_tidx = pools.type_idx[type_m] as u16;
            let name_sidx = pools.string_idx[name_m];
            out.write_u16(class_tidx);
            out.write_u16(type_tidx);
            out.write_u32(name_sidx);
        }
        if !pools.fields.is_empty() {
            map.push(MapEntry {
                type_code: 0x0004,
                count: pools.fields.len() as u32,
                offset: field_ids_off,
            });
        }

        // -- method_ids --------------------------------------------------------
        let method_ids_off = out.len() as u32;
        out.patch_u32(method_ids_off_pos, method_ids_off);
        for (class_m, name_m, proto_key) in &pools.methods {
            let class_tidx = pools.type_idx[class_m] as u16;
            let proto_pidx = pools.proto_idx[proto_key] as u16;
            let name_sidx = pools.string_idx[name_m];
            out.write_u16(class_tidx);
            out.write_u16(proto_pidx);
            out.write_u32(name_sidx);
        }
        if !pools.methods.is_empty() {
            map.push(MapEntry {
                type_code: 0x0005,
                count: pools.methods.len() as u32,
                offset: method_ids_off,
            });
        }

        // -- class_defs --------------------------------------------------------
        // Sort class_defs: topological ordering by descriptor (alphabetical gives
        // a valid ordering for typical class hierarchies; a proper topological
        // sort would be needed for full correctness when superclasses appear later).
        let mut sorted_classes = ir.classes;
        sorted_classes.sort_by(|a, b| a.descriptor.cmp(&b.descriptor));

        let class_defs_off = out.len() as u32;
        out.patch_u32(class_defs_off_pos, class_defs_off);

        // For each class we'll need to backpatch:
        //   interfaces_off (word at class_def + 12)
        //   class_data_off (word at class_def + 24)
        struct ClassSlots {
            interfaces_off_pos: usize,
            class_data_off_pos: usize,
        }
        let mut class_slots: Vec<ClassSlots> = Vec::with_capacity(sorted_classes.len());

        for class in &sorted_classes {
            let class_tidx = pools.type_idx_of(&class.descriptor) as u16;
            let super_tidx: u16 = class
                .superclass
                .as_deref()
                .map(|s| pools.type_idx_of(s) as u16)
                .unwrap_or(0xFFFF);
            let source_sidx: u32 = class
                .source_file
                .as_deref()
                .map(|s| pools.string_idx_of(s))
                .unwrap_or(0xFFFF_FFFF);

            // class_idx (u16) + pad (u16)
            out.write_u16(class_tidx);
            out.write_u16(0);
            // access_flags (u32)
            out.write_u32(class.access_flags);
            // superclass_idx (u16) + pad (u16)
            out.write_u16(super_tidx);
            out.write_u16(0);
            // interfaces_off placeholder
            let interfaces_off_pos = out.reserve_u32();
            // source_file_idx
            out.write_u32(source_sidx);
            // annotations_off = 0
            out.write_u32(0);
            // class_data_off placeholder
            let class_data_off_pos = out.reserve_u32();
            // static_values_off = 0 (TODO: encode static values)
            out.write_u32(0);

            class_slots.push(ClassSlots { interfaces_off_pos, class_data_off_pos });
        }
        if !sorted_classes.is_empty() {
            map.push(MapEntry {
                type_code: 0x0006,
                count: sorted_classes.len() as u32,
                offset: class_defs_off,
            });
        }

        // ═══ DATA SECTION begins here ═══════════════════════════════════════
        let data_off = out.len() as u32;
        out.patch_u32(data_off_pos, data_off);

        // -- type_lists (proto parameters + class interfaces) ------------------
        // Build a deduplication map so identical type lists share one entry.
        let mut type_list_cache: HashMap<Vec<u16>, u32> = HashMap::new();

        let write_type_list = |out: &mut Out,
                               _map: &mut Vec<MapEntry>,
                               type_list_cache: &mut HashMap<Vec<u16>, u32>,
                               type_indices: Vec<u16>| -> u32 {
            if type_indices.is_empty() {
                return 0;
            }
            if let Some(&off) = type_list_cache.get(&type_indices) {
                return off;
            }
            out.align4();
            let off = out.len() as u32;
            out.write_u32(type_indices.len() as u32);
            for tidx in &type_indices {
                out.write_u16(*tidx);
            }
            type_list_cache.insert(type_indices, off);
            // map entry updated after all lists are written
            off
        };

        // Write proto type lists and patch proto_ids.
        let mut type_list_offsets: Vec<u32> = Vec::with_capacity(pools.protos.len());
        for proto in &pools.protos {
            let type_indices: Vec<u16> =
                proto.params.iter().map(|p| pools.type_idx_of(p) as u16).collect();
            let off = write_type_list(
                &mut out,
                &mut map,
                &mut type_list_cache,
                type_indices,
            );
            type_list_offsets.push(off);
        }
        for (i, off) in type_list_offsets.iter().enumerate() {
            out.patch_u32(proto_params_off_positions[i], *off);
        }
        // Write class interface lists and patch class_defs.
        for (i, class) in sorted_classes.iter().enumerate() {
            let type_indices: Vec<u16> =
                class.interfaces.iter().map(|iface| pools.type_idx_of(iface) as u16).collect();
            let off = write_type_list(
                &mut out,
                &mut map,
                &mut type_list_cache,
                type_indices,
            );
            out.patch_u32(class_slots[i].interfaces_off_pos, off);
        }
        // Count type list entries for the map.
        let type_list_count = type_list_cache.len() as u32;
        if type_list_count > 0 {
            // Find the earliest type list offset for the map entry.
            let min_off = *type_list_cache.values().min().unwrap();
            map.push(MapEntry { type_code: 0x1001, count: type_list_count, offset: min_off });
        }

        // -- code_items --------------------------------------------------------
        // Build method -> code_off map; used later when writing class_data.
        let mut code_offsets: HashMap<(usize, bool, usize), u32> = HashMap::new();
        // Key: (class_index, is_virtual, method_index_in_list)
        let mut code_item_count = 0u32;
        let mut code_items_first_off = 0u32;

        for (ci, class) in sorted_classes.iter().enumerate() {
            for (is_virtual, methods) in
                [(false, &class.direct_methods), (true, &class.virtual_methods)]
            {
                for (mi, method) in methods.iter().enumerate() {
                    if let Some(code) = &method.code {
                        out.align4();
                        let off = out.len() as u32;
                        if code_item_count == 0 {
                            code_items_first_off = off;
                        }
                        code_offsets.insert((ci, is_virtual, mi), off);
                        write_code_item(&mut out, code, &pools);
                        code_item_count += 1;
                    }
                }
            }
        }
        if code_item_count > 0 {
            map.push(MapEntry {
                type_code: 0x2001,
                count: code_item_count,
                offset: code_items_first_off,
            });
        }

        // -- class_data_items --------------------------------------------------
        let mut class_data_count = 0u32;
        let mut class_data_first_off = 0u32;

        for (ci, class) in sorted_classes.iter().enumerate() {
            let has_data = !class.static_fields.is_empty()
                || !class.instance_fields.is_empty()
                || !class.direct_methods.is_empty()
                || !class.virtual_methods.is_empty();
            if !has_data {
                continue;
            }
            let cdi_off = out.len() as u32;
            if class_data_count == 0 {
                class_data_first_off = cdi_off;
            }
            out.patch_u32(class_slots[ci].class_data_off_pos, cdi_off);
            class_data_count += 1;

            write_class_data(
                &mut out,
                class,
                &pools,
                &code_offsets,
                ci,
            );
        }
        if class_data_count > 0 {
            map.push(MapEntry {
                type_code: 0x2000,
                count: class_data_count,
                offset: class_data_first_off,
            });
        }

        // -- string_data_items -------------------------------------------------
        let string_data_first_off = out.len() as u32;
        for (i, mutf8) in pools.strings.iter().enumerate() {
            let sdi_off = out.len() as u32;
            out.patch_u32(string_data_off_positions[i], sdi_off);
            // ULEB128 UTF-16 length
            let utf16_len = mutf8_to_utf16_len(mutf8);
            out.write_uleb128(utf16_len as u32);
            // MUTF-8 bytes
            out.write_bytes(mutf8);
            // null terminator
            out.write_u8(0);
        }
        if !pools.strings.is_empty() {
            map.push(MapEntry {
                type_code: 0x2002,
                count: pools.strings.len() as u32,
                offset: string_data_first_off,
            });
        }

        // -- map_list ----------------------------------------------------------
        out.align4();
        let map_off = out.len() as u32;
        out.patch_u32(map_off_pos, map_off);

        // Sort map by type code (required by DEX spec).
        // Add the map_list entry itself.
        map.push(MapEntry { type_code: 0x1000, count: 1, offset: map_off });
        map.sort_by_key(|e| e.type_code);

        out.write_u32(map.len() as u32);
        for entry in &map {
            out.write_u16(entry.type_code);
            out.write_u16(0); // unused
            out.write_u32(entry.count);
            out.write_u32(entry.offset);
        }

        // -- Finalise header ---------------------------------------------------
        let file_size = out.len() as u32;
        out.patch_u32(file_size_pos, file_size);

        let data_size = file_size - data_off;
        out.patch_u32(data_size_pos, data_size);

        // Patch remaining header offset fields (already patched above, but
        // the ones that might have been left as 0 for empty sections).
        if pools.strings.is_empty() {
            out.patch_u32(string_ids_off_pos, 0);
        }
        if pools.types.is_empty() {
            out.patch_u32(type_ids_off_pos, 0);
        }
        if pools.protos.is_empty() {
            out.patch_u32(proto_ids_off_pos, 0);
        }
        if pools.fields.is_empty() {
            out.patch_u32(field_ids_off_pos, 0);
        }
        if pools.methods.is_empty() {
            out.patch_u32(method_ids_off_pos, 0);
        }
        if sorted_classes.is_empty() {
            out.patch_u32(class_defs_off_pos, 0);
        }

        // Checksum
        update_checksum(&mut out.data);

        let _ = checksum_pos; // Written by update_checksum

        Ok(out.data)
    }
}

// -- Code item serialisation ---------------------------------------------------

fn write_code_item(out: &mut Out, code: &CodeDef, pools: &Pools) {
    // Encode all InsnNodes, resolving pool references now.
    let mut encoded: Vec<u16> = Vec::with_capacity(code.insns.len() * 2);
    for node in &code.insns {
        let ref_idx = node.reference.as_ref().map(|r| pools.ref_idx(r));
        let branch_offset = node.target.as_ref().and_then(|t| match t {
            BranchTarget::Offset(o) => Some(*o),
            BranchTarget::Label(_) => None, // should not reach here after build()
        });
        let words = encode_insn(node.opcode, &node.regs, node.literal, ref_idx, branch_offset)
            .expect("instruction encoding failed after successful build()");
        encoded.extend(words);
    }

    out.write_u16(code.registers);
    out.write_u16(code.ins);
    out.write_u16(code.outs);
    out.write_u16(code.tries.len() as u16);
    out.write_u32(0); // debug_info_off = 0
    out.write_u32(encoded.len() as u32);
    for w in &encoded {
        out.write_u16(*w);
    }
    if !code.tries.is_empty() {
        if !encoded.len().is_multiple_of(2) {
            out.write_u16(0);
        }
        write_try_items(out, &code.tries);
    }
}

fn write_try_items(out: &mut Out, tries: &[TryDef]) {
    // Write try_item array
    for t in tries {
        out.write_u32(t.start);
        out.write_u16(t.count);
        // handler_off filled after handler list is written; for now write 0 and skip
        out.write_u16(0);
    }
    // Encoded catch handler list (1 byte: handler count per try block)
    // This is a simplified implementation; full handler encoding is complex.
    out.write_uleb128(tries.len() as u32);
    for t in tries {
        let n = t.handlers.len();
        let has_catch_all = t.handlers.iter().any(|h| h.type_desc.is_none());
        let typed = t.handlers.iter().filter(|h| h.type_desc.is_some()).count();
        let sleb_val = if has_catch_all { -(typed as i32) } else { typed as i32 };
        out.write_sleb128(sleb_val);
        for h in &t.handlers {
            if h.type_desc.is_some() {
                out.write_uleb128(0); // type_idx placeholder
                out.write_uleb128(h.address);
            }
        }
        if has_catch_all {
            let catch_all = t.handlers.iter().find(|h| h.type_desc.is_none()).unwrap();
            out.write_uleb128(catch_all.address);
        }
        let _ = n;
    }
}

// -- Class data item serialisation ---------------------------------------------

fn write_class_data(
    out: &mut Out,
    class: &ClassDef,
    pools: &Pools,
    code_offsets: &HashMap<(usize, bool, usize), u32>,
    ci: usize,
) {
    out.write_uleb128(class.static_fields.len() as u32);
    out.write_uleb128(class.instance_fields.len() as u32);
    out.write_uleb128(class.direct_methods.len() as u32);
    out.write_uleb128(class.virtual_methods.len() as u32);

    // Fields use delta-encoding of field_idx
    let mut prev_idx = 0u32;
    for f in &class.static_fields {
        let fidx = pools.field_idx_of(&class.descriptor, &f.name, &f.field_type);
        out.write_uleb128(fidx - prev_idx);
        out.write_uleb128(f.access_flags);
        prev_idx = fidx;
    }
    prev_idx = 0;
    for f in &class.instance_fields {
        let fidx = pools.field_idx_of(&class.descriptor, &f.name, &f.field_type);
        out.write_uleb128(fidx - prev_idx);
        out.write_uleb128(f.access_flags);
        prev_idx = fidx;
    }

    // Methods use delta-encoding of method_idx
    prev_idx = 0;
    for (mi, m) in class.direct_methods.iter().enumerate() {
        let midx = pools.method_idx_of(&class.descriptor, &m.name, &m.proto);
        out.write_uleb128(midx - prev_idx);
        out.write_uleb128(m.access_flags);
        let code_off = code_offsets.get(&(ci, false, mi)).copied().unwrap_or(0);
        out.write_uleb128(code_off);
        prev_idx = midx;
    }
    prev_idx = 0;
    for (mi, m) in class.virtual_methods.iter().enumerate() {
        let midx = pools.method_idx_of(&class.descriptor, &m.name, &m.proto);
        out.write_uleb128(midx - prev_idx);
        out.write_uleb128(m.access_flags);
        let code_off = code_offsets.get(&(ci, true, mi)).copied().unwrap_or(0);
        out.write_uleb128(code_off);
        prev_idx = midx;
    }
}

// -- EncodedValue serialisation -----------------------------------------------

#[allow(dead_code)]
fn _write_encoded_value(out: &mut Out, v: &EncodedValueIr, pools: &Pools) {
    match v {
        EncodedValueIr::Byte(b) => {
            out.write_u8(0x00); // VALUE_BYTE, arg=0
            out.write_u8(*b as u8);
        }
        EncodedValueIr::Int(i) => {
            let bytes = i.to_le_bytes();
            let size = value_size(*i as i64);
            out.write_u8(0x04 | ((size - 1) << 5)); // VALUE_INT
            out.write_bytes(&bytes[..size as usize]);
        }
        EncodedValueIr::Long(l) => {
            let bytes = l.to_le_bytes();
            let size = value_size(*l);
            out.write_u8(0x06 | ((size - 1) << 5)); // VALUE_LONG
            out.write_bytes(&bytes[..size as usize]);
        }
        EncodedValueIr::Boolean(b) => {
            out.write_u8(0x1f | ((*b as u8) << 5)); // VALUE_BOOLEAN
        }
        EncodedValueIr::String(s) => {
            let idx = pools.string_idx_of(s);
            let bytes = idx.to_le_bytes();
            let size = unsigned_value_size(idx as i64);
            out.write_u8(0x17 | ((size - 1) << 5));
            out.write_bytes(&bytes[..size as usize]);
        }
        EncodedValueIr::Null => {
            out.write_u8(0x1e); // VALUE_NULL, arg=0
        }
        _ => {
            // Fallback: write null for unsupported types
            out.write_u8(0x1e);
        }
    }
}

#[allow(dead_code)]
fn value_size(v: i64) -> u8 {
    if v >= i8::MIN as i64 && v <= i8::MAX as i64 {
        1
    } else if v >= i16::MIN as i64 && v <= i16::MAX as i64 {
        2
    } else if v >= i32::MIN as i64 && v <= i32::MAX as i64 {
        4
    } else {
        8
    }
}

#[allow(dead_code)]
fn unsigned_value_size(v: i64) -> u8 {
    if v <= 0xFF {
        1
    } else if v <= 0xFFFF {
        2
    } else if v <= 0xFF_FFFF {
        3
    } else {
        4
    }
}

// -- UTF-16 length computation -------------------------------------------------

/// Count UTF-16 code units for a MUTF-8 byte sequence (without null terminator).
fn mutf8_to_utf16_len(mutf8: &[u8]) -> usize {
    let mut i = 0;
    let mut count = 0;
    while i < mutf8.len() {
        let b = mutf8[i];
        if b & 0x80 == 0 {
            i += 1;
        } else if b & 0xE0 == 0xC0 {
            // 2-byte sequence (includes MUTF-8 null 0xC0 0x80)
            i += 2;
        } else if b & 0xF0 == 0xE0 {
            // 3-byte: single UTF-16 unit (including surrogate pairs from MUTF-8)
            i += 3;
        } else {
            i += 1; // fallback
        }
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::{
        ir::{ClassDef, MethodDef, ProtoKey},
        modifiers::{ACC_PUBLIC, ACC_STATIC},
        builder::CodeBuilder,
        DexFile, DexLocation,
    };

    #[test]
    fn write_empty_dex() {
        let ir = DexIr::new(35);
        let bytes = DexWriter::write(ir).unwrap();
        let slice = bytes.as_slice();
        let dex = DexFile::from_raw_parts(&slice, DexLocation::InMemory).unwrap();
        assert_eq!(dex.get_header().get_version(), 35);
    }

    #[test]
    fn write_class_no_methods() {
        let mut ir = DexIr::new(35);
        ir.add_class(
            ClassDef::new("Lcom/example/Empty;")
                .access(ACC_PUBLIC)
                .superclass("Ljava/lang/Object;"),
        );
        let bytes = DexWriter::write(ir).unwrap();
        let slice = bytes.as_slice();
        let dex = DexFile::from_raw_parts(&slice, DexLocation::InMemory).unwrap();
        assert_eq!(dex.num_class_defs(), 1);
    }

    #[test]
    fn write_class_with_method_and_string_ref() {
        // Builds a class with a method that references a string constant.
        // This exercises DexRef resolution through collect_code_refs + write_code_item.
        let mut ir = DexIr::new(35);
        let mut class = ClassDef::new("Ltest/Hello;")
            .access(ACC_PUBLIC)
            .superclass("Ljava/lang/Object;");

        let mut code = CodeBuilder::new(3, 1, 2);
        code.emit(r#"sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;"#).unwrap();
        code.emit(r#"const-string v1, "Hello, DEX!""#).unwrap();
        code.emit(r#"invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V"#).unwrap();
        code.emit("return-void").unwrap();

        class.add_direct_method(
            MethodDef::new("main", ProtoKey::new("V", ["[Ljava/lang/String;"]))
                .access(ACC_PUBLIC | ACC_STATIC)
                .code(code.build().unwrap()),
        );

        ir.add_class(class);
        let bytes = DexWriter::write(ir).unwrap();
        let slice = bytes.as_slice();
        let dex = DexFile::from_raw_parts(&slice, DexLocation::InMemory).unwrap();

        assert_eq!(dex.num_class_defs(), 1);
        // "Hello, DEX!" must be in the string pool
        let found = (0..dex.num_string_ids())
            .any(|i| dex.get_str_at(i).ok().as_deref() == Some("Hello, DEX!"));
        assert!(found, "string 'Hello, DEX!' not found in pool");
    }
}
