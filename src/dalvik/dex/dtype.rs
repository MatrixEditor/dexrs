use crate::dalvik::error::{Error, Result};
use std::{
    fmt::{Debug, Display},
    rc::Rc,
};

/// A TypeDescriptor is the representation of any type, including
/// primitives, classes, arrays, and void.
///
/// @see https://source.android.com/docs/core/runtime/dex-format#typedescriptor
///
#[derive(PartialEq, Eq)]
pub struct DexType {
    pub descriptor: String,
    pub dim: usize,
    pub primitive: bool,
}

impl DexType {
    /// Create a new `DexType` from a `String` removing any array
    /// dimensions
    pub fn from(descriptor: &Rc<String>) -> Option<DexType> {
        let mut chars = descriptor.chars().peekable();
        let mut i: usize = 0;
        while *chars.peek()? == '[' {
            i += 1;
            chars.next();
        }
        match *chars.peek()? {
            // primitive types
            'V' | 'Z' | 'C' | 'B' | 'S' | 'I' | 'F' | 'J' | 'D' => {
                Some(DexType {
                    descriptor: descriptor[i..].to_string(),
                    dim: i,
                    primitive: true,
                })
            }
            // REVISIT:
            // resolve the class type descriptor directly
            'L' => {
                Some(DexType {
                    descriptor: descriptor[i..].to_string(),
                    dim: i,
                    primitive: false,
                })
            }
            _ => {
                None
            }
        }
    }

    pub fn read(descriptor: &Rc<String>) -> Result<DexType> {
        let mut chars = descriptor.chars().peekable();
        let mut i: usize = 0;
        loop {
            if let Some(c) = chars.peek() {
                if *c == '[' {
                    i += 1;
                    chars.next();
                    continue;
                }
            }
            break;
        }
        match *chars.peek().unwrap() {
            // primitive types
            'V' | 'Z' | 'C' | 'B' | 'S' | 'I' | 'F' | 'J' | 'D' => {
                Ok(DexType {
                    descriptor: descriptor[i..].to_string(),
                    dim: i,
                    primitive: true,
                })
            }
            // REVISIT:
            // resolve the class type descriptor directly
            'L' => {
                Ok(DexType {
                    descriptor: descriptor[i..].to_string(),
                    dim: i,
                    primitive: false,
                })
            }
            _ => {
                Err(Error::MalformedDescriptor(format!(
                    "Invalid type descriptor: {}",
                    descriptor
                )))
            }
        }
    }
}

impl Display for DexType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.dim > 0 {
            write!(f, "{}", "[".repeat(self.dim))?;
        }
        write!(f, "{}", self.descriptor)
    }
}

impl Debug for DexType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DexType {{ descriptor: \"{}\", dim: {}, primitive: {} }}",
            self.descriptor.escape_default(),
            self.dim,
            self.primitive
        )
    }
}

// pub struct Prototype {
//     pub shorty: Rc<String>,
//     pub return_type: Rc<DexType>,
//     pub parameters: Vec<Rc<DexType>>,
// }

// impl Prototype {
//     /// Parses the `proto_id_item` section of the dex file.
//     ///
//     /// First, the `proto_id_item` is read and the `shorty` and `return_type` descriptors
//     /// are read from the `string_ids_item` section. The `parameters` are read from the
//     /// data section only if `parameters_off` is not 0.
//     ///
//     /// @**NOTE**: this function assumes that `reader` is at the start of the next
//     ///            `proto_id_item`.
//     pub fn from<R>(mut reader: R, dex: &Dex) -> result::Result<Prototype, Error>
//     where
//         R: Read + Seek,
//     {
//         // 1. read the proto_id_item
//         let item = match ProtoIdItem::read(&mut reader) {
//             Ok(x) => x,
//             Err(e) => return Err(Error::from(e)),
//         };

//         let shorty = dex.string_at(item.shorty_idx as usize)?;
//         let return_ty = dex.type_at(item.return_type_idx)?;
//         let mut proto = Prototype {
//             shorty: shorty.clone(),
//             return_type: return_ty.clone(),
//             // REVISIT: maybe find a way to hardcode the number of parameters
//             parameters: Vec::new(),
//         };
//         // As described in Android docs: 0 if this prototype has no parameters.
//         if item.parameters_off != 0 {
//             reader.seek(io::SeekFrom::Start(item.parameters_off as u64))?;
//             let params = match TypeList::read(&mut reader) {
//                 Ok(x) => x,
//                 Err(e) => return Err(Error::from(e)),
//             };

//             for j in 0..params.size {
//                 // the parameter item stores the type index of the parameter
//                 let index = params.list[j as usize].type_idx;
//                 let ty = dex.type_at(index as u32)?;
//                 proto.parameters.push(ty.clone());
//             }
//         }
//         return Ok(proto);
//     }
// }

// impl Display for Prototype {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(
//             f,
//             "({}){}",
//             self.parameters
//                 .iter()
//                 .map(|x| x.to_string())
//                 .collect::<Vec<String>>()
//                 .join(","),
//             self.return_type
//         )
//     }
// }

// impl Debug for Prototype {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(
//             f,
//             "Prototype {{ shorty: {}, return_type: {}, parameters: {:?} }}",
//             self.shorty, self.return_type, self.parameters
//         )
//     }
// }
