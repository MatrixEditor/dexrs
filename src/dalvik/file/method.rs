use crate::dalvik::dex::{
    AccessFlags, AnnotationSetRefList, CodeItem, DebugInfoItem, DexType, EncodedMethod, SLeb128, ULeb128, ULeb128p1
};
use crate::dalvik::error::Result;
use crate::dalvik::insns::{self, Insn};

use super::annotation::DexAnnotation;
use super::{debug::DebugInfo, Dex, IDex, IDexRef};
use binrw::BinRead;
use std::io::{Read, Seek};
use std::rc::Rc;

#[derive(Debug)]
pub struct DexPrototype {
    /// The shorty of the prototype (short type descriptor)
    pub shorty: Rc<String>,
    /// The return type of this prototype
    pub return_type: Rc<DexType>,
    /// The parameters of this prototype (only types)
    pub parameters: Vec<Rc<DexType>>,
}

#[derive(Debug)]
pub struct DexParameter {
    /// The type of this parameter
    pub type_: Rc<DexType>,

    /// The name of this parameter (optional).
    ///
    /// *Note*: The actual name can be retriebed either through
    ///         parsing debug info items or through the `@MethodParameters`
    ///         annotation.
    pub name: Option<Rc<String>>,

    /// list of annotations associated with this parameter (optional)
    pub annotations: Vec<DexAnnotation>,

    /// The access flags for this parameter organized as a single [AccessFlags]
    /// instance.
    pub access_flags: Option<AccessFlags>,
}

impl DexParameter {
    pub fn read_annotations<R>(&mut self, dex: &mut Dex<'_, R>) -> Result<()>
    where
        R: Read + Seek,
    {
        let set_ref_list = AnnotationSetRefList::read(dex.fd)?;
        for set_ref in &set_ref_list.list {
            if set_ref.annotations_off == 0 {
                continue;
            }
            dex.seeks(set_ref.annotations_off as u64)?;
            DexAnnotation::read_set_into(dex, &mut self.annotations)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DexMethod {
    pub identity: u32,

    /// The declaring class of this method in the DEX file stored as
    /// a type reference.
    pub class: Rc<DexType>,

    /// The name of the method
    pub name: Rc<String>,

    /// The method signature as a prototype reference
    pub proto: Rc<DexPrototype>,

    /// list of annotations associated with this method (optional)
    pub annotations: Vec<DexAnnotation>,
    pub parameters: Vec<DexParameter>,

    /// The access flags for this method organized as a single [AccessFlags]
    /// instance.
    pub access_flags: Option<AccessFlags>,

    /// Optional code associated with this method (abstract or native methods
    /// won't store any code).
    pub code: Option<CodeItem>,

    /// Additional debug information for this method.
    pub debug_info: Option<DebugInfo>,
}

impl DexMethod {
    pub fn build<R>(
        dex: &mut Dex<'_, R>,
        encoded_method: &EncodedMethod,
        prev_diff: u32,
    ) -> Result<Self>
    where
        R: Read + Seek,
    {
        // The method_idx_diff value in the first encoded_method item in each
        // of the method types holds the index of the matching item in the method_ids
        // section.
        //
        // In subsequent items, however, this value is the difference from the index
        // of the previous item, and to calculate the method_ids index the difference
        // must be incremented to the previous method_idx_diff values.
        let index = prev_diff + encoded_method.method_idx_diff.0;
        let method_item = dex.get_method(index)?;

        let proto = dex.get_proto(method_item.proto_idx as u32)?;
        let mut parameters: Vec<DexParameter> = proto
            .parameters
            .iter()
            // The parameters will be cloned here to ensure we can infer the right
            // annotations or access flags once we've parsed additional debug information.
            .map(|x| DexParameter {
                type_: x.clone(),
                name: None,
                annotations: Vec::new(),
                access_flags: None,
            })
            .collect();

        let mut code: Option<CodeItem> = None;
        let mut debug: Option<DebugInfo> = None;
        if encoded_method.code_off.0 != 0 {
            // parse code item but don't start parsing instructions just yet
            dex.seeks(encoded_method.code_off.0 as u64)?;
            let code_item = CodeItem::read(dex.fd)?;

            if code_item.debug_info_off != 0 {
                // directly parse debug information
                dex.seeks(code_item.debug_info_off as u64)?;
                let debug_info = DebugInfoItem::read(dex.fd)?;
                DexMethod::apply_debug_info(&mut parameters, &debug_info, dex)?;

                // parse additional information
                debug = Some(debug_info.parse_debug_info(&code_item, dex, &proto)?);
            }
            code = Some(code_item);
        }

        // put everything together
        Ok(DexMethod {
            identity: index,
            class: dex.get_type(method_item.class_idx as u32)?,
            name: dex.get_string(method_item.name_idx)?,
            proto: proto.clone(),
            annotations: Vec::new(),
            parameters,
            access_flags: AccessFlags::from_bits(encoded_method.access_flags.0),
            code,
            debug_info: debug,
        })
    }

    fn apply_debug_info(
        parameters: &mut [DexParameter],
        debug_info: &DebugInfoItem,
        dex: IDexRef<'_>,
    ) -> Result<()> {
        for (i, param_name_idx) in debug_info.parameter_names.iter().enumerate() {
            if let ULeb128p1::Pos(index) = param_name_idx {
                parameters[i].name = Some(dex.get_string(*index)?);
            }
        }
        Ok(())
    }
}

/* Pulic API */
impl DexMethod {
    pub fn disasm(&self, dex: IDexRef<'_>) -> Result<Vec<Insn>> {
        if let Some(code) = &self.code {
            Ok(insns::disasm(code, dex)?)
        } else {
            Ok(Vec::new())
        }
    }
}