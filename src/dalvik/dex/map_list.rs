use binrw::binrw;

use super::types::*;

#[binrw]
#[brw(repr(UShort), little)]
#[derive(Debug, PartialEq, Eq)]
pub enum MapListItemType {
    /// header item type
    ///
    /// @size: `0x70`
    /// @type: [HeaderItem]
    HeaderItem = 0x0000,

    /// string identifier item type
    ///
    /// @size: `0x04`
    /// @type: [StringIdItem]
    StringIdItem = 0x0001,

    /// type identifier item type
    ///
    /// @size: `0x04`
    /// @type: [TypeIdItem]
    TypeIdItem = 0x0002,

    /// prototype identifier item type
    ///
    /// @size: `0x0C`
    /// @type: [ProtoIdItem]
    ProtoIdItem = 0x0003,

    /// field identifier item type
    ///
    /// @size: `0x08`
    /// @type: [FieldIdItem]
    FieldIdItem = 0x0004,

    /// method identifier item type
    ///
    /// @size: `0x08`
    /// @type: [MethodIdItem]
    MethodIdItem = 0x0005,

    /// class definition item type
    ///
    /// @size: `0x0C`
    /// @type: [ClassDefItem]
    ClassDefItem = 0x0006,

    /// call site id item type
    ///
    /// @size: `0x08`
    /// @type: [CallSiteIdItem]
    CallSiteIdItem = 0x0007,

    /// method handle item type
    ///
    /// @size: `0x08`
    /// @type: [MethodHandleItem]
    MethodHandleItem = 0x0008,

    /// map list type
    ///
    /// @size: `4 + (item.size * 12)`
    MapList = 0x1000,

    /// type list type
    ///
    /// @size: `4 + (item.size * 2)`
    TypeList = 0x1001,

    /// annotation set ref list type
    ///
    /// @size: `4 + (item.size * 4)`
    /// @type: [AnnotationSetRefList]
    AnnotationSetRefList = 0x1002,

    /// annotation set item type
    ///
    /// @size: `4 + (item.size * 4)`
    /// @type: [AnnotationSetItem]
    AnnotationSetItem = 0x1003,

    /// class data item type
    ///
    /// @size: `0x08`
    /// @type: [ClassDataItem]
    ClassDataItem = 0x2000,

    /// code item type
    ///
    /// @size: _implicit_
    /// @type: [CodeItem](CodeItem)
    CodeItem = 0x2001,

    /// string data item type
    ///
    /// @size: _implicit_
    /// @type: [StringDataItem](StringDataItem)
    StringDataItem = 0x2002,

    /// debug info item type
    ///
    /// @size: _implicit_
    /// @type: [DebugInfoItem](DebugInfoItem)
    DebugInfoItem = 0x2003,

    /// annotation item type
    ///
    /// @size: _implicit_
    /// @type: [AnnotationItem](AnnotationItem)
    AnnotationItem = 0x2004,

    /// encoded array item type
    ///
    /// @size: _implicit_
    /// @type: [EncodedArrayItem](EncodedArrayItem)
    EncodedArrayItem = 0x2005,

    /// annotations directory item type
    ///
    /// @size: _implicit_
    /// @type: [AnnotationsDirectoryItem](AnnotationsDirectoryItem)
    AnnotationsDirectoryItem = 0x2006,

    /// hidden api list class data item type
    ///
    /// @size: _implicit_
    /// @type: [HiddenAPIClassDataItem](HiddenAPIClassDataItem)
    HiddenApiListClassDataItem = 0xF000,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct MapListItem {
    /// type of the item
    #[br(align_after = 4)]
    pub type_: MapListItemType,

    /// count of the number of items to be found at the indicated offset
    pub size: UInt,

    /// offset from the start of the file to the item
    pub offset: UInt,
}

/// A map list is a list of the entire contents of a file, in order.
#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct MapList {
    /// size of the list, in entries
    // #[bw(calc = list.len() as u32)]
    pub size: UInt,

    // elements of the list
    #[br(count = size as usize)]
    list: Vec<MapListItem>, // MapListItem[this.size]
}

impl MapList {
    pub fn get(&self, type_: MapListItemType) -> Option<&MapListItem> {
        self.list.iter().find(|&item| item.type_ == type_)
    }

    pub fn item_size(&self, type_: MapListItemType) -> usize {
        match self.get(type_) {
            Some(item) => item.size as usize,
            None => 0,
        }
    }

    pub fn item_offset(&self, type_: MapListItemType) -> usize {
        match self.get(type_) {
            Some(item) => item.offset as usize,
            None => 0,
        }
    }
}
