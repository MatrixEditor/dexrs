use super::{modifiers, ClassDef, DexFile, FieldId, InvokeType, MethodId, ACC_STATIC};
use crate::{
    file::{ACC_CONSTRUCTOR, ACC_INTERFACE},
    leb128::decode_leb128_off,
    Result,
};

pub trait ClassItemBase<'a>: Copy + Clone {
    fn read(&mut self, data: &'a [u8], pos: &mut usize);

    fn init(dex: &'a DexFile<'a>) -> Self;

    fn next_section(&mut self);
}

#[derive(Copy, Clone)]
pub struct Method<'a> {
    dex: &'a DexFile<'a>,

    pub index: u32,
    pub access_flags: u32,
    pub code_offset: u32,
    pub is_static_or_direct: bool,
}

impl<'a> Method<'a> {
    #[inline]
    pub fn get_direct_invoke_type(&self) -> InvokeType {
        if self.access_flags & ACC_STATIC != 0 {
            InvokeType::Static
        } else {
            InvokeType::Direct
        }
    }

    #[inline(always)]
    pub fn get_method_id(&self) -> Result<&'a MethodId> {
        self.dex.get_method_id(self.index)
    }

    #[inline(always)]
    pub fn get_virtual_invoke_type(&self, class_access_flags: u32) -> InvokeType {
        debug_assert!(self.access_flags & ACC_STATIC == 0x00);
        if class_access_flags & ACC_INTERFACE != 0 {
            InvokeType::Interface
        } else if (self.access_flags & ACC_CONSTRUCTOR != 0) {
            InvokeType::Super
        } else {
            InvokeType::Virtual
        }
    }
}

impl<'a> ClassItemBase<'a> for Method<'a> {
    fn read(&mut self, data: &'a [u8], pos: &mut usize) {
        self.index += decode_leb128_off::<u32>(&data[*pos..], pos);
        self.access_flags = decode_leb128_off::<u32>(&data[*pos..], pos);
        self.code_offset = decode_leb128_off::<u32>(&data[*pos..], pos);
    }

    fn init(dex: &'a DexFile<'a>) -> Self {
        Self {
            dex,
            index: 0,
            access_flags: 0,
            code_offset: 0,
            is_static_or_direct: false,
        }
    }

    fn next_section(&mut self) {
        self.is_static_or_direct = true;
    }
}

#[derive(Copy, Clone)]
pub struct Field<'a> {
    dex: &'a DexFile<'a>,

    pub index: u32,
    pub access_flags: u32,
    pub is_static: bool,
}

impl<'a> Field<'a> {
    #[inline(always)]
    pub fn is_static(&self) -> bool {
        self.is_static
    }

    pub fn get_field_id(&self) -> Result<&'a FieldId> {
        self.dex.get_field_id(self.index)
    }
}

impl<'a> ClassItemBase<'a> for Field<'a> {
    fn read(&mut self, data: &'a [u8], pos: &mut usize) {
        self.index += decode_leb128_off::<u32>(&data[*pos..], pos);
        self.access_flags = decode_leb128_off::<u32>(&data[*pos..], pos);
    }

    fn init(dex: &'a DexFile<'a>) -> Self {
        Self {
            dex,
            index: 0,
            access_flags: 0,
            is_static: true,
        }
    }

    fn next_section(&mut self) {
        self.is_static = false;
    }
}

pub struct ClassAccessor<'a> {
    dex: &'a DexFile<'a>,
    ptr_pos: usize,
    class_data: &'a [u8],

    pub num_static_fields: u32,
    pub num_instance_fields: u32,
    pub num_direct_methods: u32,
    pub num_virtual_methods: u32,

    // will be set after first time parsing the data
    static_fields_off: u32,
}

impl<'a> DexFile<'a> {
    pub fn get_class_accessor(&self, class_def: &ClassDef) -> Option<ClassAccessor<'_>> {
        match class_def.class_data_off {
            0 => None,
            off => Some(ClassAccessor::from_raw(self, &self.mmap[off as usize..])),
        }
    }
}

type FieldVisitor = fn(&Field<'_>) -> Result<()>;
type MethodVisitor = fn(&Method<'_>) -> Result<()>;

fn null_method_visitor(_method: &Method<'_>) -> Result<()> {
    Ok(())
}

fn null_field_visitor(_field: &Field<'_>) -> Result<()> {
    Ok(())
}

impl<'a> ClassAccessor<'a> {
    pub fn from_raw(dex: &'a DexFile<'a>, class_data: &'a [u8]) -> Self {
        let mut accessor = Self {
            dex,
            ptr_pos: 0,
            class_data,
            num_direct_methods: 0,
            num_virtual_methods: 0,
            num_static_fields: 0,
            num_instance_fields: 0,
            static_fields_off: 0,
        };
        accessor.num_static_fields = decode_leb128_off(&class_data, &mut accessor.ptr_pos);
        accessor.num_instance_fields = decode_leb128_off(&class_data[accessor.ptr_pos..], &mut accessor.ptr_pos);
        accessor.num_direct_methods = decode_leb128_off(&class_data[accessor.ptr_pos..], &mut accessor.ptr_pos);
        accessor.num_virtual_methods = decode_leb128_off(&class_data[accessor.ptr_pos..], &mut accessor.ptr_pos);
        accessor.static_fields_off = accessor.ptr_pos as u32;
        accessor
    }

    #[inline(always)]
    pub fn num_fields(&self) -> usize {
        self.num_instance_fields as usize + self.num_static_fields as usize
    }

    #[inline(always)]
    pub fn num_methods(&self) -> usize {
        self.num_direct_methods as usize + self.num_virtual_methods as usize
    }

    #[inline(always)]
    pub fn visit_fields(
        &self,
        static_field_visitor: FieldVisitor,
        instance_field_visitor: FieldVisitor,
    ) -> Result<()> {
        self.visit_fields_and_methods(
            static_field_visitor,
            instance_field_visitor,
            null_method_visitor,
            null_method_visitor,
        )
    }

    #[inline(always)]
    pub fn visit_methods(
        &self,
        direct_method_visitor: MethodVisitor,
        virtual_method_visitor: MethodVisitor,
    ) -> Result<()> {
        self.visit_fields_and_methods(
            null_field_visitor,
            null_field_visitor,
            direct_method_visitor,
            virtual_method_visitor,
        )
    }

    #[inline]
    pub fn visit_fields_and_methods(
        &self,
        static_field_visitor: FieldVisitor,
        instance_field_visitor: FieldVisitor,
        direct_method_visitor: MethodVisitor,
        virtual_method_visitor: MethodVisitor,
    ) -> Result<()> {
        let mut field = Field::init(self.dex);
        let mut offset = self.static_fields_off as usize;
        if offset == 0 {
            panic!("Static fields offset is zero which means there is no class data associated with this class");
        }

        self.visit_members(
            self.num_static_fields,
            &mut offset,
            static_field_visitor,
            &mut field,
        )?;
        // switch to instance fields
        field.next_section();
        self.visit_members(
            self.num_instance_fields,
            &mut offset,
            instance_field_visitor,
            &mut field,
        )?;

        let mut method = Method::init(self.dex);
        self.visit_members(
            self.num_direct_methods,
            &mut offset,
            direct_method_visitor,
            &mut method,
        )?;
        method.next_section();
        self.visit_members(
            self.num_virtual_methods,
            &mut offset,
            virtual_method_visitor,
            &mut method,
        )
    }

    #[inline(always)]
    pub fn get_fields(&self) -> DataIterator<'a, Field<'a>> {
        DataIterator::new(
            self.dex,
            self.class_data,
            self.static_fields_off as usize,
            self.num_static_fields as usize,
            self.num_fields(),
        )
    }

    #[inline(always)]
    pub fn get_static_fieds(&self) -> impl Iterator<Item = Field<'a>> {
        DataIterator::new(
            self.dex,
            self.class_data,
            self.static_fields_off as usize,
            self.num_static_fields as usize,
            self.num_static_fields as usize,
        )
    }

    #[inline(always)]
    pub fn get_instance_fields(&self) -> impl Iterator<Item = Field<'a>> {
        self.get_fields().skip(self.num_static_fields as usize)
    }

    #[inline(always)]
    pub fn get_methods(&self) -> Result<impl Iterator<Item = Method<'a>>> {
        let mut field = Field::init(self.dex);
        let mut offset = self.static_fields_off as usize;
        self.visit_members(
            self.num_fields() as u32,
            &mut offset,
            null_field_visitor,
            &mut field,
        )?;
        // switch to instance fields
        Ok(DataIterator::new(
            self.dex,
            self.class_data,
            offset as usize,
            self.num_direct_methods as usize,
            self.num_methods(),
        ))
    }

    #[inline(always)]
    pub fn get_direct_methods(&self) -> Result<impl Iterator<Item = Method<'a>>> {
        Ok(self.get_methods()?.take(self.num_direct_methods as usize))
    }

    #[inline(always)]
    pub fn get_virtual_methods(&self) -> Result<impl Iterator<Item = Method<'a>>> {
        Ok(self.get_methods()?.skip(self.num_direct_methods as usize))
    }

    #[inline(always)]
    fn visit_members<T, F>(
        &self,
        count: u32,
        offset: &mut usize,
        visitor: F,
        iter: &mut T,
    ) -> Result<()>
    where
        T: ClassItemBase<'a>,
        F: Fn(&T) -> Result<()>,
    {
        for _ in 0..count {
            iter.read(&self.class_data, offset);
            visitor(&iter)?;
        }
        Ok(())
    }
}

pub struct DataIterator<'a, T: ClassItemBase<'a>> {
    class_data: &'a [u8],
    value: T,

    pos: usize,           // mutable
    off: usize,           // mutable
    partition_pos: usize, // const
    end_pos: usize,       // const
}

impl<'a, T: ClassItemBase<'a>> DataIterator<'a, T> {
    pub fn new(
        dex: &'a DexFile<'a>,
        class_data: &'a [u8],
        start_pos: usize,
        partition_pos: usize,
        end_pos: usize,
    ) -> Self {
        Self {
            class_data,
            value: T::init(dex),
            pos: 0,
            partition_pos,
            off: start_pos,
            end_pos,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.pos < self.end_pos
    }

    pub fn offset(&self) -> usize {
        self.off
    }
}

impl<'a, T: ClassItemBase<'a>> Iterator for DataIterator<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_valid() {
            if self.pos == self.partition_pos {
                self.value.next_section();
            }
            self.value.read(&self.class_data, &mut self.off);
            self.pos += 1;
            return Some(self.value);
        }
        return None;
    }
}
