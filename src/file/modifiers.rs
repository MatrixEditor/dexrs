#[repr(u32)]
#[derive(Default)]
pub enum InvokeType {
    Static = 0x00,
    Direct,
    Virtual,
    Super,
    Interface,
    Polymorphic,
    #[default]
    Custom,
}

pub const ACC_PUBLIC: u32 = 0x0001; // class, field, method, ic
pub const ACC_PRIVATE: u32 = 0x0002; // field, method, ic
pub const ACC_PROTECTED: u32 = 0x0004; // field, method, ic
pub const ACC_STATIC: u32 = 0x0008; // field, method, ic
pub const ACC_FINAL: u32 = 0x0010; // class, field, method, ic
pub const ACC_SYNCHRONIZED: u32 = 0x0020; // method (only allowed on natives)
pub const ACC_SUPER: u32 = 0x0020; // class (not used in dex)
pub const ACC_VOLATILE: u32 = 0x0040; // field
pub const ACC_BRIDGE: u32 = 0x0040; // method (1.5)
pub const ACC_TRANSIENT: u32 = 0x0080; // field
pub const ACC_VARARGS: u32 = 0x0080; // method (1.5)
pub const ACC_NATIVE: u32 = 0x0100; // method
pub const ACC_INTERFACE: u32 = 0x0200; // class, ic
pub const ACC_ABSTRACT: u32 = 0x0400; // class, method, ic
pub const ACC_STRICT: u32 = 0x0800; // method
pub const ACC_SYNTHETIC: u32 = 0x1000; // class, field, method, ic
pub const ACC_ANNOTATION: u32 = 0x2000; // class, ic (1.5)
pub const ACC_ENUM: u32 = 0x4000; // class, field, ic (1.5)

pub const ACC_CONSTRUCTOR: u32 =           0x00010000;  // method (dex only) <(cl)init>
pub const ACC_DECLARED_SYNCHRONIZED: u32 =  0x00020000;  // method (dex only)
pub const ACC_CLASSISPROXY: u32 =          0x00040000;  // class  (dex only)