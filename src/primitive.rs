/// Java primitive type classification, matching ART's `Primitive` class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrimitiveType {
    /// Reference (non-primitive) type.
    Not = 0,
    Boolean = 1,
    Byte = 2,
    Char = 3,
    Short = 4,
    Int = 5,
    Long = 6,
    Float = 7,
    Double = 8,
    Void = 9,
}

impl PrimitiveType {
    /// Returns the `PrimitiveType` for the given JVM descriptor character.
    pub fn from_char(c: char) -> Self {
        match c {
            'Z' => Self::Boolean,
            'B' => Self::Byte,
            'C' => Self::Char,
            'S' => Self::Short,
            'I' => Self::Int,
            'J' => Self::Long,
            'F' => Self::Float,
            'D' => Self::Double,
            'V' => Self::Void,
            _ => Self::Not,
        }
    }

    /// Returns the single-char DEX type descriptor, or `None` for `Not`.
    pub fn descriptor(self) -> Option<&'static str> {
        match self {
            Self::Boolean => Some("Z"),
            Self::Byte => Some("B"),
            Self::Char => Some("C"),
            Self::Short => Some("S"),
            Self::Int => Some("I"),
            Self::Long => Some("J"),
            Self::Float => Some("F"),
            Self::Double => Some("D"),
            Self::Void => Some("V"),
            Self::Not => None,
        }
    }

    /// Returns the fully-qualified descriptor for the boxed version of this type, or `None` for `Not`.
    pub fn boxed_descriptor(self) -> Option<&'static str> {
        match self {
            Self::Boolean => Some("Ljava/lang/Boolean;"),
            Self::Byte => Some("Ljava/lang/Byte;"),
            Self::Char => Some("Ljava/lang/Character;"),
            Self::Short => Some("Ljava/lang/Short;"),
            Self::Int => Some("Ljava/lang/Integer;"),
            Self::Long => Some("Ljava/lang/Long;"),
            Self::Float => Some("Ljava/lang/Float;"),
            Self::Double => Some("Ljava/lang/Double;"),
            Self::Void => Some("Ljava/lang/Void;"),
            Self::Not => None,
        }
    }

    /// Returns the storage size in bytes (0 for `Void`, 4 for object references).
    pub fn component_size(self) -> usize {
        match self {
            Self::Void => 0,
            Self::Boolean | Self::Byte => 1,
            Self::Char | Self::Short => 2,
            Self::Int | Self::Float | Self::Not => 4,
            Self::Long | Self::Double => 8,
        }
    }

    /// Returns `log2(component_size())`.
    pub fn component_size_shift(self) -> u32 {
        match self {
            Self::Void | Self::Boolean | Self::Byte => 0,
            Self::Char | Self::Short => 1,
            Self::Int | Self::Float | Self::Not => 2,
            Self::Long | Self::Double => 3,
        }
    }

    /// Returns `true` for numeric primitive types (byte/char/short/int/long/float/double).
    pub fn is_numeric(self) -> bool {
        matches!(
            self,
            Self::Byte | Self::Char | Self::Short | Self::Int | Self::Long | Self::Float | Self::Double
        )
    }

    /// Returns `true` for 64-bit types (`long` or `double`).
    pub fn is_64bit(self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    /// Returns `true` if this is any primitive type (not `Not`).
    pub fn is_primitive(self) -> bool {
        !matches!(self, Self::Not)
    }

    /// Returns the human-readable Java type name (e.g. `"int"`, `"boolean"`, `"Object"`).
    pub fn pretty_name(self) -> &'static str {
        match self {
            Self::Not => "Object",
            Self::Boolean => "boolean",
            Self::Byte => "byte",
            Self::Char => "char",
            Self::Short => "short",
            Self::Int => "int",
            Self::Long => "long",
            Self::Float => "float",
            Self::Double => "double",
            Self::Void => "void",
        }
    }
}

impl std::fmt::Display for PrimitiveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.pretty_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_descriptors() {
        for pt in [
            PrimitiveType::Boolean,
            PrimitiveType::Byte,
            PrimitiveType::Char,
            PrimitiveType::Short,
            PrimitiveType::Int,
            PrimitiveType::Long,
            PrimitiveType::Float,
            PrimitiveType::Double,
            PrimitiveType::Void,
        ] {
            let desc = pt.descriptor().unwrap();
            let back = PrimitiveType::from_char(desc.chars().next().unwrap());
            assert_eq!(pt, back);
        }
        assert_eq!(PrimitiveType::from_char('X'), PrimitiveType::Not);
    }
}
