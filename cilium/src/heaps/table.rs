use std::fmt::Debug;
use std::io::{Cursor, Error, ErrorKind, Read};
use std::sync::Arc;
use bitflags::bitflags;
use owning_ref::ArcRef;
use cilium_derive::{FromRepr, Table};

use crate::heaps::{BlobIndex, GuidIndex, MetadataHeap, MetadataHeapKind, StringIndex};
use crate::indices::coded_index::{CustomAttributeType, HasConstant, HasCustomAttribute, HasFieldMarshal, HasSemantics, Implementation, MemberForwarded, MemberRefParent, MethodDefOrRef, TypeDefOrRef, TypeOrMethodDef};
use crate::indices::sizes::*;
use crate::utilities::{enumerate_set_bits, FromByteStream, impl_from_byte_stream};

#[derive(Debug)]
pub struct TableHeap {
	major_version: u8,
	minor_version: u8,
	tables: Vec<Arc<dyn Table>>,
}

impl MetadataHeap for TableHeap {
	fn name(&self) -> &str {
		"~#"
	}

	fn data(&self) -> &[u8] {
		&[]
	}

	fn kind(&self) -> MetadataHeapKind {
		MetadataHeapKind::Table
	}
}

impl TryFrom<ArcRef<[u8]>> for TableHeap {
	type Error = Error;
	fn try_from(value: ArcRef<[u8]>) -> Result<Self, Self::Error> {
		#[repr(C)]
		#[derive(Copy, Clone)]
		struct Header {
			reserved_0: u32,
			major_version: u8,
			minor_version: u8,
			heap_sizes: u8,
			reserved_1: u8,
			valid: u64,
			sorted: u64,
		}

		impl_from_byte_stream!(Header);

		let mut stream = Cursor::new(value.as_ref());
		let Header {
			heap_sizes, valid,
			minor_version, major_version,
			..
		} = Header::read(&mut stream, &())?;

		let table_count = valid.count_ones() as usize;
		let mut table_sizes = vec![0u32; 64];

		for i in enumerate_set_bits(valid) {
			let mut bytes = 0u32.to_ne_bytes();
			stream.read_exact(&mut bytes)?;
			table_sizes[i] = u32::from_le_bytes(bytes);
		}

		let idx_sizes = IndexSizes::new(heap_sizes, table_sizes.as_slice().try_into().unwrap());

		let mut tables: Vec<Arc<dyn Table>> = Vec::with_capacity(table_count);
		for i in enumerate_set_bits(valid) {
			let len = table_sizes[i] as usize;
			let Some(kind) = TableKind::from_repr(i) else {
				return Err(ErrorKind::InvalidData.into());
			};

			tables.push(match kind {
				TableKind::Module => Arc::new(ModuleTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::TypeRef => todo!("Unimplemented table TypeRef"),
				TableKind::TypeDef => Arc::new(TypeDefTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::FieldPtr => todo!("Unimplemented table FieldPtr"),
				TableKind::Field => Arc::new(FieldTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::MethodPtr => todo!("Unimplemented table MethodPtr"),
				TableKind::MethodDef => Arc::new(MethodDefTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::ParamPtr => todo!("Unimplemented table ParamPtr"),
				TableKind::Param => Arc::new(ParamTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::InterfaceImpl => Arc::new(InterfaceImplTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::MemberRef => Arc::new(MemberRefTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::Constant => Arc::new(ConstantTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::CustomAttribute => Arc::new(CustomAttributeTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::FieldMarshal => Arc::new(FieldMarshalTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::DeclSecurity => todo!("Unimplemented table DeclSecurity"),
				TableKind::ClassLayout => Arc::new(ClassLayoutTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::FieldLayout => Arc::new(FieldLayoutTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::StandAloneSig => Arc::new(StandAloneSigTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::EventMap => Arc::new(EventMapTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::EventPtr => todo!("Unimplemented table EventPtr"),
				TableKind::Event => Arc::new(EventTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::PropertyMap => Arc::new(PropertyMapTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::PropertyPtr => todo!("Unimplemented table PropertyPtr"),
				TableKind::Property => Arc::new(PropertyTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::MethodSemantics => Arc::new(MethodSemanticsTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::MethodImpl => Arc::new(MethodImplTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::ModuleRef => Arc::new(ModuleRefTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::TypeSpec => Arc::new(TypeSpecTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::ImplMap => Arc::new(ImplMapTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::FieldRVA => Arc::new(FieldRVATable::read(&mut stream, &idx_sizes, len)?),
				TableKind::EncLog => todo!("Unimplemented table EncLog"),
				TableKind::EncMap => todo!("Unimplemented table EncMap"),
				TableKind::Assembly => Arc::new(AssemblyTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::AssemblyProcessor => todo!("Unimplemented table AssemblyProcessor"),
				TableKind::AssemblyOS => todo!("Unimplemented table AssemblyOS"),
				TableKind::AssemblyRef => todo!("Unimplemented table AssemblyRef"),
				TableKind::AssemblyRefProcessor => todo!("Unimplemented table AssemblyRefProcessor"),
				TableKind::AssemblyRefOS => todo!("Unimplemented table AssemblyRefOS"),
				TableKind::File => todo!("Unimplemented table File"),
				TableKind::ExportedType => todo!("Unimplemented table ExportedType"),
				TableKind::ManifestResource => Arc::new(ManifestResourceTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::NestedClass => Arc::new(NestedClassTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::GenericParam => Arc::new(GenericParamTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::MethodSpec => Arc::new(MethodSpecTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::GenericParamConstraint => Arc::new(GenericParamConstraintTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::Document => todo!("Unimplemented table Document"),
				TableKind::MethodDebugInformation => todo!("Unimplemented table MethodDebugInformation"),
				TableKind::LocalScope => todo!("Unimplemented table LocalScope"),
				TableKind::LocalVariable => todo!("Unimplemented table LocalVariable"),
				TableKind::LocalConstant => todo!("Unimplemented table LocalConstant"),
				TableKind::ImportScope => todo!("Unimplemented table ImportScope"),
				TableKind::StateMachineMethod => todo!("Unimplemented table StateMachineMethod"),
				TableKind::CustomDebugInformation => todo!("Unimplemented table CustomDebugInformation"),
			});
		}

		Ok(Self {
			major_version,
			minor_version,
			tables,
		})
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromRepr)]
pub enum TableKind {
	Module = 0x00,
	TypeRef = 0x01,
	TypeDef = 0x02,
	FieldPtr = 0x03,
	Field = 0x04,
	MethodPtr = 0x05,
	MethodDef = 0x06,
	ParamPtr = 0x07,
	Param = 0x08,
	InterfaceImpl = 0x09,
	MemberRef = 0x0a,
	Constant = 0x0b,
	CustomAttribute = 0x0c,
	FieldMarshal = 0x0d,
	DeclSecurity = 0x0e,
	ClassLayout = 0x0f,
	FieldLayout = 0x10,
	StandAloneSig = 0x11,
	EventMap = 0x12,
	EventPtr = 0x13,
	Event = 0x14,
	PropertyMap = 0x15,
	PropertyPtr = 0x16,
	Property = 0x17,
	MethodSemantics = 0x18,
	MethodImpl = 0x19,
	ModuleRef = 0x1a,
	TypeSpec = 0x1b,
	ImplMap = 0x1c,
	FieldRVA = 0x1d,
	EncLog = 0x1e,
	EncMap = 0x1f,
	Assembly = 0x20,
	AssemblyProcessor = 0x21,
	AssemblyOS = 0x22,
	AssemblyRef = 0x23,
	AssemblyRefProcessor = 0x24,
	AssemblyRefOS = 0x25,
	File = 0x26,
	ExportedType = 0x27,
	ManifestResource = 0x28,
	NestedClass = 0x29,
	GenericParam = 0x2a,
	MethodSpec = 0x2b,
	GenericParamConstraint = 0x2c,

	Document = 0x30,
	MethodDebugInformation = 0x31,
	LocalScope = 0x32,
	LocalVariable = 0x33,
	LocalConstant = 0x34,
	ImportScope = 0x35,
	StateMachineMethod = 0x36,
	CustomDebugInformation = 0x37,
}

pub trait Table: Debug {
	fn len(&self) -> usize;
	fn kind(&self) -> TableKind;
}

#[derive(Debug, Clone, Table)]
pub struct Module {
	generation: u16,
	name: StringIndex,
	mv_id: GuidIndex,
	enc_id: GuidIndex,
	enc_base_id: GuidIndex,
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct TypeAttributes: u32 {
		// #### Visibility attributes ####
		/// Use this mask to retrieve visibility information.
		const VISIBILITY_MASK = 0x00000007;
		/// Class has no public scope.
		const NOT_PUBLIC = 0x00000000;
		/// Class has public scope.
		const PUBLIC = 0x00000001;
		/// Class is nested with public visibility.
		const NESTED_PUBLIC = 0x00000002;
		/// Class is nested with private visibility.
		const NESTED_PRIVATE = 0x00000003;
		/// Class is nested with family visibility.
		const NESTED_FAMILY = 0x00000004;
		/// Class is nested with assembly visibility.
		const NESTED_ASSEMBLY = 0x00000005;
		/// Class is nested with family and assembly.
		const NESTED_FAMILY_AND_ASSEMBLY = 0x00000006;
		/// Class is nested with family or assembly.
		const NESTED_FAMILY_OR_ASSEMBLY = 0x00000007;

		// #### Class layout attributes ####
		/// Use this mask to retrieve class layout information.
		const LAYOUT_MASK = 0x00000018;
		/// Class fields are auto-laid out.
		const AUTO_LAYOUT = 0x00000000;
		/// Class fields are laid out sequentially.
		const SEQUENTIAL_LAYOUT = 0x00000008;
		/// Layout is supplied explicitly.
		const EXPLICIT_LAYOUT = 0x00000010;

		// #### Class semantics attributes ####
		/// Use this mask to retrive class semantics information.
		const CLASS_SEMANTICS_MASK = 0x00000020;
		/// Type is a class.
		const CLASS = 0x00000000;
		/// Type is an interface.
		const INTERFACE = 0x00000020;

		// #### Special semantics in addition to class semantics ####
		/// Class is abstract.
		const ABSTRACT =  0x00000080;
		/// Class cannot be extended.
		const SEALED =  0x00000100;
		/// Class name is special.
		const SPECIAL_NAME =  0x00000400;

		// #### Implementation Attributes ####
		/// Class/Interface is imported.
		const IMPORTED = 0x00001000;
		/// Class/Interface is imported.
		const SERIALIZABLE = 0x00002000;

		// #### String formatting Attributes ####
		/// Use this mask to retrieve string information for native interop.
		const STRING_FORMAT_MASK = 0x00030000;
		/// LPSTR is interpreted as ANSI.
		const ANSI_CLASS =  0x00000000;
		/// LPSTR is interpreted as Unicode
		const UNICODE_CLASS =  0x00010000;
		/// LPSTR is interpreted automatically.
		const AUTO_CLASS =  0x00020000;
		/// A non-standard encoding specified by CUSTOM_STRING_FORMAT_MASK.
		const CUSTOM_FORMAT_CLASS = 0x00030000;
		/// Use this mask to retrieve non-standard encoding information for native interop. The meaning of the values of these 2 bits is unspecified.
		const CUSTOM_STRING_FORMAT_MASK = 0x00C00000;

		// #### Class Initialization Attributes ####
		/// Initialize the class before first static field access.
		const BeforeFieldInit = 0x00100000;

		// #### Additional Attributes ####
		/// CLI provides 'special' behavior, depending upon the name of the Type.
		const RTSpecialName = 0x00000800;
		/// Type has security associate with it.
		const HasSecurity = 0x00040000;
		/// This ExportedType entry is a type forwarder.
		const IsTypeForwarder = 0x00200000;
	}
}

impl_from_byte_stream!(TypeAttributes);

#[derive(Debug, Clone, Table)]
pub struct TypeDef {
	flags: TypeAttributes,
	type_name: StringIndex,
	type_namespace: StringIndex,
	extends: TypeDefOrRef,
	field_list: FieldIndex,
	method_list: MethodDefIndex,
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct FieldAttributes: u16 {
		// #### Accessibility attributes ####
		/// Use this mask to retrieve access information.
		const FIELD_ACCESS_MASK = 0x0007;
		/// Member not referenceable.
		const COMPILER_CONTROLLED = 0x0000;
		/// Accessible only by the parent type.
		const PRIVATE = 0x0001;
		/// Accessible by sub-types only in this Assembly.
		const FAMILY_AND_ASSEMBLY = 0x0002;
		/// Accessibly by anyone in the Assembly.
		const ASSEMBLY = 0x0003;
		/// Accessible only by type and sub-types.
		const FAMILY = 0x0004;
		/// Accessibly by sub-types anywhere, plus anyone in assembly.
		const FAMILY_OR_ASSEMBLY = 0x0005;
		/// Accessibly by anyone who has visibility to this scope field contract attributes.
		const PUBLIC = 0x0006;
		/// Defined on type, else per instance.
		const STATIC = 0x0010;
		/// Field can only be initialized, not written to after init.
		const INIT_ONLY = 0x0020;
		/// Value is compile time constant.
		const LITERAL = 0x0040;
		/// Reserved (to indicate this field should not be serialized when type is remoted).
		const NOT_SERIALIZED = 0x0080;
		/// Field is special.
		const SPECIAL_NAME = 0x0200;

		// #### Interop Attribute ####
		/// Implementation is forwarded through PInvoke.
		const PINVOKE_IMPL = 0x2000;

		// #### Additional Attributes ####
		/// CLI provides 'special' behavior, depending upon the name of the field.
		const RT_SPECIAL_NAME = 0x0400;
		/// Field has marshalling information.
		const HAS_FIELD_MARSHAL = 0x1000;
		/// Field has default.
		const HAS_DEFAULT = 0x8000;
		/// Field has RVA.
		const HAS_FIELD_RVA = 0x0100;
	}
}

impl_from_byte_stream!(FieldAttributes);

#[derive(Debug, Clone, Table)]
pub struct Field {
	flags: FieldAttributes,
	name: StringIndex,
	signature: BlobIndex,
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct MethodAttributes: u16 {
		//TODO
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct MethodImplAttributes: u16 {
		//TODO
	}
}

impl_from_byte_stream!(MethodAttributes);
impl_from_byte_stream!(MethodImplAttributes);

#[derive(Debug, Clone, Table)]
pub struct MethodDef {
	rva: u32,
	impl_flags: MethodAttributes,
	flags: MethodAttributes,
	name: StringIndex,
	signature: BlobIndex,
	param_list: ParamIndex,
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct ParamAttributes: u16 {
		//TODO
	}
}

impl_from_byte_stream!(ParamAttributes);

#[derive(Debug, Clone, Table)]
pub struct Param {
	flags: ParamAttributes,
	sequence: u16,
	name: StringIndex,
}

#[derive(Debug, Clone, Table)]
pub struct InterfaceImpl {
	class: TypeDefIndex,
	interface: TypeDefOrRef,
}

#[derive(Debug, Clone, Table)]
pub struct MemberRef {
	class: MemberRefParent,
	name: StringIndex,
	signature: BlobIndex,
}

#[derive(Debug, Clone, Table)]
pub struct Constant {
	ty: [u8; 2],
	parent: HasConstant,
	value: BlobIndex,
}

#[derive(Debug, Clone, Table)]
pub struct CustomAttribute {
	parent: HasCustomAttribute,
	ty: CustomAttributeType,
	value: BlobIndex,
}

#[derive(Debug, Clone, Table)]
pub struct FieldMarshal {
	parent: HasFieldMarshal,
	native_type: BlobIndex,
}

#[derive(Debug, Clone, Table)]
pub struct ClassLayout {
	packing_size: u16,
	class_size: u32,
	parent: TypeDefIndex,
}

#[derive(Debug, Clone, Table)]
pub struct FieldLayout {
	offset: u32,
	field: FieldIndex,
}

#[derive(Debug, Clone, Table)]
pub struct StandAloneSig {
	signature: BlobIndex
}

#[derive(Debug, Clone, Table)]
pub struct EventMap {
	parent: TypeDefIndex,
	event_list: EventIndex
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct EventAttributes: u16 {
		//TODO
	}
}

impl_from_byte_stream!(EventAttributes);

#[derive(Debug, Clone, Table)]
pub struct Event {
	flags: EventAttributes,
	name: StringIndex,
	ty: TypeDefOrRef,
}

#[derive(Debug, Clone, Table)]
pub struct PropertyMap {
	parent: TypeDefIndex,
	property_list: PropertyIndex
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct PropertyAttributes: u16 {
		//TODO
	}
}

impl_from_byte_stream!(PropertyAttributes);

#[derive(Debug, Clone, Table)]
pub struct Property {
	flags: PropertyAttributes,
	name: StringIndex,
	ty: TypeDefOrRef,
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct MethodSemanticsAttributes: u16 {
		//TODO
	}
}

impl_from_byte_stream!(MethodSemanticsAttributes);

#[derive(Debug, Clone, Table)]
pub struct MethodSemantics {
	flags: MethodSemanticsAttributes,
	method: MethodDefIndex,
	association: HasSemantics,
}

#[derive(Debug, Clone, Table)]
pub struct MethodImpl {
	class: TypeDefIndex,
	body: MethodDefOrRef,
	declaration: MethodDefOrRef,
}

#[derive(Debug, Clone, Table)]
pub struct ModuleRef {
	name: StringIndex,
}

#[derive(Debug, Clone, Table)]
pub struct TypeSpec {
	signature: BlobIndex,
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct PInvokeAttributes: u16 {
		//TODO
	}
}

impl_from_byte_stream!(PInvokeAttributes);

#[derive(Debug, Clone, Table)]
pub struct ImplMap {
	flags: PInvokeAttributes,
	member_forwarded: MemberForwarded,
	import_name: StringIndex,
	import_scope: ModuleRefIndex,
}

#[derive(Debug, Clone, Table)]
pub struct FieldRVA {
	rva: u32,
	field: FieldIndex,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromRepr)]
pub enum AssemblyHashAlgorithm {
	None		= 0x0000,
	MD5			= 0x8003,
	SHA1		= 0x8004,
	SHA256		= 0x800C,
	SHA384		= 0x800D,
	SHA512		= 0x800E,
}

impl_from_byte_stream!(AssemblyHashAlgorithm);

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct AssemblyFlags: u32 {
		//TODO
	}
}

impl_from_byte_stream!(AssemblyFlags);

#[derive(Debug, Clone, Table)]
pub struct Assembly {
	hash_algorithm: AssemblyHashAlgorithm,
	major_version: u16,
	minor_version: u16,
	revision_number: u16,
	flags: AssemblyFlags,
	public_key: BlobIndex,
	name: StringIndex,
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct ManifestResourceAttributes: u32 {
		//TODO
	}
}

impl_from_byte_stream!(ManifestResourceAttributes);

#[derive(Debug, Clone, Table)]
pub struct ManifestResource {
	offset: u32,
	flags: ManifestResourceAttributes,
	name: StringIndex,
	implementation: Implementation,
}

#[derive(Debug, Clone, Table)]
pub struct NestedClass {
	nested_class: TypeDefIndex,
	enclosing_class: TypeDefIndex,
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct GenericParamAttributes: u16 {
		//TODO
	}
}

impl_from_byte_stream!(GenericParamAttributes);

#[derive(Debug, Clone, Table)]
pub struct GenericParam {
	number: u16,
	flags: GenericParamAttributes,
	owner: TypeOrMethodDef,
	name: StringIndex,
}

#[derive(Debug, Clone, Table)]
pub struct MethodSpec {
	method: MethodDefOrRef,
	instantiation: BlobIndex,
}

#[derive(Debug, Clone, Table)]
pub struct GenericParamConstraint {
	owner: GenericParamIndex,
	constraint: TypeDefOrRef,
}
