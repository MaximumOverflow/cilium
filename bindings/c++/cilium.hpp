#ifndef CILIUM_BINDINGS
#define CILIUM_BINDINGS

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

namespace cilium {

struct Context;

struct MetadataRoot;

struct DOSHeader {
    uint16_t magic;
    uint16_t last_page_bytes;
    uint16_t file_pages;
    uint16_t relocations;
    uint16_t header_size;
    uint16_t min_alloc;
    uint16_t max_alloc;
    uint16_t ss;
    uint16_t sp;
    uint16_t checksum;
    uint16_t ip;
    uint16_t cs;
    uint16_t relocation_table_address;
    uint16_t overlay_number;
    uint16_t reserved[4];
    uint16_t oem_id;
    uint16_t oem_info;
    uint16_t reserved_2[10];
    uint32_t new_header_start;
};

struct ImageFileHeader {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

struct DataDirectory {
    uint32_t virtual_address;
    uint32_t size;
};

struct ImageOptionalHeader32 {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    DataDirectory data_directories[16];
};

struct ImageOptionalHeader64 {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    DataDirectory data_directories[16];
};

struct ImageOptionalHeader {
    enum class Tag : uint16_t {
        None = 0,
        PE32 = 267,
        PE64 = 523,
    };

    struct PE32_Body {
        ImageOptionalHeader32 _0;
    };

    struct PE64_Body {
        ImageOptionalHeader64 _0;
    };

    Tag tag;
    union {
        PE32_Body pe32;
        PE64_Body pe64;
    };
};

struct PEHeader {
    uint32_t magic;
    ImageFileHeader image_file_header;
    ImageOptionalHeader image_optional_header;
};

using SectionName = uint8_t[8];

struct SectionHeader {
    SectionName name;
    uint32_t physical_address_or_virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_line_numbers;
    uint16_t number_of_relocations;
    uint16_t number_of_line_numbers;
    uint32_t characteristics;
};

template<typename T>
struct Slice {
    const T *data;
    size_t len;
};

struct Section {
    SectionHeader header;
    Slice<uint8_t> data;
};

template<typename T>
struct BoxSlice {
    T *data;
    size_t len;
};

struct PEFile {
    DOSHeader dos_header;
    PEHeader pe_header;
    BoxSlice<Section> sections;
};

struct RuntimeFlags {
    Internal _0;
};

using MetadataToken = uint32_t;

struct CLIHeader {
    uint32_t size_in_bytes;
    uint16_t major_runtime_version;
    uint16_t minot_runtime_version;
    DataDirectory metadata;
    RuntimeFlags flags;
    MetadataToken entry_point_token;
    DataDirectory resources;
    uint64_t strong_name_signature;
    uint64_t code_manager_table;
    uint64_t v_table_fixups;
    uint64_t export_address_table_jumps;
    uint64_t managed_native_header;
};

struct Assembly {
    PEFile pe_file;
    CLIHeader cli_header;
    MetadataRoot metadata_root;
};

struct BlobHeap {
    Slice<uint8_t> data;
};

struct GuidHeap {
    Slice<uint8_t> data;
};

struct StringHeap {
    Slice<uint8_t> data;
};

struct UserStringHeap {
    Slice<uint8_t> data;
};

struct IndexSizes {
    size_t guid;
    size_t blob;
    size_t string;
    size_t coded[14];
    size_t tables[55];
};

template<typename T>
using Box = T*;

struct ModuleTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct TypeRefTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct TypeDefTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct FieldTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct MethodDefTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct ParamTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct InterfaceImplTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct MemberRefTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct ConstantTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct CustomAttributeTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct FieldMarshalTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct DeclSecurityTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct ClassLayoutTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct FieldLayoutTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct StandAloneSigTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct EventMapTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct EventTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct PropertyMapTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct PropertyTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct MethodSemanticsTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct MethodImplTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct ModuleRefTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct TypeSpecTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct ImplMapTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct FieldRVATable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct AssemblyTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct AssemblyRefTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct FileTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct ExportedTypeTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct ManifestResourceTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct NestedClassTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct GenericParamTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct MethodSpecTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct GenericParamConstraintTable {
    size_t len;
    size_t row_size;
    Slice<uint8_t> data;
    const IndexSizes *idx_sizes;
};

struct Table {
    enum class Tag {
        Module,
        TypeRef,
        TypeDef,
        Field,
        MethodDef,
        Param,
        InterfaceImpl,
        MemberRef,
        Constant,
        CustomAttribute,
        FieldMarshal,
        DeclSecurity,
        ClassLayout,
        FieldLayout,
        StandAloneSig,
        EventMap,
        Event,
        PropertyMap,
        Property,
        MethodSemantics,
        MethodImpl,
        ModuleRef,
        TypeSpec,
        ImplMap,
        FieldRVA,
        Assembly,
        AssemblyRef,
        File,
        ExportedType,
        ManifestResource,
        NestedClass,
        GenericParam,
        MethodSpec,
        GenericParamConstraint,
    };

    struct Module_Body {
        ModuleTable _0;
    };

    struct TypeRef_Body {
        TypeRefTable _0;
    };

    struct TypeDef_Body {
        TypeDefTable _0;
    };

    struct Field_Body {
        FieldTable _0;
    };

    struct MethodDef_Body {
        MethodDefTable _0;
    };

    struct Param_Body {
        ParamTable _0;
    };

    struct InterfaceImpl_Body {
        InterfaceImplTable _0;
    };

    struct MemberRef_Body {
        MemberRefTable _0;
    };

    struct Constant_Body {
        ConstantTable _0;
    };

    struct CustomAttribute_Body {
        CustomAttributeTable _0;
    };

    struct FieldMarshal_Body {
        FieldMarshalTable _0;
    };

    struct DeclSecurity_Body {
        DeclSecurityTable _0;
    };

    struct ClassLayout_Body {
        ClassLayoutTable _0;
    };

    struct FieldLayout_Body {
        FieldLayoutTable _0;
    };

    struct StandAloneSig_Body {
        StandAloneSigTable _0;
    };

    struct EventMap_Body {
        EventMapTable _0;
    };

    struct Event_Body {
        EventTable _0;
    };

    struct PropertyMap_Body {
        PropertyMapTable _0;
    };

    struct Property_Body {
        PropertyTable _0;
    };

    struct MethodSemantics_Body {
        MethodSemanticsTable _0;
    };

    struct MethodImpl_Body {
        MethodImplTable _0;
    };

    struct ModuleRef_Body {
        ModuleRefTable _0;
    };

    struct TypeSpec_Body {
        TypeSpecTable _0;
    };

    struct ImplMap_Body {
        ImplMapTable _0;
    };

    struct FieldRVA_Body {
        FieldRVATable _0;
    };

    struct Assembly_Body {
        AssemblyTable _0;
    };

    struct AssemblyRef_Body {
        AssemblyRefTable _0;
    };

    struct File_Body {
        FileTable _0;
    };

    struct ExportedType_Body {
        ExportedTypeTable _0;
    };

    struct ManifestResource_Body {
        ManifestResourceTable _0;
    };

    struct NestedClass_Body {
        NestedClassTable _0;
    };

    struct GenericParam_Body {
        GenericParamTable _0;
    };

    struct MethodSpec_Body {
        MethodSpecTable _0;
    };

    struct GenericParamConstraint_Body {
        GenericParamConstraintTable _0;
    };

    Tag tag;
    union {
        Module_Body module;
        TypeRef_Body type_ref;
        TypeDef_Body type_def;
        Field_Body field;
        MethodDef_Body method_def;
        Param_Body param;
        InterfaceImpl_Body interface_impl;
        MemberRef_Body member_ref;
        Constant_Body constant;
        CustomAttribute_Body custom_attribute;
        FieldMarshal_Body field_marshal;
        DeclSecurity_Body decl_security;
        ClassLayout_Body class_layout;
        FieldLayout_Body field_layout;
        StandAloneSig_Body stand_alone_sig;
        EventMap_Body event_map;
        Event_Body event;
        PropertyMap_Body property_map;
        Property_Body property;
        MethodSemantics_Body method_semantics;
        MethodImpl_Body method_impl;
        ModuleRef_Body module_ref;
        TypeSpec_Body type_spec;
        ImplMap_Body impl_map;
        FieldRVA_Body field_rva;
        Assembly_Body assembly;
        AssemblyRef_Body assembly_ref;
        File_Body file;
        ExportedType_Body exported_type;
        ManifestResource_Body manifest_resource;
        NestedClass_Body nested_class;
        GenericParam_Body generic_param;
        MethodSpec_Body method_spec;
        GenericParamConstraint_Body generic_param_constraint;
    };
};

struct TableHeap {
    uint8_t major_version;
    uint8_t minor_version;
    Box<IndexSizes> index_sizes;
    BoxSlice<Table> tables;
};

using StringIndex = size_t;

using GuidIndex = size_t;

struct Module {
    uint16_t generation;
    StringIndex name;
    GuidIndex mv_id;
    GuidIndex enc_id;
    GuidIndex enc_base_id;
};

using ResolutionScope = uint32_t;

struct TypeRef {
    ResolutionScope resolution_scope;
    StringIndex name;
    StringIndex namespace_;
};

struct TypeAttributes {
    Internal _0;
};

using TypeDefOrRef = uint32_t;

using FieldIndex = size_t;

using MethodDefIndex = size_t;

struct TypeDef {
    TypeAttributes flags;
    StringIndex name;
    StringIndex namespace_;
    TypeDefOrRef extends;
    FieldIndex field_list;
    MethodDefIndex method_list;
};

struct FieldAttributes {
    Internal _0;
};

using BlobIndex = size_t;

struct Field {
    FieldAttributes flags;
    StringIndex name;
    BlobIndex signature;
};

struct MethodAttributes {
    Internal _0;
};

using ParamIndex = size_t;

struct MethodDef {
    uint32_t rva;
    MethodAttributes impl_flags;
    MethodAttributes flags;
    StringIndex name;
    BlobIndex signature;
    ParamIndex param_list;
};

struct ParamAttributes {
    Internal _0;
};

struct Param {
    ParamAttributes flags;
    uint16_t sequence;
    StringIndex name;
};

using TypeDefIndex = size_t;

struct InterfaceImpl {
    TypeDefIndex class_;
    TypeDefOrRef interface;
};

using MemberRefParent = uint32_t;

struct MemberRef {
    MemberRefParent class_;
    StringIndex name;
    BlobIndex signature;
};

using HasConstant = uint32_t;

struct Constant {
    uint8_t ty[2];
    HasConstant parent;
    BlobIndex value;
};

using HasCustomAttribute = uint32_t;

using CustomAttributeType = uint32_t;

struct CustomAttribute {
    HasCustomAttribute parent;
    CustomAttributeType ty;
    BlobIndex value;
};

using HasFieldMarshal = uint32_t;

struct FieldMarshal {
    HasFieldMarshal parent;
    BlobIndex native_type;
};

using HasDeclSecurity = uint32_t;

struct DeclSecurity {
    uint16_t action;
    HasDeclSecurity parent;
    BlobIndex permission_set;
};

struct ClassLayout {
    uint16_t packing_size;
    uint32_t class_size;
    TypeDefIndex parent;
};

struct FieldLayout {
    uint32_t offset;
    FieldIndex field;
};

struct StandAloneSig {
    BlobIndex signature;
};

using EventIndex = size_t;

struct EventMap {
    TypeDefIndex parent;
    EventIndex event_list;
};

struct EventAttributes {
    Internal _0;
};

struct Event {
    EventAttributes flags;
    StringIndex name;
    TypeDefOrRef ty;
};

using PropertyIndex = size_t;

struct PropertyMap {
    TypeDefIndex parent;
    PropertyIndex property_list;
};

struct PropertyAttributes {
    Internal _0;
};

struct Property {
    PropertyAttributes flags;
    StringIndex name;
    BlobIndex ty;
};

struct MethodSemanticsAttributes {
    Internal _0;
};

using HasSemantics = uint32_t;

struct MethodSemantics {
    MethodSemanticsAttributes flags;
    MethodDefIndex method;
    HasSemantics association;
};

using MethodDefOrRef = uint32_t;

struct MethodImpl {
    TypeDefIndex class_;
    MethodDefOrRef body;
    MethodDefOrRef declaration;
};

struct ModuleRef {
    StringIndex name;
};

struct TypeSpec {
    BlobIndex signature;
};

struct PInvokeAttributes {
    Internal _0;
};

using MemberForwarded = uint32_t;

using ModuleRefIndex = size_t;

struct ImplMap {
    PInvokeAttributes flags;
    MemberForwarded member_forwarded;
    StringIndex import_name;
    ModuleRefIndex import_scope;
};

struct FieldRVA {
    uint32_t rva;
    FieldIndex field;
};

struct AssemblyFlags {
    Internal _0;
};

struct AssemblyRef {
    uint16_t major_version;
    uint16_t minor_version;
    uint16_t build_number;
    uint16_t revision_number;
    AssemblyFlags flags;
    BlobIndex public_key;
    StringIndex name;
    StringIndex culture;
    BlobIndex hash_value;
};

struct FileAttributes {
    Internal _0;
};

struct File {
    FileAttributes flags;
    StringIndex name;
    BlobIndex hash_value;
};

using Implementation = uint32_t;

struct ExportedType {
    TypeAttributes flags;
    TypeDefIndex type_def;
    StringIndex name;
    StringIndex namespace_;
    Implementation implementation;
};

struct ManifestResourceAttributes {
    Internal _0;
};

struct ManifestResource {
    uint32_t offset;
    ManifestResourceAttributes flags;
    StringIndex name;
    Implementation implementation;
};

struct NestedClass {
    TypeDefIndex nested_class;
    TypeDefIndex enclosing_class;
};

struct GenericParamAttributes {
    Internal _0;
};

using TypeOrMethodDef = uint32_t;

struct GenericParam {
    uint16_t number;
    GenericParamAttributes flags;
    TypeOrMethodDef owner;
    StringIndex name;
};

struct MethodSpec {
    MethodDefOrRef method;
    BlobIndex instantiation;
};

using GenericParamIndex = size_t;

struct GenericParamConstraint {
    GenericParamIndex owner;
    TypeDefOrRef constraint;
};

extern "C" {

PEFile cilium_raw_PEFile_create(Slice<uint8_t> bytes);

void cilium_raw_PEFile_destroy(PEFile *pe);

Assembly *cilium_raw_Assembly_create(PEFile pe);

void cilium_raw_Assembly_destroy(Assembly *assembly);

const BlobHeap *cilium_raw_Assembly_get_heap_Blob(const Assembly *assembly);

const GuidHeap *cilium_raw_Assembly_get_heap_Guid(const Assembly *assembly);

const StringHeap *cilium_raw_Assembly_get_heap_String(const Assembly *assembly);

const UserStringHeap *cilium_raw_Assembly_get_heap_UserString(const Assembly *assembly);

const TableHeap *cilium_raw_Assembly_get_heap_Table(const Assembly *assembly);

const ModuleTable *cilium_raw_TableHeap_get_table_Module(const TableHeap *heap);

bool cilium_raw_ModuleTable_get_row(const ModuleTable *table, size_t idx, Module *out_row);

const TypeRefTable *cilium_raw_TableHeap_get_table_TypeRef(const TableHeap *heap);

bool cilium_raw_TypeRefTable_get_row(const TypeRefTable *table, size_t idx, TypeRef *out_row);

const TypeDefTable *cilium_raw_TableHeap_get_table_TypeDef(const TableHeap *heap);

bool cilium_raw_TypeDefTable_get_row(const TypeDefTable *table, size_t idx, TypeDef *out_row);

const FieldTable *cilium_raw_TableHeap_get_table_Field(const TableHeap *heap);

bool cilium_raw_FieldTable_get_row(const FieldTable *table, size_t idx, Field *out_row);

const MethodDefTable *cilium_raw_TableHeap_get_table_MethodDef(const TableHeap *heap);

bool cilium_raw_MethodDefTable_get_row(const MethodDefTable *table, size_t idx, MethodDef *out_row);

const ParamTable *cilium_raw_TableHeap_get_table_Param(const TableHeap *heap);

bool cilium_raw_ParamTable_get_row(const ParamTable *table, size_t idx, Param *out_row);

const InterfaceImplTable *cilium_raw_TableHeap_get_table_InterfaceImpl(const TableHeap *heap);

bool cilium_raw_InterfaceImplTable_get_row(const InterfaceImplTable *table,
                                           size_t idx,
                                           InterfaceImpl *out_row);

const MemberRefTable *cilium_raw_TableHeap_get_table_MemberRef(const TableHeap *heap);

bool cilium_raw_MemberRefTable_get_row(const MemberRefTable *table, size_t idx, MemberRef *out_row);

const ConstantTable *cilium_raw_TableHeap_get_table_Constant(const TableHeap *heap);

bool cilium_raw_ConstantTable_get_row(const ConstantTable *table, size_t idx, Constant *out_row);

const CustomAttributeTable *cilium_raw_TableHeap_get_table_CustomAttribute(const TableHeap *heap);

bool cilium_raw_CustomAttributeTable_get_row(const CustomAttributeTable *table,
                                             size_t idx,
                                             CustomAttribute *out_row);

const FieldMarshalTable *cilium_raw_TableHeap_get_table_FieldMarshal(const TableHeap *heap);

bool cilium_raw_FieldMarshalTable_get_row(const FieldMarshalTable *table,
                                          size_t idx,
                                          FieldMarshal *out_row);

const DeclSecurityTable *cilium_raw_TableHeap_get_table_DeclSecurity(const TableHeap *heap);

bool cilium_raw_DeclSecurityTable_get_row(const DeclSecurityTable *table,
                                          size_t idx,
                                          DeclSecurity *out_row);

const ClassLayoutTable *cilium_raw_TableHeap_get_table_ClassLayout(const TableHeap *heap);

bool cilium_raw_ClassLayoutTable_get_row(const ClassLayoutTable *table,
                                         size_t idx,
                                         ClassLayout *out_row);

const FieldLayoutTable *cilium_raw_TableHeap_get_table_FieldLayout(const TableHeap *heap);

bool cilium_raw_FieldLayoutTable_get_row(const FieldLayoutTable *table,
                                         size_t idx,
                                         FieldLayout *out_row);

const StandAloneSigTable *cilium_raw_TableHeap_get_table_StandAloneSig(const TableHeap *heap);

bool cilium_raw_StandAloneSigTable_get_row(const StandAloneSigTable *table,
                                           size_t idx,
                                           StandAloneSig *out_row);

const EventMapTable *cilium_raw_TableHeap_get_table_EventMap(const TableHeap *heap);

bool cilium_raw_EventMapTable_get_row(const EventMapTable *table, size_t idx, EventMap *out_row);

const EventTable *cilium_raw_TableHeap_get_table_Event(const TableHeap *heap);

bool cilium_raw_EventTable_get_row(const EventTable *table, size_t idx, Event *out_row);

const PropertyMapTable *cilium_raw_TableHeap_get_table_PropertyMap(const TableHeap *heap);

bool cilium_raw_PropertyMapTable_get_row(const PropertyMapTable *table,
                                         size_t idx,
                                         PropertyMap *out_row);

const PropertyTable *cilium_raw_TableHeap_get_table_Property(const TableHeap *heap);

bool cilium_raw_PropertyTable_get_row(const PropertyTable *table, size_t idx, Property *out_row);

const MethodSemanticsTable *cilium_raw_TableHeap_get_table_MethodSemantics(const TableHeap *heap);

bool cilium_raw_MethodSemanticsTable_get_row(const MethodSemanticsTable *table,
                                             size_t idx,
                                             MethodSemantics *out_row);

const MethodImplTable *cilium_raw_TableHeap_get_table_MethodImpl(const TableHeap *heap);

bool cilium_raw_MethodImplTable_get_row(const MethodImplTable *table,
                                        size_t idx,
                                        MethodImpl *out_row);

const ModuleRefTable *cilium_raw_TableHeap_get_table_ModuleRef(const TableHeap *heap);

bool cilium_raw_ModuleRefTable_get_row(const ModuleRefTable *table, size_t idx, ModuleRef *out_row);

const TypeSpecTable *cilium_raw_TableHeap_get_table_TypeSpec(const TableHeap *heap);

bool cilium_raw_TypeSpecTable_get_row(const TypeSpecTable *table, size_t idx, TypeSpec *out_row);

const ImplMapTable *cilium_raw_TableHeap_get_table_ImplMap(const TableHeap *heap);

bool cilium_raw_ImplMapTable_get_row(const ImplMapTable *table, size_t idx, ImplMap *out_row);

const FieldRVATable *cilium_raw_TableHeap_get_table_FieldRVA(const TableHeap *heap);

bool cilium_raw_FieldRVATable_get_row(const FieldRVATable *table, size_t idx, FieldRVA *out_row);

const AssemblyTable *cilium_raw_TableHeap_get_table_Assembly(const TableHeap *heap);

bool cilium_raw_AssemblyTable_get_row(const AssemblyTable *table, size_t idx, Assembly *out_row);

const AssemblyRefTable *cilium_raw_TableHeap_get_table_AssemblyRef(const TableHeap *heap);

bool cilium_raw_AssemblyRefTable_get_row(const AssemblyRefTable *table,
                                         size_t idx,
                                         AssemblyRef *out_row);

const FileTable *cilium_raw_TableHeap_get_table_File(const TableHeap *heap);

bool cilium_raw_FileTable_get_row(const FileTable *table, size_t idx, File *out_row);

const ExportedTypeTable *cilium_raw_TableHeap_get_table_ExportedType(const TableHeap *heap);

bool cilium_raw_ExportedTypeTable_get_row(const ExportedTypeTable *table,
                                          size_t idx,
                                          ExportedType *out_row);

const ManifestResourceTable *cilium_raw_TableHeap_get_table_ManifestResource(const TableHeap *heap);

bool cilium_raw_ManifestResourceTable_get_row(const ManifestResourceTable *table,
                                              size_t idx,
                                              ManifestResource *out_row);

const NestedClassTable *cilium_raw_TableHeap_get_table_NestedClass(const TableHeap *heap);

bool cilium_raw_NestedClassTable_get_row(const NestedClassTable *table,
                                         size_t idx,
                                         NestedClass *out_row);

const GenericParamTable *cilium_raw_TableHeap_get_table_GenericParam(const TableHeap *heap);

bool cilium_raw_GenericParamTable_get_row(const GenericParamTable *table,
                                          size_t idx,
                                          GenericParam *out_row);

const MethodSpecTable *cilium_raw_TableHeap_get_table_MethodSpec(const TableHeap *heap);

bool cilium_raw_MethodSpecTable_get_row(const MethodSpecTable *table,
                                        size_t idx,
                                        MethodSpec *out_row);

const GenericParamConstraintTable *cilium_raw_TableHeap_get_table_GenericParamConstraint(const TableHeap *heap);

bool cilium_raw_GenericParamConstraintTable_get_row(const GenericParamConstraintTable *table,
                                                    size_t idx,
                                                    GenericParamConstraint *out_row);

bool cilium_raw_GuidHeap_get(const GuidHeap *heap, GuidIndex idx, Uuid *out_guid);

bool cilium_raw_StringHeap_get(const StringHeap *heap,
                               StringIndex idx,
                               const uint8_t **out_str_ptr,
                               size_t *out_str_len);

bool cilium_raw_BlobHeap_get(const BlobHeap *heap,
                             BlobIndex idx,
                             const uint8_t **out_blob_ptr,
                             size_t *out_blob_len);

Context *cilium_Context_create(const char *const *paths, size_t path_count);

void cilium_Context_destroy(Context *ctx);

const Assembly *cilium_Context_load_assembly(Context *ctx, const char *path);

} // extern "C"

} // namespace cilium

#endif // CILIUM_BINDINGS
