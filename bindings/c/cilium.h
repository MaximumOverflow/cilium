#ifndef CILIUM_BINDINGS
#define CILIUM_BINDINGS

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Context Context;

typedef struct MetadataRoot MetadataRoot;

typedef struct DOSHeader {
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
} DOSHeader;

typedef struct ImageFileHeader {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} ImageFileHeader;

typedef struct DataDirectory {
    uint32_t virtual_address;
    uint32_t size;
} DataDirectory;

typedef struct ImageOptionalHeader32 {
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
    struct DataDirectory data_directories[16];
} ImageOptionalHeader32;

typedef struct ImageOptionalHeader64 {
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
    struct DataDirectory data_directories[16];
} ImageOptionalHeader64;

enum ImageOptionalHeader_Tag {
    None = 0,
    PE32 = 267,
    PE64 = 523,
};
typedef uint16_t ImageOptionalHeader_Tag;

typedef struct ImageOptionalHeader {
    ImageOptionalHeader_Tag tag;
    union {
        struct {
            struct ImageOptionalHeader32 pe32;
        };
        struct {
            struct ImageOptionalHeader64 pe64;
        };
    };
} ImageOptionalHeader;

typedef struct PEHeader {
    uint32_t magic;
    struct ImageFileHeader image_file_header;
    struct ImageOptionalHeader image_optional_header;
} PEHeader;

typedef uint8_t SectionName[8];

typedef struct SectionHeader {
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
} SectionHeader;

typedef struct Slice_u8 {
    const uint8_t *data;
    size_t len;
} Slice_u8;

typedef struct Section {
    struct SectionHeader header;
    struct Slice_u8 data;
} Section;

typedef struct BoxSlice_Section {
    struct Section *data;
    size_t len;
} BoxSlice_Section;

typedef struct PEFile {
    struct DOSHeader dos_header;
    struct PEHeader pe_header;
    struct BoxSlice_Section sections;
} PEFile;

typedef struct RuntimeFlags {
    Internal _0;
} RuntimeFlags;

typedef uint32_t MetadataToken;

typedef struct CLIHeader {
    uint32_t size_in_bytes;
    uint16_t major_runtime_version;
    uint16_t minot_runtime_version;
    struct DataDirectory metadata;
    struct RuntimeFlags flags;
    MetadataToken entry_point_token;
    struct DataDirectory resources;
    uint64_t strong_name_signature;
    uint64_t code_manager_table;
    uint64_t v_table_fixups;
    uint64_t export_address_table_jumps;
    uint64_t managed_native_header;
} CLIHeader;

typedef struct Assembly {
    struct PEFile pe_file;
    struct CLIHeader cli_header;
    struct MetadataRoot metadata_root;
} Assembly;

typedef struct BlobHeap {
    struct Slice_u8 data;
} BlobHeap;

typedef struct GuidHeap {
    struct Slice_u8 data;
} GuidHeap;

typedef struct StringHeap {
    struct Slice_u8 data;
} StringHeap;

typedef struct UserStringHeap {
    struct Slice_u8 data;
} UserStringHeap;

typedef struct IndexSizes {
    size_t guid;
    size_t blob;
    size_t string;
    size_t coded[14];
    size_t tables[55];
} IndexSizes;

typedef struct ModuleTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} ModuleTable;

typedef struct TypeRefTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} TypeRefTable;

typedef struct TypeDefTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} TypeDefTable;

typedef struct FieldTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} FieldTable;

typedef struct MethodDefTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} MethodDefTable;

typedef struct ParamTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} ParamTable;

typedef struct InterfaceImplTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} InterfaceImplTable;

typedef struct MemberRefTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} MemberRefTable;

typedef struct ConstantTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} ConstantTable;

typedef struct CustomAttributeTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} CustomAttributeTable;

typedef struct FieldMarshalTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} FieldMarshalTable;

typedef struct DeclSecurityTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} DeclSecurityTable;

typedef struct ClassLayoutTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} ClassLayoutTable;

typedef struct FieldLayoutTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} FieldLayoutTable;

typedef struct StandAloneSigTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} StandAloneSigTable;

typedef struct EventMapTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} EventMapTable;

typedef struct EventTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} EventTable;

typedef struct PropertyMapTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} PropertyMapTable;

typedef struct PropertyTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} PropertyTable;

typedef struct MethodSemanticsTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} MethodSemanticsTable;

typedef struct MethodImplTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} MethodImplTable;

typedef struct ModuleRefTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} ModuleRefTable;

typedef struct TypeSpecTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} TypeSpecTable;

typedef struct ImplMapTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} ImplMapTable;

typedef struct FieldRVATable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} FieldRVATable;

typedef struct AssemblyTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} AssemblyTable;

typedef struct AssemblyRefTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} AssemblyRefTable;

typedef struct FileTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} FileTable;

typedef struct ExportedTypeTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} ExportedTypeTable;

typedef struct ManifestResourceTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} ManifestResourceTable;

typedef struct NestedClassTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} NestedClassTable;

typedef struct GenericParamTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} GenericParamTable;

typedef struct MethodSpecTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} MethodSpecTable;

typedef struct GenericParamConstraintTable {
    size_t len;
    size_t row_size;
    struct Slice_u8 data;
    const struct IndexSizes *idx_sizes;
} GenericParamConstraintTable;

typedef enum Table_Tag {
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
} Table_Tag;

typedef struct Table {
    Table_Tag tag;
    union {
        struct {
            struct ModuleTable module;
        };
        struct {
            struct TypeRefTable type_ref;
        };
        struct {
            struct TypeDefTable type_def;
        };
        struct {
            struct FieldTable field;
        };
        struct {
            struct MethodDefTable method_def;
        };
        struct {
            struct ParamTable param;
        };
        struct {
            struct InterfaceImplTable interface_impl;
        };
        struct {
            struct MemberRefTable member_ref;
        };
        struct {
            struct ConstantTable constant;
        };
        struct {
            struct CustomAttributeTable custom_attribute;
        };
        struct {
            struct FieldMarshalTable field_marshal;
        };
        struct {
            struct DeclSecurityTable decl_security;
        };
        struct {
            struct ClassLayoutTable class_layout;
        };
        struct {
            struct FieldLayoutTable field_layout;
        };
        struct {
            struct StandAloneSigTable stand_alone_sig;
        };
        struct {
            struct EventMapTable event_map;
        };
        struct {
            struct EventTable event;
        };
        struct {
            struct PropertyMapTable property_map;
        };
        struct {
            struct PropertyTable property;
        };
        struct {
            struct MethodSemanticsTable method_semantics;
        };
        struct {
            struct MethodImplTable method_impl;
        };
        struct {
            struct ModuleRefTable module_ref;
        };
        struct {
            struct TypeSpecTable type_spec;
        };
        struct {
            struct ImplMapTable impl_map;
        };
        struct {
            struct FieldRVATable field_rva;
        };
        struct {
            struct AssemblyTable assembly;
        };
        struct {
            struct AssemblyRefTable assembly_ref;
        };
        struct {
            struct FileTable file;
        };
        struct {
            struct ExportedTypeTable exported_type;
        };
        struct {
            struct ManifestResourceTable manifest_resource;
        };
        struct {
            struct NestedClassTable nested_class;
        };
        struct {
            struct GenericParamTable generic_param;
        };
        struct {
            struct MethodSpecTable method_spec;
        };
        struct {
            struct GenericParamConstraintTable generic_param_constraint;
        };
    };
} Table;

typedef struct BoxSlice_Table {
    struct Table *data;
    size_t len;
} BoxSlice_Table;

typedef struct TableHeap {
    uint8_t major_version;
    uint8_t minor_version;
    struct IndexSizes *index_sizes;
    struct BoxSlice_Table tables;
} TableHeap;

typedef size_t StringIndex;

typedef size_t GuidIndex;

typedef struct Module {
    uint16_t generation;
    StringIndex name;
    GuidIndex mv_id;
    GuidIndex enc_id;
    GuidIndex enc_base_id;
} Module;

typedef uint32_t ResolutionScope;

typedef struct TypeRef {
    ResolutionScope resolution_scope;
    StringIndex name;
    StringIndex namespace_;
} TypeRef;

typedef struct TypeAttributes {
    Internal _0;
} TypeAttributes;

typedef uint32_t TypeDefOrRef;

typedef size_t FieldIndex;

typedef size_t MethodDefIndex;

typedef struct TypeDef {
    struct TypeAttributes flags;
    StringIndex name;
    StringIndex namespace_;
    TypeDefOrRef extends;
    FieldIndex field_list;
    MethodDefIndex method_list;
} TypeDef;

typedef struct FieldAttributes {
    Internal _0;
} FieldAttributes;

typedef size_t BlobIndex;

typedef struct Field {
    struct FieldAttributes flags;
    StringIndex name;
    BlobIndex signature;
} Field;

typedef struct MethodAttributes {
    Internal _0;
} MethodAttributes;

typedef size_t ParamIndex;

typedef struct MethodDef {
    uint32_t rva;
    struct MethodAttributes impl_flags;
    struct MethodAttributes flags;
    StringIndex name;
    BlobIndex signature;
    ParamIndex param_list;
} MethodDef;

typedef struct ParamAttributes {
    Internal _0;
} ParamAttributes;

typedef struct Param {
    struct ParamAttributes flags;
    uint16_t sequence;
    StringIndex name;
} Param;

typedef size_t TypeDefIndex;

typedef struct InterfaceImpl {
    TypeDefIndex class_;
    TypeDefOrRef interface;
} InterfaceImpl;

typedef uint32_t MemberRefParent;

typedef struct MemberRef {
    MemberRefParent class_;
    StringIndex name;
    BlobIndex signature;
} MemberRef;

typedef uint32_t HasConstant;

typedef struct Constant {
    uint8_t ty[2];
    HasConstant parent;
    BlobIndex value;
} Constant;

typedef uint32_t HasCustomAttribute;

typedef uint32_t CustomAttributeType;

typedef struct CustomAttribute {
    HasCustomAttribute parent;
    CustomAttributeType ty;
    BlobIndex value;
} CustomAttribute;

typedef uint32_t HasFieldMarshal;

typedef struct FieldMarshal {
    HasFieldMarshal parent;
    BlobIndex native_type;
} FieldMarshal;

typedef uint32_t HasDeclSecurity;

typedef struct DeclSecurity {
    uint16_t action;
    HasDeclSecurity parent;
    BlobIndex permission_set;
} DeclSecurity;

typedef struct ClassLayout {
    uint16_t packing_size;
    uint32_t class_size;
    TypeDefIndex parent;
} ClassLayout;

typedef struct FieldLayout {
    uint32_t offset;
    FieldIndex field;
} FieldLayout;

typedef struct StandAloneSig {
    BlobIndex signature;
} StandAloneSig;

typedef size_t EventIndex;

typedef struct EventMap {
    TypeDefIndex parent;
    EventIndex event_list;
} EventMap;

typedef struct EventAttributes {
    Internal _0;
} EventAttributes;

typedef struct Event {
    struct EventAttributes flags;
    StringIndex name;
    TypeDefOrRef ty;
} Event;

typedef size_t PropertyIndex;

typedef struct PropertyMap {
    TypeDefIndex parent;
    PropertyIndex property_list;
} PropertyMap;

typedef struct PropertyAttributes {
    Internal _0;
} PropertyAttributes;

typedef struct Property {
    struct PropertyAttributes flags;
    StringIndex name;
    BlobIndex ty;
} Property;

typedef struct MethodSemanticsAttributes {
    Internal _0;
} MethodSemanticsAttributes;

typedef uint32_t HasSemantics;

typedef struct MethodSemantics {
    struct MethodSemanticsAttributes flags;
    MethodDefIndex method;
    HasSemantics association;
} MethodSemantics;

typedef uint32_t MethodDefOrRef;

typedef struct MethodImpl {
    TypeDefIndex class_;
    MethodDefOrRef body;
    MethodDefOrRef declaration;
} MethodImpl;

typedef struct ModuleRef {
    StringIndex name;
} ModuleRef;

typedef struct TypeSpec {
    BlobIndex signature;
} TypeSpec;

typedef struct PInvokeAttributes {
    Internal _0;
} PInvokeAttributes;

typedef uint32_t MemberForwarded;

typedef size_t ModuleRefIndex;

typedef struct ImplMap {
    struct PInvokeAttributes flags;
    MemberForwarded member_forwarded;
    StringIndex import_name;
    ModuleRefIndex import_scope;
} ImplMap;

typedef struct FieldRVA {
    uint32_t rva;
    FieldIndex field;
} FieldRVA;

typedef struct AssemblyFlags {
    Internal _0;
} AssemblyFlags;

typedef struct AssemblyRef {
    uint16_t major_version;
    uint16_t minor_version;
    uint16_t build_number;
    uint16_t revision_number;
    struct AssemblyFlags flags;
    BlobIndex public_key;
    StringIndex name;
    StringIndex culture;
    BlobIndex hash_value;
} AssemblyRef;

typedef struct FileAttributes {
    Internal _0;
} FileAttributes;

typedef struct File {
    struct FileAttributes flags;
    StringIndex name;
    BlobIndex hash_value;
} File;

typedef uint32_t Implementation;

typedef struct ExportedType {
    struct TypeAttributes flags;
    TypeDefIndex type_def;
    StringIndex name;
    StringIndex namespace_;
    Implementation implementation;
} ExportedType;

typedef struct ManifestResourceAttributes {
    Internal _0;
} ManifestResourceAttributes;

typedef struct ManifestResource {
    uint32_t offset;
    struct ManifestResourceAttributes flags;
    StringIndex name;
    Implementation implementation;
} ManifestResource;

typedef struct NestedClass {
    TypeDefIndex nested_class;
    TypeDefIndex enclosing_class;
} NestedClass;

typedef struct GenericParamAttributes {
    Internal _0;
} GenericParamAttributes;

typedef uint32_t TypeOrMethodDef;

typedef struct GenericParam {
    uint16_t number;
    struct GenericParamAttributes flags;
    TypeOrMethodDef owner;
    StringIndex name;
} GenericParam;

typedef struct MethodSpec {
    MethodDefOrRef method;
    BlobIndex instantiation;
} MethodSpec;

typedef size_t GenericParamIndex;

typedef struct GenericParamConstraint {
    GenericParamIndex owner;
    TypeDefOrRef constraint;
} GenericParamConstraint;

struct PEFile cilium_raw_PEFile_create(struct Slice_u8 bytes);

void cilium_raw_PEFile_destroy(struct PEFile *pe);

struct Assembly *cilium_raw_Assembly_create(struct PEFile pe);

void cilium_raw_Assembly_destroy(struct Assembly *assembly);

const struct BlobHeap *cilium_raw_Assembly_get_heap_Blob(const struct Assembly *assembly);

const struct GuidHeap *cilium_raw_Assembly_get_heap_Guid(const struct Assembly *assembly);

const struct StringHeap *cilium_raw_Assembly_get_heap_String(const struct Assembly *assembly);

const struct UserStringHeap *cilium_raw_Assembly_get_heap_UserString(const struct Assembly *assembly);

const struct TableHeap *cilium_raw_Assembly_get_heap_Table(const struct Assembly *assembly);

const struct ModuleTable *cilium_raw_TableHeap_get_table_Module(const struct TableHeap *heap);

bool cilium_raw_ModuleTable_get_row(const struct ModuleTable *table,
                                    size_t idx,
                                    struct Module *out_row);

const struct TypeRefTable *cilium_raw_TableHeap_get_table_TypeRef(const struct TableHeap *heap);

bool cilium_raw_TypeRefTable_get_row(const struct TypeRefTable *table,
                                     size_t idx,
                                     struct TypeRef *out_row);

const struct TypeDefTable *cilium_raw_TableHeap_get_table_TypeDef(const struct TableHeap *heap);

bool cilium_raw_TypeDefTable_get_row(const struct TypeDefTable *table,
                                     size_t idx,
                                     struct TypeDef *out_row);

const struct FieldTable *cilium_raw_TableHeap_get_table_Field(const struct TableHeap *heap);

bool cilium_raw_FieldTable_get_row(const struct FieldTable *table,
                                   size_t idx,
                                   struct Field *out_row);

const struct MethodDefTable *cilium_raw_TableHeap_get_table_MethodDef(const struct TableHeap *heap);

bool cilium_raw_MethodDefTable_get_row(const struct MethodDefTable *table,
                                       size_t idx,
                                       struct MethodDef *out_row);

const struct ParamTable *cilium_raw_TableHeap_get_table_Param(const struct TableHeap *heap);

bool cilium_raw_ParamTable_get_row(const struct ParamTable *table,
                                   size_t idx,
                                   struct Param *out_row);

const struct InterfaceImplTable *cilium_raw_TableHeap_get_table_InterfaceImpl(const struct TableHeap *heap);

bool cilium_raw_InterfaceImplTable_get_row(const struct InterfaceImplTable *table,
                                           size_t idx,
                                           struct InterfaceImpl *out_row);

const struct MemberRefTable *cilium_raw_TableHeap_get_table_MemberRef(const struct TableHeap *heap);

bool cilium_raw_MemberRefTable_get_row(const struct MemberRefTable *table,
                                       size_t idx,
                                       struct MemberRef *out_row);

const struct ConstantTable *cilium_raw_TableHeap_get_table_Constant(const struct TableHeap *heap);

bool cilium_raw_ConstantTable_get_row(const struct ConstantTable *table,
                                      size_t idx,
                                      struct Constant *out_row);

const struct CustomAttributeTable *cilium_raw_TableHeap_get_table_CustomAttribute(const struct TableHeap *heap);

bool cilium_raw_CustomAttributeTable_get_row(const struct CustomAttributeTable *table,
                                             size_t idx,
                                             struct CustomAttribute *out_row);

const struct FieldMarshalTable *cilium_raw_TableHeap_get_table_FieldMarshal(const struct TableHeap *heap);

bool cilium_raw_FieldMarshalTable_get_row(const struct FieldMarshalTable *table,
                                          size_t idx,
                                          struct FieldMarshal *out_row);

const struct DeclSecurityTable *cilium_raw_TableHeap_get_table_DeclSecurity(const struct TableHeap *heap);

bool cilium_raw_DeclSecurityTable_get_row(const struct DeclSecurityTable *table,
                                          size_t idx,
                                          struct DeclSecurity *out_row);

const struct ClassLayoutTable *cilium_raw_TableHeap_get_table_ClassLayout(const struct TableHeap *heap);

bool cilium_raw_ClassLayoutTable_get_row(const struct ClassLayoutTable *table,
                                         size_t idx,
                                         struct ClassLayout *out_row);

const struct FieldLayoutTable *cilium_raw_TableHeap_get_table_FieldLayout(const struct TableHeap *heap);

bool cilium_raw_FieldLayoutTable_get_row(const struct FieldLayoutTable *table,
                                         size_t idx,
                                         struct FieldLayout *out_row);

const struct StandAloneSigTable *cilium_raw_TableHeap_get_table_StandAloneSig(const struct TableHeap *heap);

bool cilium_raw_StandAloneSigTable_get_row(const struct StandAloneSigTable *table,
                                           size_t idx,
                                           struct StandAloneSig *out_row);

const struct EventMapTable *cilium_raw_TableHeap_get_table_EventMap(const struct TableHeap *heap);

bool cilium_raw_EventMapTable_get_row(const struct EventMapTable *table,
                                      size_t idx,
                                      struct EventMap *out_row);

const struct EventTable *cilium_raw_TableHeap_get_table_Event(const struct TableHeap *heap);

bool cilium_raw_EventTable_get_row(const struct EventTable *table,
                                   size_t idx,
                                   struct Event *out_row);

const struct PropertyMapTable *cilium_raw_TableHeap_get_table_PropertyMap(const struct TableHeap *heap);

bool cilium_raw_PropertyMapTable_get_row(const struct PropertyMapTable *table,
                                         size_t idx,
                                         struct PropertyMap *out_row);

const struct PropertyTable *cilium_raw_TableHeap_get_table_Property(const struct TableHeap *heap);

bool cilium_raw_PropertyTable_get_row(const struct PropertyTable *table,
                                      size_t idx,
                                      struct Property *out_row);

const struct MethodSemanticsTable *cilium_raw_TableHeap_get_table_MethodSemantics(const struct TableHeap *heap);

bool cilium_raw_MethodSemanticsTable_get_row(const struct MethodSemanticsTable *table,
                                             size_t idx,
                                             struct MethodSemantics *out_row);

const struct MethodImplTable *cilium_raw_TableHeap_get_table_MethodImpl(const struct TableHeap *heap);

bool cilium_raw_MethodImplTable_get_row(const struct MethodImplTable *table,
                                        size_t idx,
                                        struct MethodImpl *out_row);

const struct ModuleRefTable *cilium_raw_TableHeap_get_table_ModuleRef(const struct TableHeap *heap);

bool cilium_raw_ModuleRefTable_get_row(const struct ModuleRefTable *table,
                                       size_t idx,
                                       struct ModuleRef *out_row);

const struct TypeSpecTable *cilium_raw_TableHeap_get_table_TypeSpec(const struct TableHeap *heap);

bool cilium_raw_TypeSpecTable_get_row(const struct TypeSpecTable *table,
                                      size_t idx,
                                      struct TypeSpec *out_row);

const struct ImplMapTable *cilium_raw_TableHeap_get_table_ImplMap(const struct TableHeap *heap);

bool cilium_raw_ImplMapTable_get_row(const struct ImplMapTable *table,
                                     size_t idx,
                                     struct ImplMap *out_row);

const struct FieldRVATable *cilium_raw_TableHeap_get_table_FieldRVA(const struct TableHeap *heap);

bool cilium_raw_FieldRVATable_get_row(const struct FieldRVATable *table,
                                      size_t idx,
                                      struct FieldRVA *out_row);

const struct AssemblyTable *cilium_raw_TableHeap_get_table_Assembly(const struct TableHeap *heap);

bool cilium_raw_AssemblyTable_get_row(const struct AssemblyTable *table,
                                      size_t idx,
                                      struct Assembly *out_row);

const struct AssemblyRefTable *cilium_raw_TableHeap_get_table_AssemblyRef(const struct TableHeap *heap);

bool cilium_raw_AssemblyRefTable_get_row(const struct AssemblyRefTable *table,
                                         size_t idx,
                                         struct AssemblyRef *out_row);

const struct FileTable *cilium_raw_TableHeap_get_table_File(const struct TableHeap *heap);

bool cilium_raw_FileTable_get_row(const struct FileTable *table, size_t idx, struct File *out_row);

const struct ExportedTypeTable *cilium_raw_TableHeap_get_table_ExportedType(const struct TableHeap *heap);

bool cilium_raw_ExportedTypeTable_get_row(const struct ExportedTypeTable *table,
                                          size_t idx,
                                          struct ExportedType *out_row);

const struct ManifestResourceTable *cilium_raw_TableHeap_get_table_ManifestResource(const struct TableHeap *heap);

bool cilium_raw_ManifestResourceTable_get_row(const struct ManifestResourceTable *table,
                                              size_t idx,
                                              struct ManifestResource *out_row);

const struct NestedClassTable *cilium_raw_TableHeap_get_table_NestedClass(const struct TableHeap *heap);

bool cilium_raw_NestedClassTable_get_row(const struct NestedClassTable *table,
                                         size_t idx,
                                         struct NestedClass *out_row);

const struct GenericParamTable *cilium_raw_TableHeap_get_table_GenericParam(const struct TableHeap *heap);

bool cilium_raw_GenericParamTable_get_row(const struct GenericParamTable *table,
                                          size_t idx,
                                          struct GenericParam *out_row);

const struct MethodSpecTable *cilium_raw_TableHeap_get_table_MethodSpec(const struct TableHeap *heap);

bool cilium_raw_MethodSpecTable_get_row(const struct MethodSpecTable *table,
                                        size_t idx,
                                        struct MethodSpec *out_row);

const struct GenericParamConstraintTable *cilium_raw_TableHeap_get_table_GenericParamConstraint(const struct TableHeap *heap);

bool cilium_raw_GenericParamConstraintTable_get_row(const struct GenericParamConstraintTable *table,
                                                    size_t idx,
                                                    struct GenericParamConstraint *out_row);

bool cilium_raw_GuidHeap_get(const struct GuidHeap *heap, GuidIndex idx, Uuid *out_guid);

bool cilium_raw_StringHeap_get(const struct StringHeap *heap,
                               StringIndex idx,
                               const uint8_t **out_str_ptr,
                               size_t *out_str_len);

bool cilium_raw_BlobHeap_get(const struct BlobHeap *heap,
                             BlobIndex idx,
                             const uint8_t **out_blob_ptr,
                             size_t *out_blob_len);

struct Context *cilium_Context_create(const char *const *paths, size_t path_count);

void cilium_Context_destroy(struct Context *ctx);

const struct Assembly *cilium_Context_load_assembly(struct Context *ctx, const char *path);

#endif /* CILIUM_BINDINGS */
