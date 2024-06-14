// This file is generated by rust-protobuf 3.2.0. Do not edit
// .proto file is parsed by pure
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `confidential_data_hub.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_2_0;

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:api.GetResourceRequest)
pub struct GetResourceRequest {
    // message fields
    // @@protoc_insertion_point(field:api.GetResourceRequest.ResourcePath)
    pub ResourcePath: ::std::string::String,
    // @@protoc_insertion_point(field:api.GetResourceRequest.ExtraCredential)
    pub ExtraCredential: ::protobuf::MessageField<super::attestation_agent::ExtraCredential>,
    // special fields
    // @@protoc_insertion_point(special_field:api.GetResourceRequest.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a GetResourceRequest {
    fn default() -> &'a GetResourceRequest {
        <GetResourceRequest as ::protobuf::Message>::default_instance()
    }
}

impl GetResourceRequest {
    pub fn new() -> GetResourceRequest {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "ResourcePath",
            |m: &GetResourceRequest| { &m.ResourcePath },
            |m: &mut GetResourceRequest| { &mut m.ResourcePath },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::attestation_agent::ExtraCredential>(
            "ExtraCredential",
            |m: &GetResourceRequest| { &m.ExtraCredential },
            |m: &mut GetResourceRequest| { &mut m.ExtraCredential },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<GetResourceRequest>(
            "GetResourceRequest",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for GetResourceRequest {
    const NAME: &'static str = "GetResourceRequest";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.ResourcePath = is.read_string()?;
                },
                18 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.ExtraCredential)?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.ResourcePath.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.ResourcePath);
        }
        if let Some(v) = self.ExtraCredential.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.ResourcePath.is_empty() {
            os.write_string(1, &self.ResourcePath)?;
        }
        if let Some(v) = self.ExtraCredential.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(2, v, os)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> GetResourceRequest {
        GetResourceRequest::new()
    }

    fn clear(&mut self) {
        self.ResourcePath.clear();
        self.ExtraCredential.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static GetResourceRequest {
        static instance: GetResourceRequest = GetResourceRequest {
            ResourcePath: ::std::string::String::new(),
            ExtraCredential: ::protobuf::MessageField::none(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for GetResourceRequest {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("GetResourceRequest").unwrap()).clone()
    }
}

impl ::std::fmt::Display for GetResourceRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for GetResourceRequest {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:api.GetResourceResponse)
pub struct GetResourceResponse {
    // message fields
    // @@protoc_insertion_point(field:api.GetResourceResponse.Resource)
    pub Resource: ::std::vec::Vec<u8>,
    // special fields
    // @@protoc_insertion_point(special_field:api.GetResourceResponse.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a GetResourceResponse {
    fn default() -> &'a GetResourceResponse {
        <GetResourceResponse as ::protobuf::Message>::default_instance()
    }
}

impl GetResourceResponse {
    pub fn new() -> GetResourceResponse {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(1);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "Resource",
            |m: &GetResourceResponse| { &m.Resource },
            |m: &mut GetResourceResponse| { &mut m.Resource },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<GetResourceResponse>(
            "GetResourceResponse",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for GetResourceResponse {
    const NAME: &'static str = "GetResourceResponse";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.Resource = is.read_bytes()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.Resource.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.Resource);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.Resource.is_empty() {
            os.write_bytes(1, &self.Resource)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> GetResourceResponse {
        GetResourceResponse::new()
    }

    fn clear(&mut self) {
        self.Resource.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static GetResourceResponse {
        static instance: GetResourceResponse = GetResourceResponse {
            Resource: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for GetResourceResponse {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("GetResourceResponse").unwrap()).clone()
    }
}

impl ::std::fmt::Display for GetResourceResponse {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for GetResourceResponse {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:api.SetResourceRequest)
pub struct SetResourceRequest {
    // message fields
    // @@protoc_insertion_point(field:api.SetResourceRequest.ResourcePath)
    pub ResourcePath: ::std::string::String,
    // @@protoc_insertion_point(field:api.SetResourceRequest.Resource)
    pub Resource: ::std::vec::Vec<u8>,
    // special fields
    // @@protoc_insertion_point(special_field:api.SetResourceRequest.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a SetResourceRequest {
    fn default() -> &'a SetResourceRequest {
        <SetResourceRequest as ::protobuf::Message>::default_instance()
    }
}

impl SetResourceRequest {
    pub fn new() -> SetResourceRequest {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "ResourcePath",
            |m: &SetResourceRequest| { &m.ResourcePath },
            |m: &mut SetResourceRequest| { &mut m.ResourcePath },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "Resource",
            |m: &SetResourceRequest| { &m.Resource },
            |m: &mut SetResourceRequest| { &mut m.Resource },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<SetResourceRequest>(
            "SetResourceRequest",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for SetResourceRequest {
    const NAME: &'static str = "SetResourceRequest";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.ResourcePath = is.read_string()?;
                },
                18 => {
                    self.Resource = is.read_bytes()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.ResourcePath.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.ResourcePath);
        }
        if !self.Resource.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.Resource);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.ResourcePath.is_empty() {
            os.write_string(1, &self.ResourcePath)?;
        }
        if !self.Resource.is_empty() {
            os.write_bytes(2, &self.Resource)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> SetResourceRequest {
        SetResourceRequest::new()
    }

    fn clear(&mut self) {
        self.ResourcePath.clear();
        self.Resource.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static SetResourceRequest {
        static instance: SetResourceRequest = SetResourceRequest {
            ResourcePath: ::std::string::String::new(),
            Resource: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for SetResourceRequest {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("SetResourceRequest").unwrap()).clone()
    }
}

impl ::std::fmt::Display for SetResourceRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for SetResourceRequest {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:api.SetResourceResponse)
pub struct SetResourceResponse {
    // message fields
    // @@protoc_insertion_point(field:api.SetResourceResponse.Response)
    pub Response: ::std::vec::Vec<u8>,
    // special fields
    // @@protoc_insertion_point(special_field:api.SetResourceResponse.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a SetResourceResponse {
    fn default() -> &'a SetResourceResponse {
        <SetResourceResponse as ::protobuf::Message>::default_instance()
    }
}

impl SetResourceResponse {
    pub fn new() -> SetResourceResponse {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(1);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "Response",
            |m: &SetResourceResponse| { &m.Response },
            |m: &mut SetResourceResponse| { &mut m.Response },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<SetResourceResponse>(
            "SetResourceResponse",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for SetResourceResponse {
    const NAME: &'static str = "SetResourceResponse";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.Response = is.read_bytes()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.Response.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.Response);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.Response.is_empty() {
            os.write_bytes(1, &self.Response)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> SetResourceResponse {
        SetResourceResponse::new()
    }

    fn clear(&mut self) {
        self.Response.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static SetResourceResponse {
        static instance: SetResourceResponse = SetResourceResponse {
            Response: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for SetResourceResponse {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("SetResourceResponse").unwrap()).clone()
    }
}

impl ::std::fmt::Display for SetResourceResponse {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for SetResourceResponse {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x1bconfidential_data_hub.proto\x12\x03api\x1a\x17attestation_agent.pr\
    oto\"\x86\x01\n\x12GetResourceRequest\x12\"\n\x0cResourcePath\x18\x01\
    \x20\x01(\tR\x0cResourcePath\x12L\n\x0fExtraCredential\x18\x02\x20\x01(\
    \x0b2\".attestation_agent.ExtraCredentialR\x0fExtraCredential\"1\n\x13Ge\
    tResourceResponse\x12\x1a\n\x08Resource\x18\x01\x20\x01(\x0cR\x08Resourc\
    e\"T\n\x12SetResourceRequest\x12\"\n\x0cResourcePath\x18\x01\x20\x01(\tR\
    \x0cResourcePath\x12\x1a\n\x08Resource\x18\x02\x20\x01(\x0cR\x08Resource\
    \"1\n\x13SetResourceResponse\x12\x1a\n\x08Response\x18\x01\x20\x01(\x0cR\
    \x08Response2\x95\x01\n\x0fResourceService\x12@\n\x0bGetResource\x12\x17\
    .api.GetResourceRequest\x1a\x18.api.GetResourceResponse\x12@\n\x0bSetRes\
    ource\x12\x17.api.SetResourceRequest\x1a\x18.api.SetResourceResponseb\
    \x06proto3\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(1);
            deps.push(super::attestation_agent::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(4);
            messages.push(GetResourceRequest::generated_message_descriptor_data());
            messages.push(GetResourceResponse::generated_message_descriptor_data());
            messages.push(SetResourceRequest::generated_message_descriptor_data());
            messages.push(SetResourceResponse::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(0);
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}
