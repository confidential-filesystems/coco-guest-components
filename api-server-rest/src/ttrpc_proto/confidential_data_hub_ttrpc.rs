// This file is generated by ttrpc-compiler 0.6.1. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clipto_camel_casepy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]
use protobuf::{CodedInputStream, CodedOutputStream, Message};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;

#[derive(Clone)]
pub struct ResourceServiceClient {
    client: ::ttrpc::r#async::Client,
}

impl ResourceServiceClient {
    pub fn new(client: ::ttrpc::r#async::Client) -> Self {
        ResourceServiceClient {
            client: client,
        }
    }

    pub async fn get_resource(&self, ctx: ttrpc::context::Context, req: &super::confidential_data_hub::GetResourceRequest) -> ::ttrpc::Result<super::confidential_data_hub::GetResourceResponse> {
        let mut cres = super::confidential_data_hub::GetResourceResponse::new();
        ::ttrpc::async_client_request!(self, ctx, req, "api.ResourceService", "GetResource", cres);
    }

    pub async fn set_resource(&self, ctx: ttrpc::context::Context, req: &super::confidential_data_hub::SetResourceRequest) -> ::ttrpc::Result<super::confidential_data_hub::SetResourceResponse> {
        let mut cres = super::confidential_data_hub::SetResourceResponse::new();
        ::ttrpc::async_client_request!(self, ctx, req, "api.ResourceService", "SetResource", cres);
    }

    pub async fn delete_resource(&self, ctx: ttrpc::context::Context, req: &super::confidential_data_hub::DeleteResourceRequest) -> ::ttrpc::Result<super::confidential_data_hub::DeleteResourceResponse> {
        let mut cres = super::confidential_data_hub::DeleteResourceResponse::new();
        ::ttrpc::async_client_request!(self, ctx, req, "api.ResourceService", "DeleteResource", cres);
    }
}

struct GetResourceMethod {
    service: Arc<Box<dyn ResourceService + Send + Sync>>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for GetResourceMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, confidential_data_hub, GetResourceRequest, get_resource);
    }
}

struct SetResourceMethod {
    service: Arc<Box<dyn ResourceService + Send + Sync>>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for SetResourceMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, confidential_data_hub, SetResourceRequest, set_resource);
    }
}

struct DeleteResourceMethod {
    service: Arc<Box<dyn ResourceService + Send + Sync>>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for DeleteResourceMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, confidential_data_hub, DeleteResourceRequest, delete_resource);
    }
}

#[async_trait]
pub trait ResourceService: Sync {
    async fn get_resource(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::confidential_data_hub::GetResourceRequest) -> ::ttrpc::Result<super::confidential_data_hub::GetResourceResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/api.ResourceService/GetResource is not supported".to_string())))
    }
    async fn set_resource(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::confidential_data_hub::SetResourceRequest) -> ::ttrpc::Result<super::confidential_data_hub::SetResourceResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/api.ResourceService/SetResource is not supported".to_string())))
    }
    async fn delete_resource(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::confidential_data_hub::DeleteResourceRequest) -> ::ttrpc::Result<super::confidential_data_hub::DeleteResourceResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/api.ResourceService/DeleteResource is not supported".to_string())))
    }
}

pub fn create_resource_service(service: Arc<Box<dyn ResourceService + Send + Sync>>) -> HashMap<String, ::ttrpc::r#async::Service> {
    let mut ret = HashMap::new();
    let mut methods = HashMap::new();
    let streams = HashMap::new();

    methods.insert("GetResource".to_string(),
                    Box::new(GetResourceMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    methods.insert("SetResource".to_string(),
                    Box::new(SetResourceMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    methods.insert("DeleteResource".to_string(),
                    Box::new(DeleteResourceMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    ret.insert("api.ResourceService".to_string(), ::ttrpc::r#async::Service{ methods, streams });
    ret
}
