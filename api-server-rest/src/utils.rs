// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use hyper::{Body, Request};

pub fn split_nth_slash(url: &str, n: usize) -> Option<(&str, &str)> {
    let mut split_pos = None;
    let mut splits = url.match_indices('/');

    for _ in 0..n {
        split_pos = splits.next();
    }

    split_pos.map(|(idx, pat)| url.split_at(idx + pat.len() - 1))
}

pub async fn get_extra_credential_from_req(req: Request<Body>) -> Result<attester::extra_credential::ExtraCredential> {
    let body = match hyper::body::to_bytes(req.into_body()).await {
        core::result::Result::Ok(content) => {
            println!("confilesystem10 - get_extra_credential_from_req(): req.into_body() -> content = {:?}", content);
            content
        },
        Err(e) => {
            println!("confilesystem10 - get_extra_credential_from_req(): req.into_body() -> e = {:?}", e);
            return Err(anyhow!("get_extra_credential_from_req(): get body: e = {:?}", e));
        }
    };
    if body.len() <= 0 {
        return Err(anyhow!("get_extra_credential_from_req(): body.len() = {:?}", body.len()));
    }
    let extra_credential: attester::extra_credential::ExtraCredential = match serde_json::from_slice(&body) {
        core::result::Result::Ok(content) => {
            println!("confilesystem10 - get_extra_credential_from_req(): serde_json::from_slice() -> content = {:?}", content);
            content
        },
        Err(e) => {
            println!("confilesystem10 - get_extra_credential_from_req(): serde_json::from_slice() -> e = {:?}", e);
            return Err(anyhow!("get_extra_credential_from_req(): parse body: e = {:?}", e));
        }
    };
    println!("confilesystem10 - get_extra_credential_from_req(): extra_credential = {:?}", extra_credential);
    Ok(extra_credential)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_nth_slash() {
        let url_path = "/cdh/resource/default/";
        assert_eq!(split_nth_slash(url_path, 0), None);
        assert_eq!(
            split_nth_slash(url_path, 1),
            Some(("", "/cdh/resource/default/"))
        );
        assert_eq!(
            split_nth_slash(url_path, 2),
            Some(("/cdh", "/resource/default/"))
        );
        assert_eq!(
            split_nth_slash(url_path, 3),
            Some(("/cdh/resource", "/default/"))
        );
        assert_eq!(
            split_nth_slash(url_path, 4),
            Some(("/cdh/resource/default", "/"))
        );
        assert_eq!(split_nth_slash(url_path, 5), None);
    }
}
