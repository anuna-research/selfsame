//! SPEC-082 account-linked archive access. Only public requests and signed encrypted
//! completions cross the native boundary; wallet recovery material stays here.
use cbcl_archive_core::{wallet_exchange::{Request,Action},key_pages::HpkePrivate};
use selfsame_app_identity::{profile::ApplicationId,scope::AccountScopeId,hierarchy};
use crate::{commands::UiError,custody::Custody};
use serde::Serialize;
use zeroize::Zeroizing;
use std::time::Duration;
type Result<T>=std::result::Result<T,UiError>;
fn refused()->UiError{UiError::from("ArchiveRecoveryRefused")}
fn mailbox(value:&str)->Result<reqwest::Url>{
    let url=reqwest::Url::parse(value).map_err(|_|refused())?;
    let token=url.path().strip_prefix("/archive/identity/").ok_or_else(refused)?;
    if url.scheme()!="https"||url.host_str().is_none()||!url.username().is_empty()||url.password().is_some()||
        url.query().is_some()||url.fragment().is_some()||token.len()!=64||!token.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))||url.as_str()!=value {
        return Err(refused());
    }Ok(url)
}
fn client()->Result<reqwest::Client>{
    #[cfg(test)]
    if let Some(client)=TEST_CLIENT.get(){return Ok(client.clone());}
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15)).build().map_err(|_|refused())
}
// Only the native test host supplies its already-recognised disposable CA and
// loopback proxy. Production has no alternate trust configuration.
#[cfg(test)]
static TEST_CLIENT:std::sync::OnceLock<reqwest::Client>=std::sync::OnceLock::new();
#[cfg(test)]
pub(crate) fn configure_test_client(root:&[u8],proxy:&str)->Result<()> {
    selfsame_app_identity_net::test_support::HostConfig::new(root,proxy).map_err(|_|refused())?;
    let client=reqwest::Client::builder().no_proxy()
        .proxy(reqwest::Proxy::https(proxy).map_err(|_|refused())?)
        .add_root_certificate(reqwest::Certificate::from_pem(root).map_err(|_|refused())?)
        .redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15))
        .build().map_err(|_|refused())?;
    TEST_CLIENT.set(client).map_err(|_|refused())
}
async fn fetch(value:&str)->Result<(reqwest::Client,reqwest::Url,Request)>{
    let url=mailbox(value)?;let client=client()?;
    let mut response=client.get(url.clone()).send().await.map_err(|_|refused())?;
    if response.status()!=reqwest::StatusCode::OK||response.headers().contains_key("content-encoding"){return Err(refused());}
    let mut bytes=Vec::new();while let Some(chunk)=response.chunk().await.map_err(|_|refused())?{
        if bytes.len()+chunk.len()>cbcl_archive_core::wallet_exchange::MAX_EXCHANGE{return Err(refused());}bytes.extend_from_slice(&chunk);
    }
    let request=Request::read(&bytes).map_err(|_|refused())?;
    request.current(crate::commands::now()).map_err(|_|refused())?;
    let application=ApplicationId::parse(&request.application).map_err(|_|refused())?;
    if application.origin()!=url.origin().ascii_serialization(){return Err(refused());}
    selfsame_app_identity_net::profile::fetch_or_cached(&application,None,crate::commands::now() as i64).await.map_err(|_|refused())?;
    Ok((client,url,request))
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub struct ArchiveReview {application:String,account:String,device:Vec<u8>,request_digest:Vec<u8>,expires:u64,action:&'static str}
#[tauri::command]
pub async fn archive_recovery_review(url:String)->Result<ArchiveReview>{
    let (_,_,request)=fetch(&url).await?;
    Ok(ArchiveReview{application:request.application.clone(),account:request.account.clone(),device:request.device.to_vec(),
        request_digest:request.digest().map_err(|_|refused())?.to_vec(),expires:request.expires,
        action:if request.action==Action::Configure{"Protect archive recovery"}else{"Recover archive access"}})
}
#[tauri::command]
pub async fn archive_recovery_approve(url:String,request_digest:Vec<u8>,passcode:String)->Result<()> {
    let passcode=Zeroizing::new(passcode);
    let (client,url,request)=fetch(&url).await?;
    if request.digest().map_err(|_|refused())?.as_slice()!=request_digest{return Err(refused());}
    let application=ApplicationId::parse(&request.application).map_err(|_|refused())?;
    let scope=AccountScopeId::from_octets(request.scope);
    let completion=Custody::use_hierarchy_root(&passcode,|root|{
        let account=hierarchy::account_node(&hierarchy::application_node(root,&application),&scope);
        let home=hierarchy::home_key(&account);
        if home.home_did().map_err(|_|refused())?!=request.account{return Err(refused());}
        let material=hierarchy::archive_recovery_seed(&account);
        let private=HpkePrivate::from_identity_material(material.for_wallet_hpke());
        cbcl_archive_core::wallet_exchange::complete(&request,&private,home.signing_key(),crate::commands::now()).map_err(|_|refused())
    })??;
    let response=client.post(url).header("content-type","application/json").body(completion.bytes().map_err(|_|refused())?)
        .send().await.map_err(|_|refused())?;
    if response.status()!=reqwest::StatusCode::OK{return Err(refused());}Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mailbox_origin_and_token_are_closed(){
        let good=format!("https://chat.anuna.io/archive/identity/{}","ab".repeat(32));assert!(mailbox(&good).is_ok());
        for value in [good.replace("https:","http:"),good.clone()+"?callback=https://evil.test",good.clone()+"#fragment",
            good.replace("chat.anuna.io","user@chat.anuna.io"),good.replace("abab","ABAB"),good.clone()+"/extra"] {
            assert!(mailbox(&value).is_err());
        }
    }
}

/// SPEC-082 CON-006. Runs only inside the just-approved link's live attempt.
/// It borrows custody at signing time; it never retains a root for background use.
pub(crate) async fn complete_linked(
    installed: &crate::cbcl_v2_completion::InstalledCredentialV2Link,
    complete: impl Fn(&cbcl_archive_core::wallet_exchange::LinkedDevice, &Request) -> Result<Vec<u8>>,
) -> Result<()> {
    let Some(link)=installed.archive_link()? else{return Ok(());};
    let application=ApplicationId::parse(&link.application).map_err(|_|refused())?;
    let token=link.nonce.iter().map(|b|format!("{b:02x}")).collect::<String>();
    let url=mailbox(&format!("{}/archive/identity/{token}",application.origin()))?;
    let client=client()?;
    tokio::time::timeout(Duration::from_secs(60),async {
        let mut answered=None;
        loop {
            let mut response=client.get(url.clone()).send().await.map_err(|_|refused())?;
            if response.status()==reqwest::StatusCode::NOT_FOUND{return Err(refused());}
            if response.status()==reqwest::StatusCode::NO_CONTENT{return Ok(());}
            if response.status()==reqwest::StatusCode::ACCEPTED {
                tokio::time::sleep(Duration::from_millis(250)).await;continue;
            }
            if response.status()!=reqwest::StatusCode::OK||response.headers().contains_key("content-encoding"){return Err(refused());}
            let mut bytes=Vec::new();
            while let Some(chunk)=response.chunk().await.map_err(|_|refused())? {
                if bytes.len()+chunk.len()>cbcl_archive_core::wallet_exchange::MAX_EXCHANGE{return Err(refused());}
                bytes.extend_from_slice(&chunk);
            }
            let request=Request::read(&bytes).map_err(|_|refused())?;
            link.verify(&request,crate::commands::now()).map_err(|_|refused())?;
            let digest=request.digest().map_err(|_|refused())?;
            if answered==Some(digest){tokio::time::sleep(Duration::from_millis(250)).await;continue;}
            let completion=complete(&link,&request)?;
            let posted=client.post(url.clone()).header("content-type","application/json")
                .body(completion).send().await.map_err(|_|refused())?;
            if posted.status()!=reqwest::StatusCode::OK{return Err(refused());}
            answered=Some(digest);
        }
    }).await.map_err(|_|refused())?
}

pub(crate) fn complete_for_link(
    root:&hierarchy::HierarchyRoot,link:&cbcl_archive_core::wallet_exchange::LinkedDevice,request:&Request,
)->Result<Vec<u8>> {
    link.verify(request,crate::commands::now()).map_err(|_|refused())?;
    let application=ApplicationId::parse(&link.application).map_err(|_|refused())?;
    let scope=AccountScopeId::from_octets(link.scope);
    let account=hierarchy::account_node(&hierarchy::application_node(root,&application),&scope);
    let home=hierarchy::home_key(&account);
    if home.home_did().map_err(|_|refused())?!=link.account{return Err(refused());}
    let material=hierarchy::archive_recovery_seed(&account);
    let private=HpkePrivate::from_identity_material(material.for_wallet_hpke());
    cbcl_archive_core::wallet_exchange::complete_link(link,request,&private,home.signing_key(),crate::commands::now())
        .and_then(|c|c.bytes()).map_err(|_|refused())
}

#[cfg(test)]
mod linked_tests {
    use super::*;
    use cbcl_archive_core::wallet_exchange::{self as wallet, LinkedDevice};
    #[test]
    fn one_account_derives_the_same_recipient_for_two_linked_devices() {
        let root=hierarchy::HierarchyRoot::from_octets([42;64]);
        let application=ApplicationId::parse("https://chat.anuna.io/selfsame/application").unwrap();
        let scope=AccountScopeId::from_octets([21;32]);
        let account=hierarchy::account_node(&hierarchy::application_node(&root,&application),&scope);
        let home=hierarchy::home_key(&account);
        let did=home.home_did().unwrap();
        let mut recipient=None;
        for device in [31,32] {
            let link=LinkedDevice{application:application.as_str().to_owned(),account:did.clone(),scope:[21;32],
                device:[device;32],nonce:wallet::link_nonce(&[device;100]).unwrap()};
            let request=Request{version:1,action:Action::Configure,application:link.application.clone(),account:did.clone(),
                scope:link.scope,device:link.device,hpke:HpkePrivate::generate().unwrap().public().unwrap(),nonce:link.nonce,
                expires:crate::commands::now()+60,manifest:None};
            let result=wallet::Completion::read(&complete_for_link(&root,&link,&request).unwrap()).unwrap();
            result.verify(&request,&[home.signing_key().verifying_key().to_bytes()],crate::commands::now()).unwrap();
            if let Some(key)=recipient {assert_eq!(key,result.certificate.recipient);}
            recipient=Some(result.certificate.recipient);
            let other_root=hierarchy::HierarchyRoot::from_octets([43;64]);
            assert!(complete_for_link(&other_root,&link,&request).is_err());
            let mut substituted=request.clone();substituted.device[0]^=1;
            assert!(complete_for_link(&root,&link,&substituted).is_err());
        }
    }
}
