// Presentation only. Native commands recognize the URL, current request and
// account before protected custody operations or any signed response.
export function initArchiveRecovery({invoke,actions}){
  let active=null;
  actions['archive-access']=()=>{
    active?.remove();
    const dialog=document.createElement('dialog');active=dialog;dialog.className='archive-recovery-dialog';
    const title=document.createElement('h2');title.textContent='Archive access';
    const detail=document.createElement('p');detail.textContent='Paste the archive approval link from your chat app.';
    const url=document.createElement('input');url.type='url';url.autocomplete='off';url.placeholder='https://…/archive/identity/…';url.setAttribute('aria-label','Archive approval link');
    const status=document.createElement('p');status.setAttribute('role','status');
    const password=document.createElement('input');password.type='password';password.autocomplete='current-password';password.placeholder='Selfsame passcode';password.setAttribute('aria-label','Selfsame passcode');password.hidden=true;
    const review=document.createElement('button');review.textContent='Review request';review.className='btn btn--primary';
    const approve=document.createElement('button');approve.textContent='Approve archive access';approve.className='btn btn--primary';approve.hidden=true;
    const cancel=document.createElement('button');cancel.textContent='Cancel';cancel.className='btn btn--quiet';
    let snapshot=null,closed=false,approving=false;
    const close=()=>{if(approving)return;closed=true;password.value='';snapshot=null;dialog.close();dialog.remove();if(active===dialog)active=null;};
    cancel.onclick=close;dialog.addEventListener('cancel',event=>{event.preventDefault();close();});
    review.onclick=async()=>{
      review.disabled=true;status.textContent='Checking the application…';
      try{
        const value=await invoke('archive_recovery_review',{url:url.value});if(closed)return;
        snapshot={url:url.value,digest:value.requestDigest};url.readOnly=true;
        detail.textContent=value.action+' for '+value.application+'\nAccount: '+value.account+'\nDevice: '+value.device.map(b=>b.toString(16).padStart(2,'0')).join('');
        status.textContent='Approve only if you requested archive access on this device.';
        review.hidden=true;password.hidden=false;approve.hidden=false;password.focus();
      }catch{if(!closed)status.textContent='This request is unavailable or expired. Request a new link in chat.';}
      finally{review.disabled=false;}
    };
    approve.onclick=async()=>{
      if(!snapshot||closed)return;approving=true;approve.disabled=true;cancel.disabled=true;
      const passcode=password.value;password.value='';status.textContent='Approving archive access…';
      try{
        await invoke('archive_recovery_approve',{url:snapshot.url,requestDigest:snapshot.digest,passcode});
        if(closed)return;status.textContent='Approved. Return to your chat app.';approve.hidden=true;password.hidden=true;cancel.textContent='Done';
      }catch{if(!closed){status.textContent='Approval could not finish. Check your passcode or request a new link.';approve.disabled=false;}}
      finally{approving=false;cancel.disabled=false;}
    };
    dialog.append(title,detail,url,status,password,review,approve,cancel);document.body.append(dialog);dialog.showModal();url.focus();
  };
}
