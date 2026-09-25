import {randomUUID} from 'node:crypto';
// Log only server-controlled response metadata. Never log URLs, IDs from the
// request, headers, tokens, proof bodies, parsed contacts, or exception messages.
export function callbackDiagnostics(record) {
  return (req,res,next)=>{
    const requestId=randomUUID(),started=performance.now();
    const length=String(req.headers['content-length']||'');
    const requestBytes=/^\d{1,12}$/.test(length)?Number(length):null;
    let errorCode=null,emitted=false;
    res.set('X-Request-ID',requestId);
    const json=res.json;
    res.json=function(body){
      if(typeof body?.error==='string' && /^[A-Z][A-Z0-9_]{0,59}$/.test(body.error)) errorCode=body.error;
      return json.call(this,body);
    };
    const emit=aborted=>{
      if(emitted)return;emitted=true;
      const event={event:'mygate_callback',requestId,status:aborted?499:res.statusCode,errorCode:aborted?'CLIENT_DISCONNECTED':errorCode,requestBytes,durationMs:Math.round(performance.now()-started)};
      try{record(event);}catch{/* Diagnostics must never change verification. */}
    };
    res.once('finish',()=>emit(false));res.once('close',()=>emit(!res.writableFinished));
    next();
  };
}
