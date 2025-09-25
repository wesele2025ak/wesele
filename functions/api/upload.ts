export const onRequestPost: PagesFunction<{
  GOOGLE_SA_JSON: string,
  DRIVE_FOLDER_ID: string,
}> = async ({ request, env }) => {
  try {
    const form = await request.formData();
    const file = form.get('file') as File | null;
    if (!file) return jerr('file is required', 400);

    const { client_email, private_key } = JSON.parse(env.GOOGLE_SA_JSON);
    const accessToken = await getAccessToken(client_email, private_key);

    const boundary = '----cf-' + crypto.randomUUID();
    const meta = { name: sanitize(file.name || `upload-${Date.now()}.jpg`),
                   parents: [env.DRIVE_FOLDER_ID] };
    const body = await multipart(boundary, meta, file);

    const res = await fetch(
      'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart',
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': `multipart/related; boundary=${boundary}`,
        },
        body
      }
    );
    if (!res.ok) return jerr('Drive error: ' + await res.text(), 502);

    const data = await res.json();
    return new Response(JSON.stringify({ ok: true, id: data.id }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e: any) {
    return jerr(e.message || 'server error', 500);
  }
};

function jerr(msg: string, status=400) {
  return new Response(JSON.stringify({ ok:false, error: msg }), {
    status, headers: { 'Content-Type': 'application/json' }
  });
}

function sanitize(name: string){ return name.replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,150); }

async function multipart(boundary: string, metadata: any, file: File) {
  const enc = new TextEncoder();
  const p1 = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n`;
  const p2 = `--${boundary}\r\nContent-Type: ${file.type || 'application/octet-stream'}\r\n\r\n`;
  const p3 = `\r\n--${boundary}--`;
  const b1 = enc.encode(p1), b2 = enc.encode(p2), b3 = enc.encode(p3);
  const fb = new Uint8Array(await file.arrayBuffer());
  const out = new Uint8Array(b1.length + b2.length + fb.length + b3.length);
  out.set(b1,0); out.set(b2,b1.length); out.set(fb,b1.length+b2.length); out.set(b3,b1.length+b2.length+fb.length);
  return out;
}

async function getAccessToken(client_email: string, private_key: string) {
  const now = Math.floor(Date.now()/1000);
  const enc = new TextEncoder();
  const b64url = (u8: Uint8Array) => {
    let s=''; for (let i=0;i<u8.length;i++) s += String.fromCharCode(u8[i]);
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  };
  const header = b64url(enc.encode(JSON.stringify({ alg:'RS256', typ:'JWT' })));
  const claim = {
    iss: client_email,
    scope: 'https://www.googleapis.com/auth/drive.file',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now+3600
  };
  const payload = b64url(enc.encode(JSON.stringify(claim)));
  const toSign = enc.encode(`${header}.${payload}`);

  const keyData = pemToPkcs8(private_key);
  const key = await crypto.subtle.importKey(
    'pkcs8', keyData, { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, toSign));
  const assertion = `${header}.${payload}.${b64url(sig)}`;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method:'POST',
    headers:{ 'Content-Type':'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion
    })
  });
  if (!res.ok) throw new Error('token exchange failed');
  const j = await res.json();
  return j.access_token as string;
}

function pemToPkcs8(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----[^-]+-----/g,'').replace(/\s+/g,'');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
