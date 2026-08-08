const ORIGIN_HEADER = 'x-rsvp-origin-secret';
const AWS_LAMBDA_HOST_SUFFIX = '.lambda-url.eu-west-2.on.aws';

const secureResponseHeaders = (headers) => {
  const secured = new Headers(headers);
  secured.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
  secured.set('permissions-policy', 'camera=(), geolocation=(), microphone=(), payment=(), usb=()');
  secured.delete('server');
  secured.delete('x-amzn-trace-id');
  return secured;
};

const errorResponse = () => new Response(JSON.stringify({ error: 'origin_unavailable' }), {
  status: 502,
  headers: {
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
    'x-content-type-options': 'nosniff',
  },
});

export const validatedOrigin = (value) => {
  let origin;
  try {
    origin = new URL(value);
  } catch {
    return null;
  }

  if (origin.protocol !== 'https:' || !origin.hostname.endsWith(AWS_LAMBDA_HOST_SUFFIX)) return null;
  if (origin.username || origin.password || origin.port) return null;
  return origin;
};

export const proxyRequest = async (request, env, fetchImpl = fetch) => {
  const incomingUrl = new URL(request.url);
  if (incomingUrl.protocol !== 'https:') {
    incomingUrl.protocol = 'https:';
    return Response.redirect(incomingUrl, 308);
  }
  if (incomingUrl.hostname === 'www.calcada2026.pt') {
    incomingUrl.hostname = 'calcada2026.pt';
    return Response.redirect(incomingUrl, 308);
  }

  const origin = validatedOrigin(env.ORIGIN_URL);
  if (!origin || !env.ORIGIN_SECRET) return errorResponse();

  origin.pathname = incomingUrl.pathname;
  origin.search = incomingUrl.search;

  const headers = new Headers(request.headers);
  headers.delete(ORIGIN_HEADER);
  headers.delete('host');
  headers.delete('content-length');
  headers.set(ORIGIN_HEADER, env.ORIGIN_SECRET);
  headers.set('x-forwarded-host', incomingUrl.host);
  headers.set('x-forwarded-proto', 'https');

  const init = {
    method: request.method,
    headers,
    redirect: 'manual',
  };
  if (request.method !== 'GET' && request.method !== 'HEAD') init.body = request.body;

  try {
    const originResponse = await fetchImpl(origin, init);
    const responseHeaders = secureResponseHeaders(originResponse.headers);
    // Lambda Function URLs can return several independent Set-Cookie headers.
    // Rebuilding Headers can otherwise collapse them into one invalid cookie.
    const setCookies = typeof originResponse.headers.getSetCookie === 'function'
      ? originResponse.headers.getSetCookie()
      : [];
    if (setCookies.length) {
      responseHeaders.delete('set-cookie');
      for (const cookie of setCookies) responseHeaders.append('set-cookie', cookie);
    }
    return new Response(originResponse.body, {
      status: originResponse.status,
      statusText: originResponse.statusText,
      headers: responseHeaders,
    });
  } catch {
    return errorResponse();
  }
};

export default {
  fetch(request, env) {
    return proxyRequest(request, env);
  },
};
