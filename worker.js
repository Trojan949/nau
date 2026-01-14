export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Test endpoint
    if (url.pathname === '/test') {
      return new Response('Worker is OK! ✅', { status: 200 });
    }
    
    // Test KV fetch
    if (url.pathname === '/test-kv') {
      try {
        const kvUrl = env.KV_PROXY_URL || "https://raw.githubusercontent.com/Trojan949/nau/main/kvProxyList.json";
        const response = await fetch(kvUrl);
        const data = await response.json();
        return new Response(JSON.stringify(data, null, 2), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (e) {
        return new Response(`KV Error: ${e.message}`, { status: 500 });
      }
    }
    
    return new Response('Hello from NAU Worker!', { status: 200 });
  }
};
