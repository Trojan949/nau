import { connect } from "cloudflare:sockets";

// ===== SETTING PRIBADI & KONSTANTA =====
const serviceName = "nau";
const DEFAULT_PROXY_TARGET = "speed.cloudflare.com";
const TIMEOUT_SECONDS = 60;
const MAX_RETRIES = 5;
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

// Global Variables
let isApiReady = false;
let cachedProxyList = [];

// Error Handler
const handleError = async (error, request) => {
    console.error('Error:', error);
    
    if (error.message.includes('proxy') || error.message.includes('connection')) {
        try {
            const fallbackResponse = await fetch(DEFAULT_PROXY_TARGET);
            return fallbackResponse;
        } catch (fallbackError) {
            console.error('Fallback error:', fallbackError);
        }
    }
    
    return new Response(
        JSON.stringify({
            error: error.message || 'Internal Server Error',
            timestamp: new Date().toISOString()
        }),
        {
            status: error.status || 500,
            headers: {
                'Content-Type': 'application/json',
                ...CORS_HEADER_OPTIONS
            }
        }
    );
};

// Optimasi fetch
async function fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_SECONDS * 1000);
    
    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal,
            cf: {
                cacheTtl: 300,
                cacheEverything: true,
                minify: true,
            }
        });
        clearTimeout(timeoutId);
        return response;
    } catch (error) {
        clearTimeout(timeoutId);
        throw error;
    }
}

export default {
    async fetch(request, env, ctx) {
        try {
            // Setup error response helper
            const errorResponse = (message, status = 500) => new Response(
                JSON.stringify({ error: message, timestamp: new Date().toISOString() }),
                { 
                    status, 
                    headers: { 
                        'Content-Type': 'application/json',
                        ...CORS_HEADER_OPTIONS 
                    }
                }
            );

            // 1. Setup Environment & API Status
            const apiKey = env.CLOUDFLARE_API_KEY;
            const apiEmail = env.CLOUDFLARE_EMAIL;
            const accountID = env.CLOUDFLARE_ACCOUNT_ID;
            const zoneID = env.CLOUDFLARE_ZONE_ID;

            // Basic validation
            if (!apiKey || !apiEmail) {
                return errorResponse('Missing required credentials', 403);
            }

            if (apiKey && apiEmail && accountID && zoneID) isApiReady = true;

            const url = new URL(request.url);
            const upgradeHeader = request.headers.get("Upgrade");
            const hostname = request.headers.get("Host");

            // Add health check endpoint
            if (url.pathname === '/health') {
                return new Response('OK', { status: 200 });
            }
                        // 2. Handle WebSocket (VPN Tunneling)
            if (upgradeHeader === "websocket") {
                let proxyIP = "";
                const proxyMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

                // Logic pemilihan Proxy IP
                if (url.pathname.length == 4 || url.pathname.match(",")) { 
                    const proxyKeys = url.pathname.replace("/", "").toUpperCase().split(",");
                    const proxyKey = proxyKeys[Math.floor(Math.random() * proxyKeys.length)];
                    
                    if (env.KV_PROXY_URL) {
                        const kvProxy = await getKVProxyList(env.KV_PROXY_URL);
                        if (kvProxy && kvProxy[proxyKey]) {
                            proxyIP = kvProxy[proxyKey][Math.floor(Math.random() * kvProxy[proxyKey].length)];
                        }
                    }
                } else if (proxyMatch) {
                    proxyIP = proxyMatch[1];
                }

                if (proxyIP) {
                    let retries = 0;
                    while (retries < MAX_RETRIES) {
                        try {
                            return await websocketHandler(request, proxyIP);
                        } catch (err) {
                            retries++;
                            if (retries === MAX_RETRIES) {
                                return errorResponse(`WebSocket connection failed after ${MAX_RETRIES} attempts: ${err.message}`);
                            }
                            await new Promise(resolve => setTimeout(resolve, 1000 * retries));
                        }
                    }
                }
            }
                        // 3. Handle Subscription Page (/sub)
            if (url.pathname.startsWith("/sub")) {
                try {
                    const page = url.pathname.match(/^\/sub\/(\d+)$/);
                    const pageIndex = parseInt(page ? page[1] : "0");

                    const countrySelect = url.searchParams.get("cc")?.split(",");
                    const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL || "https://raw.githubusercontent.com/Trojan949/nau/main/proxyList.txt";
                    
                    let proxyList = await getProxyList(proxyBankUrl);
                    
                    if (countrySelect) {
                        proxyList = proxyList.filter((proxy) => countrySelect.includes(proxy.country));
                    }
                    
                    cachedProxyList = proxyList;

                    const result = await getAllConfig(request, hostname, proxyList, pageIndex);
                    return new Response(result, {
                        status: 200,
                        headers: { 
                            "Content-Type": "text/html;charset=utf-8",
                            "Cache-Control": "public, max-age=300"
                        }
                    });
                } catch (err) {
                    return errorResponse(`Error generating config: ${err.message}`);
                }
            }
                        // 4. Handle Cloudflare API (Auto Subdomain)
            if (url.pathname.startsWith("/api/v1/domains")) {
                if (!isApiReady) return errorResponse("API Credentials not set", 500);

                const cloudflareApi = new CloudflareApi(apiKey, apiEmail, zoneID, accountID);
                const action = url.pathname.split("/").pop();

                if (action === "get") {
                    const domains = await cloudflareApi.getDomainList();
                    return new Response(JSON.stringify(domains), { headers: CORS_HEADER_OPTIONS });
                } else if (action === "put") {
                    const domain = url.searchParams.get("domain");
                    const register = await cloudflareApi.registerDomain(domain);
                    return new Response(register.toString(), { 
                        status: register === 200 ? 200 : 400, 
                        headers: CORS_HEADER_OPTIONS 
                    });
                }
                
                if(url.pathname.includes("myip")) {
                    return new Response(JSON.stringify({
                        ip: request.headers.get("CF-Connecting-IP"),
                        country: request.headers.get("CF-IPCountry"),
                        asOrganization: request.cf.asOrganization
                    }), { headers: CORS_HEADER_OPTIONS });
                }
            }

            // 5. Default: Reverse Proxy dengan retry
            return await reverseProxyWithRetry(request, env.REVERSE_PROXY_TARGET || DEFAULT_PROXY_TARGET);

        } catch (err) {
            return new Response(
                JSON.stringify({ 
                    error: err.message, 
                    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined 
                }),
                { 
                    status: 500,
                    headers: { 
                        'Content-Type': 'application/json',
                        ...CORS_HEADER_OPTIONS 
                    }
                }
            );
        }
    }
};
async function websocketHandler(request, assignedProxyIP) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let addressLog = "";
    let portLog = "";
    const log = (info, event) => {
        if (process.env.NODE_ENV === 'development') {
            console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
        }
    };

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWapper = { value: null };
    let isDns = false;

    try {
        await readableWebSocketStream.pipeTo(new WritableStream({
            async write(chunk, controller) {
                if (isDns) {
                    return await handleDNSQuery(chunk, webSocket, null, log);
                }
                if (remoteSocketWapper.value) {
                    const writer = remoteSocketWapper.value.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                    return;
                }

                const protocol = await protocolSniffer(chunk);
                let protocolHeader;

                if (protocol === reverse("najorT")) {
                    protocolHeader = parseNajortHeader(chunk);
                } else if (protocol === reverse("SSELV")) {
                    protocolHeader = parseSselvHeader(chunk);
                } else if (protocol === reverse("skcoswodahS")) {
                    protocolHeader = parseSsHeader(chunk);
                } else {
                    protocolHeader = parseSsHeader(chunk);
                }

                if (protocolHeader.hasError) {
                    throw new Error(protocolHeader.message);
                }

                addressLog = protocolHeader.addressRemote;
                portLog = protocolHeader.portRemote;

                if (protocolHeader.isUDP) {
                    isDns = true;
                    await handleUDPOutbound(protocolHeader.addressRemote, protocolHeader.portRemote, protocolHeader.rawClientData, webSocket, protocolHeader.version, log);
                    return;
                }

                await handleTCPOutBound(
                    remoteSocketWapper,
                    protocolHeader.addressRemote,
                    protocolHeader.portRemote,
                    protocolHeader.rawClientData,
                    webSocket,
                    protocolHeader.version,
                    log,
                    assignedProxyIP
                );
            },
            close() { log(`readableWebSocketStream is close`); },
            abort(reason) { log(`readableWebSocketStream is abort`, JSON.stringify(reason)); },
        }));
    } catch (err) {
        log("WebSocket Error:", err);
        safeCloseWebSocket(webSocket);
    }

    return new Response(null, { status: 101, webSocket: client });
}
async function protocolSniffer(buffer) {
    if (buffer.byteLength >= 62) {
        const najortDelimiter = new Uint8Array(buffer.slice(56, 60));
        if (najortDelimiter[0] === 0x0d && najortDelimiter[1] === 0x0a) {
            if (najortDelimiter[2] === 0x01 || najortDelimiter[2] === 0x03 || najortDelimiter[2] === 0x7f) {
                if (najortDelimiter[3] === 0x01 || najortDelimiter[3] === 0x03 || najortDelimiter[3] === 0x04) {
                    return reverse("najorT");
                }
            }
        }
    }
    const sselvDelimiter = new Uint8Array(buffer.slice(1, 17));
    if (arrayBufferToHex(sselvDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
        return reverse("SSELV");
    }
    return reverse("skcoswodahS");
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log, assignedProxyIP) {
    async function connectAndWrite(address, port) {
        const targetHostname = assignedProxyIP ? assignedProxyIP.split(/[:=-]/)[0] : address;
        const targetPort = assignedProxyIP ? parseInt(assignedProxyIP.split(/[:=-]/)[1] || port) : port;
        
        const tcpSocket = connect({ hostname: targetHostname, port: targetPort });
        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
}

async function handleUDPOutbound(targetAddress, targetPort, udpChunk, webSocket, responseHeader, log) {
    try {
        let protocolHeader = responseHeader;
        const tcpSocket = connect({ hostname: targetAddress, port: targetPort });
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(
            new WritableStream({
                async write(chunk) {
                    if (webSocket.readyState === WS_READY_STATE_OPEN) {
                        if (protocolHeader) {
                            webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
                            protocolHeader = null;
                        } else {
                            webSocket.send(chunk);
                        }
                    }
                },
                close() { log(`UDP connection closed`); },
                abort(reason) { console.error(`UDP connection aborted`, reason); },
            })
        );
    } catch (e) { console.error(`Error UDP`, e); }
}

async function handleDNSQuery(chunk, webSocket, responseHeader, log) { }

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) return;
                controller.enqueue(event.data);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) return;
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer has error");
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel(reason) {
            if (readableStreamCancel) return;
            log(`ReadableStream was canceled`, reason);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        },
    });
    return stream;
}
function parseSsHeader(ssBuffer) {
    const view = new DataView(ssBuffer);
    const addressType = view.getUint8(0);
    let addressLength = 0, addressValueIndex = 1, addressValue = "";
    switch (addressType) {
        case 1: addressLength = 4; addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
        case 3: addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0]; addressValueIndex += 1; addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
        case 4: addressLength = 16; const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16)); addressValue = ipv6.join(":"); break;
        default: return { hasError: true, message: `Invalid addressType: ${addressType}` };
    }
    if (!addressValue) return { hasError: true, message: `Destination address empty` };
    const portIndex = addressValueIndex + addressLength;
    const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return { hasError: false, addressRemote: addressValue, addressType: addressType, portRemote: portRemote, rawDataIndex: portIndex + 2, rawClientData: ssBuffer.slice(portIndex + 2), version: null, isUDP: portRemote == 53 };
}
function parseSselvHeader(buffer) {
    const version = new Uint8Array(buffer.slice(0, 1));
    let isUDP = false;
    const optLength = new Uint8Array(buffer.slice(17, 18))[0];
    const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
    if (cmd === 1) {} else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: `command ${cmd} is not support` }; }
    const portIndex = 18 + optLength + 1;
    const portBuffer = buffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1));
    const addressType = addressBuffer[0];
    let addressLength = 0, addressValueIndex = addressIndex + 1, addressValue = "";
    switch (addressType) {
        case 1: addressLength = 4; addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
        case 2: addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0]; addressValueIndex += 1; addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
        case 3: addressLength = 16; const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16)); addressValue = ipv6.join(":"); break;
        default: return { hasError: true, message: `invalid addressType is ${addressType}` };
    }
    return { hasError: false, addressRemote: addressValue, addressType: addressType, portRemote: portRemote, rawDataIndex: addressValueIndex + addressLength, rawClientData: buffer.slice(addressValueIndex + addressLength), version: new Uint8Array([version[0], 0]), isUDP: isUDP };
}

function parseNajortHeader(buffer) {
    const socks5DataBuffer = buffer.slice(58);
    if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "invalid SOCKS5 request data" };
    let isUDP = false;
    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd == 3) { isUDP = true; } else if (cmd != 1) { throw new Error("Unsupported command type!"); }
    let addressType = view.getUint8(1);
    let addressLength = 0, addressValueIndex = 2, addressValue = "";
    switch (addressType) {
        case 1: addressLength = 4; addressValue = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
        case 3: addressLength = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0]; addressValueIndex += 1; addressValue = new TextDecoder().decode(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
        case 4: addressLength = 16; const dataView = new DataView(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16)); addressValue = ipv6.join(":"); break;
        default: return { hasError: true, message: `invalid addressType is ${addressType}` };
    }
    const portIndex = addressValueIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return { hasError: false, addressRemote: addressValue, addressType: addressType, portRemote: portRemote, rawDataIndex: portIndex + 4, rawClientData: socks5DataBuffer.slice(portIndex + 4), version: null, isUDP: isUDP };
}
async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let header = responseHeader;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                if (webSocket.readyState !== WS_READY_STATE_OPEN) controller.error("webSocket closed");
                if (header) {
                    webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            close() { log(`remoteConnection readable close`); },
            abort(reason) { console.error(`remoteConnection abort`, reason); },
        })
    ).catch((error) => { console.error(`remoteSocketToWS error`, error); safeCloseWebSocket(webSocket); });
}

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}
async function getProxyList(url) {
    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error("Network response was not ok");
        const text = await response.text();
        const lines = text.split('\n');
        const proxies = [];
        for(let line of lines) {
            line = line.trim();
            if(!line || line.startsWith("#")) continue;
            const parts = line.split('#');
            const address = parts[0].trim();
            const name = parts[1] || "Unknown";
            const [ip, port] = address.split(':');
            if(ip && port) {
                let country = "UN"; 
                if(name.match(/ID|SG|US|JP|CN/i)) country = name.match(/ID|SG|US|JP|CN/i)[0].toUpperCase();
                proxies.push({ proxyIP: ip, proxyPort: port, country: country, org: name });
            }
        }
        return proxies;
    } catch(e) { 
        console.error("Error fetching proxy list, using empty list", e);
        return []; 
    }
}

async function getKVProxyList(url) {
    try { 
        const res = await fetch(url); 
        return await res.json(); 
    } catch { 
        return {}; 
    }
}
async function reverseProxyWithRetry(request, target, maxRetries = 3) {
    let lastError;
    
    for (let i = 0; i < maxRetries; i++) {
        try {
            const url = new URL(request.url);
            url.hostname = target;
            url.protocol = "https:";

            const newHeaders = new Headers(request.headers);
            newHeaders.set("Host", target);
            newHeaders.set("Referer", `https://${target}/`);
            
            if (request.headers.get("Upgrade") === "websocket") {
                newHeaders.set("Connection", "Upgrade");
                newHeaders.set("Upgrade", "websocket");
            }

            const response = await fetchWithTimeout(url.toString(), {
                method: request.method,
                headers: newHeaders,
                body: request.body,
                redirect: 'follow'
            });

            if (!response.ok && i < maxRetries - 1) {
                throw new Error(`HTTP ${response.status}`);
            }

            return response;

        } catch (error) {
            lastError = error;
            if (i < maxRetries - 1) {
                await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
            }
        }
    }

    throw lastError;
}

async function getAllConfig(request, hostname, proxyList, pageIndex) {
    const doc = new Document(request);
    doc.setTitle("Nautica Proxy List");
    const pageSize = 20;
    const start = pageIndex * pageSize;
    const end = start + pageSize;
    const slicedProxies = proxyList.slice(start, end);

    for(const proxy of slicedProxies) {
        const uuid = crypto.randomUUID(); // Auto UUID
        const path = `/${proxy.proxyIP}:${proxy.proxyPort}`; 
        
        const vlessTls = `vless://${uuid}@${hostname}:443?encryption=none&security=tls&sni=${hostname}&fp=chrome&type=ws&host=${hostname}&path=${path}#${proxy.org}-TLS`;
        const vlessNtls = `vless://${uuid}@${hostname}:80?encryption=none&security=none&sni=${hostname}&fp=chrome&type=ws&host=${hostname}&path=${path}#${proxy.org}-NTLS`;
        const trojanTls = `trojan://${uuid}@${hostname}:443?security=tls&sni=${hostname}&type=ws&host=${hostname}&path=${path}#${proxy.org}-TLS`;
        
        doc.registerProxies(proxy, [vlessTls, vlessNtls, trojanTls]); 
    }
    doc.addPageButton("Prev", `/sub/${pageIndex - 1}`, pageIndex === 0);
    doc.addPageButton("Next", `/sub/${pageIndex + 1}`, end >= proxyList.length);
    return doc.build();
}
class CloudflareApi {
    constructor(apiKey, apiEmail, zoneID, accountID) {
        this.apiKey = apiKey;
        this.apiEmail = apiEmail;
        this.zoneID = zoneID;
        this.accountID = accountID;
        this.headers = { 
            "X-Auth-Email": this.apiEmail, 
            "X-Auth-Key": this.apiKey, 
            "Content-Type": "application/json" 
        };
    }
    
    async getDomainList() {
        const url = `https://api.cloudflare.com/client/v4/zones/${this.zoneID}/dns_records`;
        const res = await fetch(url, { headers: this.headers });
        const data = await res.json();
        return data.result ? data.result.map(d => d.name) : [];
    }
    
    async registerDomain(domain) {
        if(!domain) return 400;
        const url = `https://api.cloudflare.com/client/v4/zones/${this.zoneID}/dns_records`;
        const res = await fetch(url, { 
            method: "POST", 
            headers: this.headers, 
            body: JSON.stringify({ 
                type: "CNAME", 
                name: domain, 
                content: `${serviceName}.workers.dev`, 
                ttl: 1, 
                proxied: true 
            }) 
        });
        return res.status;
    }
}
const baseHTML = `
<!DOCTYPE html>
<html lang="en" id="html" class="scroll-auto scrollbar-hide dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Proxy List</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>.scrollbar-hide::-webkit-scrollbar{display:none}.scrollbar-hide{-ms-overflow-style:none;scrollbar-width:none}</style>
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/lozad/dist/lozad.min.js"></script>
    <script>tailwind.config={darkMode:'selector'}</script>
  </head>
  <body class="bg-white dark:bg-neutral-800 bg-fixed">
    <div id="notification-badge" class="fixed z-50 opacity-0 transition-opacity ease-in-out duration-300 mt-9 mr-6 right-0 p-3 max-w-sm bg-white rounded-xl border border-2 border-neutral-800 flex items-center gap-x-4">
      <div><div class="text-md font-bold text-blue-500">Berhasil!</div><p class="text-sm text-neutral-800">Copied to clipboard</p></div>
    </div>
    <div><div class="h-full fixed top-0 w-14 bg-white dark:bg-neutral-800 border-r-2 border-neutral-800 dark:border-white z-20 overflow-y-scroll scrollbar-hide"><div class="text-2xl flex flex-col items-center h-full gap-2">PLACEHOLDER_BENDERA_NEGARA</div></div></div>
    <div class="container mx-auto pl-16 pr-4">
      <div id="container-title" class="sticky top-0 bg-white dark:bg-neutral-800 border-b-2 border-neutral-800 dark:border-white z-10 py-6">
        <h1 class="text-xl text-center text-neutral-800 dark:text-white">PLACEHOLDER_JUDUL</h1>
      </div>
      <div class="flex flex-wrap gap-6 pt-10 justify-center">PLACEHOLDER_PROXY_GROUP</div>
      <nav id="container-pagination" class="mt-8 flex justify-center pb-10"><ul class="flex justify-center space-x-4">PLACEHOLDER_PAGE_BUTTON</ul></nav>
    </div>
    <script>
      function copyToClipboard(text) {
        navigator.clipboard.writeText(text);
        const notification = document.getElementById("notification-badge");
        notification.classList.remove("opacity-0");
        setTimeout(() => notification.classList.add("opacity-0"), 2000);
      }
      function navigateTo(link) { window.location.href = link + window.location.search; }
      const observer = lozad(); observer.observe();
    </script>
  </body>
</html>`;

class Document {
    proxies = [];
    constructor(request) { 
        this.html = baseHTML; 
        this.request = request; 
        this.url = new URL(this.request.url); 
    }
    
    setTitle(title) { 
        this.html = this.html.replaceAll("PLACEHOLDER_JUDUL", title); 
    }
    
    registerProxies(data, proxies) { 
        this.proxies.push({ ...data, list: proxies }); 
    }
    
    buildProxyGroup() {
        let proxyGroupElement = "";
        for (let i = 0; i < this.proxies.length; i++) {
            const proxyData = this.proxies[i];
            proxyGroupElement += `<div class="lozad mb-2 bg-white dark:bg-neutral-800 rounded-lg p-4 w-60 border-2 border-neutral-800">`;
            proxyGroupElement += `<div class="rounded py-1 px-2 bg-amber-400 dark:bg-neutral-800 dark:border-2 dark:border-amber-400"><h5 class="font-bold text-md text-neutral-900 dark:text-white mb-1 overflow-hidden text-ellipsis whitespace-nowrap">${proxyData.org}</h5><div class="text-neutral-900 dark:text-white text-sm"><p>IP: ${proxyData.proxyIP}</p><p>Port: ${proxyData.proxyPort}</p><p>CC: ${proxyData.country}</p></div></div>`;
            proxyGroupElement += `<div class="flex flex-col gap-2 mt-3 text-sm">`;
            const labels = ["VLESS TLS", "VLESS NTLS", "Trojan TLS"];
            for (let x = 0; x < 3; x++) {
                proxyGroupElement += `<button class="bg-blue-500 dark:bg-neutral-800 dark:border-2 dark:border-blue-500 rounded p-1 w-full text-white hover:bg-blue-600" onclick="copyToClipboard('${proxyData.list[x]}')">${labels[x]}</button>`;
            }
            proxyGroupElement += `</div></div>`;
        }
        this.html = this.html.replaceAll("PLACEHOLDER_PROXY_GROUP", proxyGroupElement);
    }
    
    buildCountryFlag() {
        const proxyBankUrl = this.url.searchParams.get("proxy-list");
        const flagList = new Set(cachedProxyList.map(p => p.country));
        let flagElement = "";
        flagList.forEach(flag => {
            if(flag) flagElement += `<a href="/sub?cc=${flag}${proxyBankUrl ? "&proxy-list=" + proxyBankUrl : ""}" class="py-1"><img width=20 src="https://hatscripts.github.io/circle-flags/flags/${flag.toLowerCase()}.svg" onerror="this.style.display='none'" /></a>`;
        });
        this.html = this.html.replaceAll("PLACEHOLDER_BENDERA_NEGARA", flagElement);
    }
    
    addPageButton(text, link, isDisabled) {
        const pageButton = `<li><button ${isDisabled ? "disabled class='opacity-50 cursor-not-allowed px-3 py-1 bg-gray-400 border-2 border-neutral-800 rounded'" : "class='px-3 py-1 bg-amber-400 border-2 border-neutral-800 rounded hover:bg-amber-500'"} onclick="navigateTo('${link}')">${text}</button></li>`;
        this.html = this.html.replaceAll("PLACEHOLDER_PAGE_BUTTON", `${pageButton}\nPLACEHOLDER_PAGE_BUTTON`);
    }
    
    build() { 
        this.buildProxyGroup(); 
        this.buildCountryFlag(); 
        return this.html.replaceAll(/PLACEHOLDER_\w+/gim, ""); 
    }
}
