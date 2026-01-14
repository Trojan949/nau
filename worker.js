import { connect } from "cloudflare:sockets";

// Variables
let serviceName = "";
let APP_DOMAIN = "";
let prxIP = "";
let cachedPrxList = [];

// Constant
const horse = "dHJvamFu";  // "trojan" in base64
const flash = "dm1lc3M=";  // "vmess" in base64
const v2 = "djJyYXk=";    // "v2ray" in base64
const neko = "Y2xhc2g=";  // "clash" in base64
const vless = "dmxlc3M=";  // "vless" in base64

const PORTS = [443, 80];
const PROTOCOLS = [atob(horse), atob(flash), atob(vless), "ss"];
const KV_PRX_URL = "https://raw.githubusercontent.com/backup-heavenly-demons/gateway/refs/heads/main/kvProxyList.json";
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = {
  host: "udp-relay.hobihaus.space",
  port: 7300,
};
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};
async function getKVPrxList(kvPrxUrl = KV_PRX_URL) {
  if (!kvPrxUrl) {
    throw new Error("No URL Provided!");
  }

  const kvPrx = await fetch(kvPrxUrl);
  if (kvPrx.status == 200) {
    return await kvPrx.json();
  } else {
    return {};
  }
}

async function reverseWeb(request, target, targetPath) {
  const targetUrl = new URL(request.url);
  const targetChunk = target.split(":");

  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk[1]?.toString() || "443";
  targetUrl.pathname = targetPath || targetUrl.pathname;

  const modifiedRequest = new Request(targetUrl, request);
  modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

  const response = await fetch(modifiedRequest);

  const newResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
    newResponse.headers.set(key, value);
  }
  newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");

  return newResponse;
}

function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

async function embedAssets(response, originalUrl) {
  const rewriter = new HTMLRewriter();

  const fetchAndEncode = async (assetUrl) => {
    try {
      const absoluteUrl = new URL(assetUrl, originalUrl.href).href;
      const assetResponse = await fetch(absoluteUrl);
      if (!assetResponse.ok) return null;

      const contentType = assetResponse.headers.get('content-type') || 'application/octet-stream';
      const buffer = await assetResponse.arrayBuffer();
      const base64 = bufferToBase64(buffer);
      return `data:${contentType};base64,${base64}`;
    } catch (e) {
      console.error(`Failed to fetch and embed asset: ${assetUrl}`, e);
      return null;
    }
  };

  rewriter.on('link[rel="stylesheet"]', {
    async element(element) {
      const href = element.getAttribute('href');
      if (href) {
        const absoluteUrl = new URL(href, originalUrl.href).href;
        const cssResponse = await fetch(absoluteUrl);
        if (cssResponse.ok) {
            const cssText = await cssResponse.text();
            element.replace(`<style>${cssText}</style>`, { html: true });
        }
      }
    },
  });

  rewriter.on('img', {
    async element(element) {
      const src = element.getAttribute('src');
      if (src && !src.startsWith('data:')) {
        const dataUri = await fetchAndEncode(src);
        if (dataUri) {
          element.setAttribute('src', dataUri);
        }
      }
    },
  });

  rewriter.on('script[src]', {
    async element(element) {
      const src = element.getAttribute('src');
      if (src) {
        const absoluteUrl = new URL(src, originalUrl.href).href;
        const scriptResponse = await fetch(absoluteUrl);
        if (scriptResponse.ok) {
          const scriptText = await scriptResponse.text();
          element.removeAttribute('src');
          element.append(scriptText, { html: false });
        }
      }
    }
  });

  return rewriter.transform(response);
}
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      APP_DOMAIN = url.hostname;
      serviceName = APP_DOMAIN.split(".")[0];

      const upgradeHeader = request.headers.get("Upgrade");

      // Handle WebSocket connections
      if (upgradeHeader === "websocket") {
        // Support multiple separators: "-", ":", "="
        const pathRegex = /^\/([^:=-]+)[:=-](\d+)$/;
        const prxMatch = url.pathname.match(pathRegex);

        if (url.pathname.length == 3 || url.pathname.match(",")) {
          const prxKeys = url.pathname.replace("/", "").toUpperCase().split(",");
          const prxKey = prxKeys[Math.floor(Math.random() * prxKeys.length)];
          const kvPrx = await getKVPrxList();

          if (kvPrx && kvPrx[prxKey]) {
            const selectedPrx = kvPrx[prxKey][Math.floor(Math.random() * kvPrx[prxKey].length)];
            prxIP = selectedPrx.replace(/[-=]/, ':');
          }
          return await websocketHandler(request);
        } else if (prxMatch) {
          prxIP = `${prxMatch[1]}:${prxMatch[2]}`;
          return await websocketHandler(request);
        }
      }

      // Handle web interface and reverse proxy
      if (url.pathname.startsWith("/sub")) {
        return await handleSubPage(request);
      }

      const targetReversePrx = env.REVERSE_PRX_TARGET || "example.com";
      const response = await reverseWeb(request, targetReversePrx);

      if (env.EMBED_ASSETS === 'true' && response.headers.get('content-type')?.includes('text/html')) {
        return embedAssets(response, url);
      }

      return response;
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: { ...CORS_HEADER_OPTIONS },
      });
    }
  },
};
async function websocketHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = {
    value: null,
  };
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS) {
            return handleUDPOutbound(
              DNS_SERVER_ADDRESS,
              DNS_SERVER_PORT,
              chunk,
              webSocket,
              null,
              log,
              RELAY_SERVER_UDP
            );
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const protocol = await protocolSniffer(chunk);
          let protocolHeader;

          if (protocol === atob(horse)) {
            protocolHeader = readHorseHeader(chunk);
          } else if (protocol === atob(flash)) {
            protocolHeader = readFlashHeader(chunk);
          } else if (protocol === atob(vless)) {
            protocolHeader = readVlessHeader(chunk);
          } else if (protocol === "ss") {
            protocolHeader = readSsHeader(chunk);
          } else {
            throw new Error("Unknown Protocol!");
          }

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
              return handleUDPOutbound(
                DNS_SERVER_ADDRESS,
                DNS_SERVER_PORT,
                chunk,
                webSocket,
                protocolHeader.version,
                log,
                RELAY_SERVER_UDP
              );
            }

            return handleUDPOutbound(
              protocolHeader.addressRemote,
              protocolHeader.portRemote,
              chunk,
              webSocket,
              protocolHeader.version,
              log,
              RELAY_SERVER_UDP
            );
          }

          handleTCPOutBound(
            remoteSocketWrapper,
            protocolHeader.addressRemote,
            protocolHeader.portRemote,
            protocolHeader.rawClientData,
            webSocket,
            protocolHeader.version,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) {
      if (horseDelimiter[2] === 0x01 || horseDelimiter[2] === 0x03 || horseDelimiter[2] === 0x7f) {
        if (horseDelimiter[3] === 0x01 || horseDelimiter[3] === 0x03 || horseDelimiter[3] === 0x04) {
          return atob(horse);
        }
      }
    }
  }

  const flashDelimiter = new Uint8Array(buffer.slice(1, 17));
  if (arrayBufferToHex(flashDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
    return atob(flash);
  }

  // Add VLESS detection
  const vlessDelimiter = new Uint8Array(buffer.slice(0, 1));
  if (vlessDelimiter[0] === 0x00) {
    return atob(vless);
  }

  return "ss"; // default
}
function readVlessHeader(buffer) {
  const version = new Uint8Array(buffer.slice(0, 1));
  if (version[0] !== 0) {
    return {
      hasError: true,
      message: `invalid VLESS version ${version[0]}`,
    };
  }

  let isUDP = false;
  const uuid = buffer.slice(1, 17);
  const optLength = new Uint8Array(buffer.slice(17, 18))[0];
  
  const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (cmd === 1) {
    // TCP
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `invalid VLESS command ${cmd}`,
    };
  }

  const portIndex = 18 + optLength + 1;
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressType = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";

  switch (addressType) {
    case 1: // IPv4
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2: // Domain
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: // IPv6
      addressLength = 16;
      const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid VLESS address type ${addressType}`,
      };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    rawClientData: buffer.slice(addressValueIndex + addressLength),
    version: new Uint8Array([version[0], 0]),
    isUDP: isUDP,
  };
}
function readHorseHeader(buffer) {
  const dataBuffer = buffer.slice(58);
  if (dataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid request data",
    };
  }

  let isUDP = false;
  const view = new DataView(dataBuffer);
  const cmd = view.getUint8(0);
  if (cmd == 3) {
    isUDP = true;
  } else if (cmd != 1) {
    throw new Error("Unsupported command type!");
  }

  let addressType = view.getUint8(1);
  let addressLength = 0;
  let addressValueIndex = 2;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3: // For Domain
      addressLength = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4: // For IPv6
      addressLength = 16;
      const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = dataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 4,
    rawClientData: dataBuffer.slice(portIndex + 4),
    version: null,
    isUDP: isUDP,
  };
}

function readFlashHeader(buffer) {
  const version = new Uint8Array(buffer.slice(0, 1));
  let isUDP = false;

  const optLength = new Uint8Array(buffer.slice(17, 18))[0];

  const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (cmd === 1) {
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${cmd} is not supported`,
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1));

  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2: // For Domain
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: // For IPv6
      addressLength = 16;
      const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    rawClientData: buffer.slice(addressValueIndex + addressLength),
    version: new Uint8Array([version[0], 0]),
    isUDP: isUDP,
  };
}

function readSsHeader(buffer) {
  const view = new DataView(buffer);
  const addressType = view.getUint8(0);
  let addressLength = 0;
  let addressValueIndex = 1;
  let addressValue = "";

  switch (addressType) {
    case 1: // IPv4
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3: // Domain
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4: // IPv6
      addressLength = 16;
      const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `Invalid addressType for SS: ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `Destination address empty, address type is: ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 2,
    rawClientData: buffer.slice(portIndex + 2),
    version: null,
    isUDP: portRemote == 53,
  };
}
async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  responseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();

    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = await connectAndWrite(
      prxIP.split(/[:=-]/)[0] || addressRemote,
      prxIP.split(/[:=-]/)[1] || portRemote
    );
    tcpSocket.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

async function handleUDPOutbound(targetAddress, targetPort, dataChunk, webSocket, responseHeader, log, relay) {
  try {
    let protocolHeader = responseHeader;

    const tcpSocket = connect({
      hostname: relay.host,
      port: relay.port,
    });

    const header = `udp:${targetAddress}:${targetPort}`;
    const headerBuffer = new TextEncoder().encode(header);
    const separator = new Uint8Array([0x7c]);
    const relayMessage = new Uint8Array(headerBuffer.length + separator.length + dataChunk.byteLength);
    relayMessage.set(headerBuffer, 0);
    relayMessage.set(separator, headerBuffer.length);
    relayMessage.set(new Uint8Array(dataChunk), headerBuffer.length + separator.length);

    const writer = tcpSocket.writable.getWriter();
    await writer.write(relayMessage);
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
        close() {
          log(`UDP connection to ${targetAddress} closed`);
        },
        abort(reason) {
          console.error(`UDP connection aborted due to ${reason}`);
        },
      })
    );
  } catch (e) {
    console.error(`Error while handling UDP outbound: ${e.message}`);
  }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
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

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
const baseHTML = `
<!DOCTYPE html>
<html lang="en" id="html" class="scroll-auto scrollbar-hide dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Proxy List</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
      .scrollbar-hide::-webkit-scrollbar{display:none}
      .scrollbar-hide{-ms-overflow-style:none;scrollbar-width:none}
    </style>
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/lozad/dist/lozad.min.js"></script>
    <script>tailwind.config={darkMode:'selector'}</script>
  </head>
  <body class="bg-white dark:bg-neutral-800 bg-fixed">
    <div id="notification-badge" class="fixed z-50 opacity-0 transition-opacity ease-in-out duration-300 mt-9 mr-6 right-0 p-3 max-w-sm bg-white rounded-xl border border-2 border-neutral-800 flex items-center gap-x-4">
      <div><div class="text-md font-bold text-blue-500">Success!</div><p class="text-sm text-neutral-800">Config copied to clipboard</p></div>
    </div>
    <div>
      <div class="h-full fixed top-0 w-14 bg-white dark:bg-neutral-800 border-r-2 border-neutral-800 dark:border-white z-20 overflow-y-scroll scrollbar-hide">
        <div class="text-2xl flex flex-col items-center h-full gap-2">PLACEHOLDER_FLAGS</div>
      </div>
    </div>
    <div class="container mx-auto pl-16 pr-4">
      <div id="container-title" class="sticky top-0 bg-white dark:bg-neutral-800 border-b-2 border-neutral-800 dark:border-white z-10 py-6">
        <h1 class="text-xl text-center text-neutral-800 dark:text-white">PLACEHOLDER_TITLE</h1>
      </div>
      <div class="flex flex-wrap gap-6 pt-10 justify-center">PLACEHOLDER_PROXIES</div>
      <nav id="container-pagination" class="mt-8 flex justify-center pb-10">
        <ul class="flex justify-center space-x-4">PLACEHOLDER_PAGINATION</ul>
      </nav>
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
    constructor(request) {
        this.html = baseHTML;
        this.request = request;
        this.url = new URL(request.url);
        this.proxies = [];
    }

    setTitle(title) {
        this.html = this.html.replace("PLACEHOLDER_TITLE", title);
    }

    addProxy(proxy, configs) {
        this.proxies.push({ proxy, configs });
    }

    buildFlags() {
        const flags = [...new Set(this.proxies.map(p => p.proxy.country))];
        const flagElements = flags.map(country => 
            `<a href="/sub?cc=${country}" class="py-1">
                <img width=20 src="https://hatscripts.github.io/circle-flags/flags/${country.toLowerCase()}.svg" 
                     onerror="this.style.display='none'" />
             </a>`
        ).join('');
        this.html = this.html.replace("PLACEHOLDER_FLAGS", flagElements);
    }

    buildProxies() {
        const proxyElements = this.proxies.map(({proxy, configs}) => `
            <div class="lozad mb-2 bg-white dark:bg-neutral-800 rounded-lg p-4 w-60 border-2 border-neutral-800">
                <div class="rounded py-1 px-2 bg-amber-400 dark:bg-neutral-800 dark:border-2 dark:border-amber-400">
                    <h5 class="font-bold text-md text-neutral-900 dark:text-white mb-1 overflow-hidden text-ellipsis whitespace-nowrap">
                        ${proxy.org}
                    </h5>
                    <div class="text-neutral-900 dark:text-white text-sm">
                        <p>IP: ${proxy.proxyIP}</p>
                        <p>Port: ${proxy.proxyPort}</p>
                        <p>CC: ${proxy.country}</p>
                    </div>
                </div>
                <div class="flex flex-col gap-2 mt-3 text-sm">
                    <button onclick="copyToClipboard('${configs.vless.tls}')" 
                            class="bg-blue-500 dark:bg-neutral-800 dark:border-2 dark:border-blue-500 rounded p-1 w-full text-white hover:bg-blue-600">
                        VLESS TLS
                    </button>
                    <button onclick="copyToClipboard('${configs.vless.ntls}')"
                            class="bg-blue-500 dark:bg-neutral-800 dark:border-2 dark:border-blue-500 rounded p-1 w-full text-white hover:bg-blue-600">
                        VLESS Non-TLS
                    </button>
                    <button onclick="copyToClipboard('${configs.trojan.tls}')"
                            class="bg-blue-500 dark:bg-neutral-800 dark:border-2 dark:border-blue-500 rounded p-1 w-full text-white hover:bg-blue-600">
                        Trojan
                    </button>
                    <button onclick="copyToClipboard('${configs.vmess.tls}')"
                            class="bg-blue-500 dark:bg-neutral-800 dark:border-2 dark:border-blue-500 rounded p-1 w-full text-white hover:bg-blue-600">
                        VMESS
                    </button>
                    <button onclick="copyToClipboard('${configs.ss.tls}')"
                            class="bg-blue-500 dark:bg-neutral-800 dark:border-2 dark:border-blue-500 rounded p-1 w-full text-white hover:bg-blue-600">
                        Shadowsocks
                    </button>
                </div>
            </div>
        `).join('');
        this.html = this.html.replace("PLACEHOLDER_PROXIES", proxyElements);
    }

    addPagination(currentPage, hasMore) {
        const pagination = `
            ${currentPage > 0 ? `
                <li><button class="px-3 py-1 bg-amber-400 border-2 border-neutral-800 rounded hover:bg-amber-500" 
                            onclick="navigateTo('/sub/${currentPage - 1}')">Previous</button></li>
            ` : ''}
            ${hasMore ? `
                <li><button class="px-3 py-1 bg-amber-400 border-2 border-neutral-800 rounded hover:bg-amber-500" 
                            onclick="navigateTo('/sub/${currentPage + 1}')">Next</button></li>
            ` : ''}
        `;
        this.html = this.html.replace("PLACEHOLDER_PAGINATION", pagination);
    }

    build() {
        this.buildFlags();
        this.buildProxies();
        return this.html;
    }
}

async function generateConfig(hostname, proxy) {
    const uuid = crypto.randomUUID();
    const path = `/${proxy.proxyIP}:${proxy.proxyPort}`;
    
    return {
        vless: {
            tls: `vless://${uuid}@${hostname}:443?encryption=none&security=tls&sni=${hostname}&fp=chrome&type=ws&host=${hostname}&path=${path}#${proxy.org}-TLS`,
            ntls: `vless://${uuid}@${hostname}:80?encryption=none&security=none&sni=${hostname}&fp=chrome&type=ws&host=${hostname}&path=${path}#${proxy.org}-NTLS`
        },
        trojan: {
            tls: `trojan://${uuid}@${hostname}:443?security=tls&sni=${hostname}&type=ws&host=${hostname}&path=${path}#${proxy.org}-TLS`
        },
        vmess: {
            tls: `vmess://${btoa(JSON.stringify({
                v: "2",
                ps: `${proxy.org}-TLS`,
                add: hostname,
                port: 443,
                id: uuid,
                aid: 0,
                net: "ws",
                type: "none",
                host: hostname,
                path: path,
                tls: "tls",
                sni: hostname
            }))}`
        },
        ss: {
            tls: `ss://${btoa(`aes-256-gcm:${uuid}@${hostname}:443`)}?plugin=v2ray-plugin%3Bhost%3D${hostname}%3Bpath%3D${path}%3Btls#${proxy.org}-TLS`
        }
    };
}
