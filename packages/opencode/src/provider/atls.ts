import { Log } from "../util/log"
import { Flag } from "../flag/flag"
import type { Config } from "../config/config"

export namespace Atls {
  const log = Log.create({ service: "atls" })

  let cachedFetch: ((input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) | undefined
  let binding: AtlsBinding | undefined

  interface AtlsBinding {
    atlsConnect(
      targetHost: string,
      serverName: string,
      policyJson: any,
    ): Promise<{ socketId: number; attestation: AtlsAttestation }>
    socketRead(socketId: number, size?: number | null): Promise<Buffer>
    socketWrite(socketId: number, data: Buffer): Promise<number>
    socketClose(socketId: number): Promise<void>
    socketDestroy(socketId: number): void
    closeAllSockets(): Promise<void>
  }

  interface AtlsAttestation {
    trusted: boolean
    teeType: string
    measurement?: string
    tcbStatus: string
    advisoryIds: string[]
  }

  // ---------------------------------------------------------------------------
  // Connection pool
  //
  // Reuses aTLS sockets across HTTP requests to avoid the ~1s handshake per
  // request. Sockets live in atlas-node's Rust HashMap until explicitly closed
  // or until socketRead returns EOF (which removes them). With keep-alive the
  // TLS stream stays open after the HTTP response body ends, so we can send
  // another request on the same socket.
  // ---------------------------------------------------------------------------

  interface PooledSocket {
    socketId: number
    attestation: AtlsAttestation
    idleSince: number
  }

  const idle: PooledSocket[] = []
  const POOL_MAX_IDLE = 4
  const POOL_MAX_AGE_MS = 55_000 // slightly under typical 60s server timeout

  function poolAcquire(b: AtlsBinding): PooledSocket | undefined {
    const now = Date.now()
    while (idle.length > 0) {
      const entry = idle.shift()!
      if (now - entry.idleSince > POOL_MAX_AGE_MS) {
        b.socketClose(entry.socketId).catch(() => {})
        continue
      }
      return entry
    }
    return undefined
  }

  function poolRelease(b: AtlsBinding, entry: PooledSocket) {
    entry.idleSince = Date.now()
    if (idle.length >= POOL_MAX_IDLE) {
      const evicted = idle.shift()!
      b.socketClose(evicted.socketId).catch(() => {})
    }
    idle.push(entry)
  }

  // ---------------------------------------------------------------------------

  function parseTarget(target: string) {
    const withoutProtocol = target.trim().replace(/^https?:\/\//, "")
    const hostPart = withoutProtocol.split("/")[0]
    const [host, port = "443"] = hostPart.split(":")
    return { host, port, hostPort: `${host}:${port}` }
  }

  async function loadBinding(): Promise<AtlsBinding> {
    if (binding) return binding
    const mod = await import("@concrete-security/atlas-node/binding")
    binding = (mod as any).default ?? mod
    return binding!
  }

  /**
   * Build a raw HTTP/1.1 request over an aTLS socket and return a standard Response.
   * Handles chunked transfer encoding for streaming LLM responses (SSE).
   * Supports connection pooling: reuses idle sockets and returns them to the
   * pool after the response body is fully consumed.
   */
  async function doAtlsRequest(
    b: AtlsBinding,
    target: { host: string; port: string; hostPort: string },
    policy: any,
    serverName: string,
    url: URL,
    init: RequestInit | undefined,
    onAttestation?: (att: AtlsAttestation) => void,
  ): Promise<Response> {
    // Try a pooled socket first; fall back to a fresh connection.
    let socketId: number
    let attestation: AtlsAttestation
    let fromPool = false

    const pooled = poolAcquire(b)
    if (pooled) {
      socketId = pooled.socketId
      attestation = pooled.attestation
      fromPool = true
      log.info("pool hit", { socketId })
    } else {
      const conn = await b.atlsConnect(target.hostPort, serverName, policy)
      socketId = conn.socketId
      attestation = conn.attestation
      log.info("new connection", { socketId })
    }

    if (onAttestation) onAttestation(attestation)

    const method = init?.method ?? "GET"
    const reqHeaders = new Headers(init?.headers)
    if (!reqHeaders.has("host")) reqHeaders.set("host", url.host)
    if (!reqHeaders.has("accept")) reqHeaders.set("accept", "*/*")
    if (!reqHeaders.has("connection")) reqHeaders.set("connection", "keep-alive")

    let bodyBuf: Buffer | null = null
    if (init?.body) {
      if (typeof init.body === "string") {
        bodyBuf = Buffer.from(init.body)
      } else if (init.body instanceof ArrayBuffer) {
        bodyBuf = Buffer.from(init.body)
      } else if (init.body instanceof Uint8Array) {
        bodyBuf = Buffer.from(init.body)
      } else if (init.body instanceof ReadableStream) {
        const reader = init.body.getReader()
        const chunks: Buffer[] = []
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          chunks.push(Buffer.from(value))
        }
        bodyBuf = Buffer.concat(chunks)
      } else if (init.body && typeof init.body === "object" && Symbol.asyncIterator in (init.body as object)) {
        const chunks: Buffer[] = []
        for await (const chunk of init.body as unknown as AsyncIterable<Uint8Array>) {
          chunks.push(Buffer.from(chunk))
        }
        bodyBuf = Buffer.concat(chunks)
      }
    }

    if (bodyBuf && !reqHeaders.has("content-length")) {
      reqHeaders.set("content-length", String(bodyBuf.length))
    }

    // Build HTTP/1.1 request
    let headerStr = `${method} ${url.pathname}${url.search} HTTP/1.1\r\n`
    reqHeaders.forEach((value, name) => {
      headerStr += `${name}: ${value}\r\n`
    })
    headerStr += "\r\n"

    // If the pooled socket is stale (server closed it), the write will fail.
    // Catch that and retry with a fresh connection.
    try {
      await b.socketWrite(socketId, Buffer.from(headerStr))
      if (bodyBuf) {
        await b.socketWrite(socketId, bodyBuf)
      }
    } catch (e) {
      if (!fromPool) throw e
      log.info("pooled socket stale, reconnecting", { socketId })
      b.socketDestroy(socketId)
      const conn = await b.atlsConnect(target.hostPort, serverName, policy)
      socketId = conn.socketId
      attestation = conn.attestation
      if (onAttestation) onAttestation(attestation)
      await b.socketWrite(socketId, Buffer.from(headerStr))
      if (bodyBuf) {
        await b.socketWrite(socketId, bodyBuf)
      }
    }

    // Read response headers
    let headerBuf = Buffer.alloc(0)
    let headerEnd = -1
    while (headerEnd === -1) {
      const chunk = await b.socketRead(socketId, 16384)
      if (!chunk || chunk.length === 0) break
      headerBuf = Buffer.concat([headerBuf, chunk])
      headerEnd = headerBuf.indexOf("\r\n\r\n")
    }

    const headerText = headerBuf.slice(0, headerEnd).toString("utf-8")
    const leftover = headerBuf.slice(headerEnd + 4)

    // Parse status line
    const [statusLine, ...headerLines] = headerText.split("\r\n")
    const statusMatch = statusLine.match(/^HTTP\/\d\.\d\s+(\d+)\s*(.*)$/)
    const status = statusMatch ? parseInt(statusMatch[1]) : 0
    const statusText = statusMatch?.[2] ?? ""

    // Parse response headers
    const resHeaders = new Headers()
    for (const line of headerLines) {
      const idx = line.indexOf(":")
      if (idx > 0) {
        resHeaders.append(line.slice(0, idx).trim(), line.slice(idx + 1).trim())
      }
    }

    const isChunked = resHeaders.get("transfer-encoding")?.toLowerCase().includes("chunked")
    const contentLength = resHeaders.has("content-length") ? parseInt(resHeaders.get("content-length")!) : null
    const connectionHeader = resHeaders.get("connection")?.toLowerCase() ?? ""
    const canKeepAlive = connectionHeader !== "close"

    // Callback: return socket to pool or close it
    const releaseSocket = () => {
      if (canKeepAlive) {
        poolRelease(b, { socketId, attestation, idleSince: Date.now() })
      } else {
        b.socketClose(socketId).catch(() => {})
      }
    }
    const destroySocket = () => {
      b.socketDestroy(socketId)
    }

    // Create a ReadableStream that reads from the aTLS socket
    let bodyStream: ReadableStream<Uint8Array>

    if (isChunked) {
      bodyStream = createChunkedStream(b, socketId, leftover, releaseSocket, destroySocket)
    } else if (contentLength !== null) {
      bodyStream = createFixedLengthStream(b, socketId, leftover, contentLength, releaseSocket, destroySocket)
    } else {
      // Read until connection close — socket can't be reused
      bodyStream = createReadUntilCloseStream(b, socketId, leftover)
    }

    const response = new Response(bodyStream, {
      status,
      statusText,
      headers: resHeaders,
    })

    // Attach attestation
    Object.defineProperty(response, "attestation", {
      value: attestation,
      enumerable: true,
    })

    return response
  }

  function createFixedLengthStream(
    b: AtlsBinding,
    socketId: number,
    leftover: Buffer,
    contentLength: number,
    onDone: () => void,
    onCancel: () => void,
  ): ReadableStream<Uint8Array> {
    let received = 0
    let initial = leftover

    return new ReadableStream({
      async pull(controller) {
        try {
          let chunk: Buffer
          if (initial.length > 0) {
            chunk = initial
            initial = Buffer.alloc(0)
          } else {
            chunk = await b.socketRead(socketId, Math.min(16384, contentLength - received))
            if (!chunk || chunk.length === 0) {
              controller.close()
              onDone()
              return
            }
          }
          received += chunk.length
          controller.enqueue(new Uint8Array(chunk))
          if (received >= contentLength) {
            controller.close()
            onDone()
          }
        } catch {
          controller.close()
          onCancel()
        }
      },
      cancel() {
        onCancel()
      },
    })
  }

  function createReadUntilCloseStream(
    b: AtlsBinding,
    socketId: number,
    leftover: Buffer,
  ): ReadableStream<Uint8Array> {
    let initial = leftover

    return new ReadableStream({
      async pull(controller) {
        try {
          let chunk: Buffer
          if (initial.length > 0) {
            chunk = initial
            initial = Buffer.alloc(0)
          } else {
            chunk = await b.socketRead(socketId, 16384)
            if (!chunk || chunk.length === 0) {
              controller.close()
              // socketRead EOF already removed the socket from the Rust HashMap
              return
            }
          }
          controller.enqueue(new Uint8Array(chunk))
        } catch {
          controller.close()
          b.socketClose(socketId).catch(() => {})
        }
      },
      cancel() {
        b.socketDestroy(socketId)
      },
    })
  }

  function createChunkedStream(
    b: AtlsBinding,
    socketId: number,
    leftover: Buffer,
    onDone: () => void,
    onCancel: () => void,
  ): ReadableStream<Uint8Array> {
    let buffer = leftover

    return new ReadableStream({
      async pull(controller) {
        try {
          while (true) {
            // Look for chunk size line
            const lineEnd = buffer.indexOf("\r\n")
            if (lineEnd === -1) {
              const chunk = await b.socketRead(socketId, 16384)
              if (!chunk || chunk.length === 0) {
                controller.close()
                onDone()
                return
              }
              buffer = Buffer.concat([buffer, chunk])
              continue
            }

            const sizeLine = buffer.slice(0, lineEnd).toString("utf-8").trim()
            const chunkSize = parseInt(sizeLine, 16)

            if (chunkSize === 0) {
              // Terminal chunk — consume trailing \r\n so the socket is clean
              // for the next request
              const trailerStart = lineEnd + 2
              // Minimal: just skip past "0\r\n\r\n"
              const termEnd = buffer.indexOf("\r\n", trailerStart)
              if (termEnd === -1) {
                // Need to read the trailing \r\n
                while (true) {
                  const more = await b.socketRead(socketId, 64)
                  if (!more || more.length === 0) break
                  buffer = Buffer.concat([buffer, more])
                  if (buffer.indexOf("\r\n", trailerStart) !== -1) break
                }
              }
              controller.close()
              onDone()
              return
            }

            // Need chunkSize bytes + \r\n after the chunk
            const dataStart = lineEnd + 2
            const needed = dataStart + chunkSize + 2

            while (buffer.length < needed) {
              const more = await b.socketRead(socketId, Math.max(16384, needed - buffer.length))
              if (!more || more.length === 0) {
                if (buffer.length > dataStart) {
                  controller.enqueue(new Uint8Array(buffer.slice(dataStart)))
                }
                controller.close()
                onCancel()
                return
              }
              buffer = Buffer.concat([buffer, more])
            }

            const chunkData = buffer.slice(dataStart, dataStart + chunkSize)
            buffer = buffer.slice(needed)
            controller.enqueue(new Uint8Array(chunkData))
            return // One chunk per pull
          }
        } catch {
          controller.close()
          onCancel()
        }
      },
      cancel() {
        onCancel()
      },
    })
  }

  /**
   * Returns an aTLS-wrapped fetch function if configured, or undefined.
   * Uses raw NAPI bindings (NOT createAtlsFetch) because Bun's https.Agent
   * silently ignores createConnection, bypassing aTLS entirely.
   */
  export async function getFetch(
    config: { atls?: Config.Atls },
  ): Promise<((input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) | undefined> {
    if (Flag.OPENCODE_ATLS_DISABLE) return undefined
    if (!config.atls?.target) return undefined
    if (config.atls.enabled === false) return undefined
    if (cachedFetch) return cachedFetch

    const targetStr = Flag.OPENCODE_ATLS_TARGET ?? config.atls.target
    const target = parseTarget(targetStr)
    const policy = config.atls.policy
    const logAtt = config.atls.logAttestation
    const serverName = target.host

    try {
      const b = await loadBinding()
      log.info("initialized", { target: target.hostPort })

      const atlsFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        let url: URL | null = null
        let isRelative = false

        try {
          if (input instanceof URL) {
            url = input
          } else if (typeof input === "string") {
            url = new URL(input)
          } else if (input && typeof input === "object" && "url" in input) {
            url = new URL((input as Request).url)
          }
        } catch {
          isRelative = true
        }

        const shouldAtls = isRelative || url?.hostname === target.host

        if (!shouldAtls) {
          return globalThis.fetch(input, init)
        }

        const resolvedUrl = new URL(
          typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url,
          `https://${target.hostPort}`,
        )

        return doAtlsRequest(
          b,
          target,
          policy,
          serverName,
          resolvedUrl,
          init,
          logAtt ? (att) => log.info("attestation", att) : undefined,
        )
      }

      cachedFetch = atlsFetch
      return atlsFetch
    } catch (e) {
      log.error("failed to initialize - aTLS disabled", { error: e })
      return undefined
    }
  }

  export function reset() {
    cachedFetch = undefined
    // Drain the pool before clearing the binding
    const b = binding
    for (const entry of idle.splice(0)) {
      b?.socketClose(entry.socketId).catch(() => {})
    }
    binding = undefined
  }
}
