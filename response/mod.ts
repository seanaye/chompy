export class RedirectResponse extends Response {
  constructor(url: URL, init?: ResponseInit | undefined) {
    const headers = new Headers(init?.headers)
    headers.set("Location", url.toString())
    const opts: ResponseInit = {
      ...(init ?? {}),
      headers,
      status: 302,
      statusText: "Found"
    }
    super(null, opts)
  }
}
