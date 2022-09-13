import { Cookie, deleteCookie, getCookies, setCookie } from "./deps.ts";
import { decodeCookieValue, encodeCookieValue } from "./encoding.ts";

type Key = { name: string };
type CookieOptions = Omit<Cookie, "name" | "value" | "unparsed">;
type CookieSetter<T> = (
  val: T,
  headers: Headers,
  opt?: CookieOptions,
) => Promise<void>;

export interface CookieContainer<T> {
  get: (headers: Headers) => Promise<null | T>;
  set: CookieSetter<T>;
  flash: CookieSetter<T>;
  clear: (
    headers: Headers,
    attributes?: { path?: string; domain?: string },
  ) => void;
}

export function createContainer<T>(
  opts: CookieOptions & Key,
  secrets: string[] = [],
): CookieContainer<T> {
  const flashName = `__flash_${opts.name}__`;

  /** Set the value of the cookie */
  const set: CookieSetter<T> = async (val, headers, opt) => {
    const cookie: Cookie = {
      ...opts,
      ...(opt ?? {}),
      value: await encodeCookieValue(val, secrets),
    };
    setCookie(headers, cookie);
  };

  return {
    async get(headers) {
      const cookies = getCookies(headers);
      let output: null | T = null;
      if (opts.name in cookies) {
        output = await decodeCookieValue<T>(cookies[opts.name], secrets);
      }
      if (flashName in cookies) {
        deleteCookie(headers, flashName, {
          path: opts.path,
          domain: opts.domain,
        });
      }
      return output;
    },
    set,

    /** Set the value of the cookie but delete the value upon the next read */
    async flash(val, headers, opt): Promise<void> {
      await set(val, headers, opt);
      setCookie(headers, {
        name: flashName,
        value: "true",
        ...opt,
      });
    },

    clear(
      headers: Headers,
      attributes?: {
        path?: string;
        domain?: string;
      },
    ) {
      deleteCookie(headers, opts.name, attributes);
    },
  };
}
