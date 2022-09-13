import { RedirectResponse } from "../response/mod.ts";
import { type CookieContainer } from "../session/mod.ts";

export interface AuthenticateConf<User> {
  session: CookieContainer<User>;
  error: CookieContainer<{ message: string }>;
  strategyType: CookieContainer<{ name: string }>;
  /**
   * To what URL redirect in case of a successful authentication.
   */
  successUrl: URL;
  /**
   * To what URL redirect in case of a failed authentication.
   */
  failureUrl: URL;
}

type AuthHandler = (
  req: Request,
) => Promise<Response>;

export interface Strategy {
  name: string;
  authenticate: AuthHandler;
}

export interface StrategyFactory<User, Deps = unknown> {
  options: AuthenticateConf<User>;
  dependencies: Deps;
  create: (d: Deps) => Strategy;
}

export type VerifyCb<User, Params> = (p: Params) => Promise<User | Error>;

export function createStrategyFactory<User>(conf: AuthenticateConf<User>) {
  async function success(user: User, name: string) {
    const response = new RedirectResponse(conf.successUrl);
    await conf.session.set(user, response.headers);
    conf.strategyType.set({ name }, response.headers);
    return response;
  }

  async function failure(message: string) {
    const response = new RedirectResponse(conf.failureUrl);
    await conf.error.set({ message }, response.headers);
    conf.session.clear(response.headers);
    return response;
  }

  return { success, failure };
}
