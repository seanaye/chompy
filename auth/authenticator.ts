import { RedirectResponse } from "../response/mod.ts";
import { StrategyFactory } from "./strategy.ts";

interface Authenticator<User> {
  authenticate: (req: Request) => Promise<Response>;
  getUser: (req: Request) => Promise<User | null>;
  isAuthenticated: (req: Request) => Promise<RedirectResponse>;
  logout: (redirect: URL) => RedirectResponse;
}

/**
 * Create an authenticator from an auth strategy factory
 * @param factory - a strategy factory which confirms to the interface
 */
export function createAuthenticator<User, Deps = unknown>(
  factory: StrategyFactory<User, Deps>,
): Authenticator<User> {
  const { dependencies, create, options } = factory;
  const { authenticate } = create(dependencies);

  const getUser: Authenticator<User>["getUser"] = async (req) => {
    return await options.session.get(req.headers);
  };

  return {
    authenticate,
    getUser,
    async isAuthenticated(req: Request) {
      const u = await getUser(req);
      const url = u ? options.successUrl : options.failureUrl;
      return new RedirectResponse(url);
    },
    logout(redirect) {
      const res = new RedirectResponse(redirect);
      options.session.clear(res.headers);
      return res;
    },
  };
}
