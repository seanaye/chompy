import { RedirectResponse } from "../../response/mod.ts";
import { createContainer } from "../../session/mod.ts";
import {
  AuthenticateConf,
  createStrategyFactory,
  VerifyCb,
} from "../strategy.ts";

export interface OAuth2Profile {
  provider: string;
  id?: string;
  displayName?: string;
  name?: {
    familyName?: string;
    givenName?: string;
    middleName?: string;
  };
  emails?: Array<{
    value: string;
    type?: string;
  }>;
  photos?: Array<{ value: string }>;
}

export interface OAuth2StrategyOptions<User> extends AuthenticateConf<User> {
  authorizationURL: string;
  tokenURL: string;
  clientId: string;
  clientSecret: string;
  callbackURL: string;
}

export interface OAuth2StrategyVerifyParams<
  Profile extends OAuth2Profile,
  ExtraParams extends Record<string, unknown> = Record<string, never>,
> {
  accessToken: string;
  refreshToken: string | null;
  extraParams: ExtraParams;
  profile: Profile;
}

function authorizationParams(params: URLSearchParams): URLSearchParams {
  params.set("grant_type", "authorization_code");
  return new URLSearchParams(params);
}

export function createOAuth2Strategy<
  User,
  Profile extends OAuth2Profile,
  ExtraParams extends Record<string, unknown> = Record<string, never>,
>(
  options: OAuth2StrategyOptions<User>,
  verify: VerifyCb<User, OAuth2StrategyVerifyParams<Profile, ExtraParams>>,
) {
  const name = "oauth2";
  const stateContainer = createContainer<string>({ name: `${name}:state` });

  function getCallbackUrl(url: URL): URL {
    if (
      options.callbackURL.startsWith("http:") ||
      options.callbackURL.startsWith("https:")
    ) {
      return new URL(options.callbackURL);
    }
    if (options.callbackURL.startsWith("/")) {
      return new URL(options.callbackURL, url);
    }
    return new URL(`${url.protocol}//${options.callbackURL}`);
  }

  function getAuthorizationUrl(
    req: Request,
    state: string,
    authorizationParams: (u: URLSearchParams) => URLSearchParams,
  ) {
    const params = authorizationParams(new URL(req.url).searchParams);
    params.set("response_type", "code");
    params.set("client_id", options.clientId);
    params.set("redirect_uri", getCallbackUrl(new URL(req.url)).toString());
    params.set("state", state);

    const url = new URL(options.authorizationURL);
    url.search = params.toString();
    return url;
  }

  async function getAccessToken(res: Response) {
    const data = await res.json();
    if (data.isErr()) return data.error;
    const { refreshToken, accessToken, ...extraParams } = data.value;
    return {
      accessToken,
      refreshToken,
      extraParams: extraParams as ExtraParams,
    };
  }

  async function fetchAccessToken(code: string, params: URLSearchParams) {
    params.set("client_id", options.clientId);
    params.set("client_secret", options.clientSecret);
    if (params.get("grant_type") === "refresh_token") {
      params.set("refresh_token", code);
    } else {
      params.set("code", code);
    }
    const res = await fetch(options.tokenURL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
    });
    if (!res.ok) return new Error("Invalid response received");
    return await getAccessToken(res);
  }

  async function stateRedirect(req: Request) {
    const state = crypto.randomUUID();
    const authUrl = getAuthorizationUrl(req, state, authorizationParams);
    const redirect = new RedirectResponse(authUrl);
    await stateContainer.flash(state, redirect.headers);
    return redirect;
  }

  function userProfile(
    _accessToken: string,
    _extraParams: ExtraParams,
  ): Promise<Profile | Error> {
    return Promise.resolve({
      provider: name,
    } as Profile);
  }

  const dependencies = {
    authorizationParams,
    getAuthorizationUrl,
    getCallbackUrl,
    getAccessToken,
    fetchAccessToken,
    stateRedirect,
    userProfile,
    name
  }

  function create(deps: typeof dependencies) {
    async function authenticate(req: Request) {
      const user = await options.session.get(req.headers);
      const { success, failure } = createStrategyFactory<User>(options);
      if (user) {
        return success(user, deps.name);
      }

      const reqUrl = new URL(req.url);

      const callbackURL = deps.getCallbackUrl(reqUrl);

      if (reqUrl.pathname !== callbackURL.pathname) {
        return await deps.stateRedirect(req);
      }

      const stateUrl = reqUrl.searchParams.get("state");
      if (!stateUrl) {
        return await failure(
          `Missing state querystring on url: ${reqUrl.toString()}`,
        );
      }

      const stateSession = await stateContainer.get(req.headers);
      if (!stateSession) {
        return await failure(`Missing state value on session`);
      }

      if (stateSession !== stateUrl) {
        return await failure(
          `session state ${stateSession} does not match url state ${stateUrl}`,
        );
      }

      const code = reqUrl.searchParams.get("code");
      if (!code) {
        return await failure("Missing code");
      }

      const params = deps.authorizationParams(new URLSearchParams());
      params.set("redirect_uri", callbackURL.toString());

      const tokens = await deps.fetchAccessToken(code, params);
      if (tokens instanceof Error) return await failure(tokens.message);

      const { accessToken, refreshToken, extraParams } = tokens;
      const profile = await deps.userProfile(accessToken, extraParams);
      if (profile instanceof Error) return await failure(profile.message);

      const validUser = await verify({
        accessToken,
        refreshToken,
        extraParams,
        profile,
      });

      if (validUser instanceof Error) return await failure(validUser.message);
      return await success(validUser, deps.name);
    }
    return {
      name: deps.name,
      authenticate,
    }
  }

  return {
    dependencies,
    create,
    options
  };
}
