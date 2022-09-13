import { VerifyCb } from "../strategy.ts";
import {
  createOAuth2Strategy,
  OAuth2Profile,
  OAuth2StrategyOptions,
  OAuth2StrategyVerifyParams,
} from "./oauth2.ts";

export interface GoogleStrategyOptions<User>
  extends Omit<OAuth2StrategyOptions<User>, "authorizationURL" | "tokenURL"> {
  /**
   * @default "openid profile email"
   */
  scope?: string;
  accessType?: "online" | "offline";
  includeGrantedScopes?: boolean;
  prompt?: "none" | "consent" | "select_account";
}

export type GoogleProfile = {
  id: string;
  displayName: string;
  name: {
    familyName: string;
    givenName: string;
  };
  emails: [{ value: string }];
  photos: [{ value: string }];
  _json: {
    sub: string;
    name: string;
    given_name: string;
    family_name: string;
    picture: string;
    locale: string;
    email: string;
    email_verified: boolean;
    hd: string;
  };
} & OAuth2Profile;

const authorizationURL = "https://accounts.google.com/o/oauth2/v2/auth";
const tokenURL = "https://oauth2.googleapis.com/token";
const name = "google";

export function createGoogleStrategy<User>(
  options: GoogleStrategyOptions<User>,
  verify: VerifyCb<User, OAuth2StrategyVerifyParams<GoogleProfile, never>>,
) {
  const { dependencies, create } = createOAuth2Strategy(
    { ...options, authorizationURL, tokenURL },
    verify,
  );

  const userInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo";
  async function userProfile(accessToken: string) {
    const response = await fetch(userInfoURL, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    const raw: GoogleProfile["_json"] = await response.json();
    const profile: GoogleProfile = {
      provider: "google",
      id: raw.sub,
      displayName: raw.name,
      name: {
        familyName: raw.family_name,
        givenName: raw.given_name,
      },
      emails: [{ value: raw.email }],
      photos: [{ value: raw.picture }],
      _json: raw,
    };
    return profile;
  }

  function authorizationParams() {
    const params = new URLSearchParams({
      scope: options.scope ?? "openid profile email",
      access_type: options.accessType ?? "online",
      include_granted_scopes: `${options.includeGrantedScopes ?? false}`,
    });
    if (options.prompt) {
      params.set("prompt", options.prompt);
    }
    return dependencies.authorizationParams(params);
  }

  return {
    dependencies: { ...dependencies, userProfile, authorizationParams, name },
    create,
    options
  };
}
