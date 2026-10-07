import { request, setSiteAccessToken } from "./api_client";

export async function verifySiteAccess(turnstileToken) {
  const data = await request("/auth/site-access/verify", {
    method: "POST",
    body: { turnstile_token: turnstileToken },
    auth: false,
  });
  setSiteAccessToken(data.site_access_token);
  return data;
}
