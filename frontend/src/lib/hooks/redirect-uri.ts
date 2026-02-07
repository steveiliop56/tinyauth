type IuseRedirectUri = {
  url?: URL;
  valid: boolean;
  trusted: boolean;
  allowedProto: boolean;
  httpsDowngrade: boolean;
};

export const useRedirectUri = (
  redirect_uri: string | null,
  cookieDomain: string,
): IuseRedirectUri => {
  let isValid = false;
  let isTrusted = false;
  let isAllowedProto = false;
  let isHttpsDowngrade = false;

  if (!redirect_uri) {
    return {
      valid: false,
      trusted: false,
      allowedProto: false,
      httpsDowngrade: false,
    };
  }

  let url: URL;

  try {
    url = new URL(redirect_uri);
  } catch {
    return {
      valid: false,
      trusted: false,
      allowedProto: false,
      httpsDowngrade: false,
    };
  }

  isValid = true;

  if (
    url.hostname == cookieDomain ||
    url.hostname.endsWith(`.${cookieDomain}`)
  ) {
    isTrusted = true;
  }

  if (url.protocol == "http:" || url.protocol == "https:") {
    isAllowedProto = true;
  }

  if (window.location.protocol == "https:" && url.protocol == "http:") {
    isHttpsDowngrade = true;
  }

  return {
    url,
    valid: isValid,
    trusted: isTrusted,
    allowedProto: isAllowedProto,
    httpsDowngrade: isHttpsDowngrade,
  };
};
