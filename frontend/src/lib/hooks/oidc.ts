export type OIDCValues = {
  scope: string;
  response_type: string;
  client_id: string;
  redirect_uri: string;
  state: string;
};

interface IuseOIDCParams {
  values: OIDCValues;
  compiled: string;
  isOidc: boolean;
  missingParams: string[];
}

const optionalParams: string[] = ["state"];

export function useOIDCParams(params: URLSearchParams): IuseOIDCParams {
  let compiled: string = "";
  let isOidc = false;
  const missingParams: string[] = [];

  const values: OIDCValues = {
    scope: params.get("scope") ?? "",
    response_type: params.get("response_type") ?? "",
    client_id: params.get("client_id") ?? "",
    redirect_uri: params.get("redirect_uri") ?? "",
    state: params.get("state") ?? "",
  };

  for (const key of Object.keys(values)) {
    if (!values[key as keyof OIDCValues]) {
      if (!optionalParams.includes(key)) {
        missingParams.push(key);
      }
    }
  }

  if (missingParams.length === 0) {
    isOidc = true;
  }

  if (isOidc) {
    compiled = new URLSearchParams(values).toString();
  }

  return {
    values,
    compiled,
    isOidc,
    missingParams,
  };
}
