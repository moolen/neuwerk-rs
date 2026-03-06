import type {
  PolicyTlsHttpHeadersMatch,
  PolicyTlsHttpPathMatch,
  PolicyTlsHttpPolicy,
  PolicyTlsHttpQueryMatch,
  PolicyTlsHttpRequest,
  PolicyTlsHttpResponse,
} from '../../../../types';
import {
  sanitizeStringList,
  sanitizeStringListMap,
  sanitizeStringMap,
  sanitizeUppercaseStringList,
} from '../shared';
import { sanitizeTlsNameMatch } from './name';

function sanitizeHeaders(value?: PolicyTlsHttpHeadersMatch): PolicyTlsHttpHeadersMatch | undefined {
  if (!value) return undefined;
  const require_present = sanitizeStringList(value.require_present);
  const deny_present = sanitizeStringList(value.deny_present);
  const exact = sanitizeStringListMap(value.exact);
  const regex = sanitizeStringMap(value.regex);
  if (
    !require_present.length &&
    !deny_present.length &&
    !Object.keys(exact).length &&
    !Object.keys(regex).length
  ) {
    return undefined;
  }
  return {
    require_present,
    deny_present,
    exact,
    regex,
  };
}

function sanitizeQuery(value?: PolicyTlsHttpQueryMatch): PolicyTlsHttpQueryMatch | undefined {
  if (!value) return undefined;
  const keys_present = sanitizeStringList(value.keys_present);
  const key_values_exact = sanitizeStringListMap(value.key_values_exact);
  const key_values_regex = sanitizeStringMap(value.key_values_regex);
  if (
    !keys_present.length &&
    !Object.keys(key_values_exact).length &&
    !Object.keys(key_values_regex).length
  ) {
    return undefined;
  }
  return {
    keys_present,
    key_values_exact,
    key_values_regex,
  };
}

function sanitizePath(value?: PolicyTlsHttpPathMatch): PolicyTlsHttpPathMatch | undefined {
  if (!value) return undefined;
  const exact = sanitizeStringList(value.exact);
  const prefix = sanitizeStringList(value.prefix);
  const regex = value.regex?.trim();
  if (!exact.length && !prefix.length && !regex) return undefined;
  return {
    exact,
    prefix,
    ...(regex ? { regex } : {}),
  };
}

function sanitizeHttpRequest(value?: PolicyTlsHttpRequest): PolicyTlsHttpRequest | undefined {
  if (!value) return undefined;
  const host = sanitizeTlsNameMatch(value.host);
  const methods = sanitizeUppercaseStringList(value.methods);
  const path = sanitizePath(value.path);
  const query = sanitizeQuery(value.query);
  const headers = sanitizeHeaders(value.headers);
  if (!host && !methods.length && !path && !query && !headers) return undefined;
  return {
    ...(host ? { host } : {}),
    ...(methods.length ? { methods } : {}),
    ...(path ? { path } : {}),
    ...(query ? { query } : {}),
    ...(headers ? { headers } : {}),
  };
}

function sanitizeHttpResponse(value?: PolicyTlsHttpResponse): PolicyTlsHttpResponse | undefined {
  if (!value) return undefined;
  const headers = sanitizeHeaders(value.headers);
  if (!headers) return undefined;
  return { headers };
}

export function sanitizeHttp(value?: PolicyTlsHttpPolicy): PolicyTlsHttpPolicy | undefined {
  if (!value) return undefined;
  const request = sanitizeHttpRequest(value.request);
  const response = sanitizeHttpResponse(value.response);
  if (!request && !response) return undefined;
  return {
    ...(request ? { request } : {}),
    ...(response ? { response } : {}),
  };
}
