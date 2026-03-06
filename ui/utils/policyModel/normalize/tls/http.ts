import type {
  PolicyTlsHttpHeadersMatch,
  PolicyTlsHttpPathMatch,
  PolicyTlsHttpPolicy,
  PolicyTlsHttpQueryMatch,
  PolicyTlsHttpRequest,
  PolicyTlsHttpResponse,
} from '../../../../types';
import { asString, asStringList, asStringListMap, asStringMap, isObject } from '../shared';
import { normalizeTlsNameMatch } from './name';

function normalizeHttpPath(value: unknown): PolicyTlsHttpPathMatch | undefined {
  if (!isObject(value)) return undefined;
  const exact = asStringList(value.exact);
  const prefix = asStringList(value.prefix);
  const regex = asString(value.regex);
  if (!exact.length && !prefix.length && !regex) return undefined;
  return {
    exact,
    prefix,
    ...(regex ? { regex } : {}),
  };
}

function normalizeHttpQuery(value: unknown): PolicyTlsHttpQueryMatch | undefined {
  if (!isObject(value)) return undefined;
  const keys_present = asStringList(value.keys_present);
  const key_values_exact = asStringListMap(value.key_values_exact);
  const key_values_regex = asStringMap(value.key_values_regex);
  if (!keys_present.length && !Object.keys(key_values_exact).length && !Object.keys(key_values_regex).length) {
    return undefined;
  }
  return {
    keys_present,
    key_values_exact,
    key_values_regex,
  };
}

function normalizeHttpHeaders(value: unknown): PolicyTlsHttpHeadersMatch | undefined {
  if (!isObject(value)) return undefined;
  const require_present = asStringList(value.require_present);
  const deny_present = asStringList(value.deny_present);
  const exact = asStringListMap(value.exact);
  const regex = asStringMap(value.regex);
  if (!require_present.length && !deny_present.length && !Object.keys(exact).length && !Object.keys(regex).length) {
    return undefined;
  }
  return {
    require_present,
    deny_present,
    exact,
    regex,
  };
}

function normalizeHttpRequest(value: unknown): PolicyTlsHttpRequest | undefined {
  if (!isObject(value)) return undefined;
  const host = normalizeTlsNameMatch(value.host);
  const methods = asStringList(value.methods).map((method) => method.toUpperCase());
  const path = normalizeHttpPath(value.path);
  const query = normalizeHttpQuery(value.query);
  const headers = normalizeHttpHeaders(value.headers);

  if (!host && !methods.length && !path && !query && !headers) return undefined;
  return {
    ...(host ? { host } : {}),
    methods,
    ...(path ? { path } : {}),
    ...(query ? { query } : {}),
    ...(headers ? { headers } : {}),
  };
}

function normalizeHttpResponse(value: unknown): PolicyTlsHttpResponse | undefined {
  if (!isObject(value)) return undefined;
  const headers = normalizeHttpHeaders(value.headers);
  if (!headers) return undefined;
  return { headers };
}

export function normalizeTlsHttp(value: unknown): PolicyTlsHttpPolicy | undefined {
  if (!isObject(value)) return undefined;
  const request = normalizeHttpRequest(value.request);
  const response = normalizeHttpResponse(value.response);
  if (!request && !response) return undefined;
  return {
    ...(request ? { request } : {}),
    ...(response ? { response } : {}),
  };
}
