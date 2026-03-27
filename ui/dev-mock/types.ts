import type { IncomingMessage, ServerResponse } from 'node:http';

export type MockResponseKind = 'json' | 'text' | 'blob' | 'sse';

export type MockHeaders = Record<string, string>;

export interface MockIncomingRequest {
  method: string;
  url: string;
  headers: MockHeaders;
  body: Buffer | undefined;
}

export interface MockRequest extends MockIncomingRequest {
  pathname: string;
}

export interface MockResponse {
  status: number;
  headers: MockHeaders;
  kind: MockResponseKind;
  json?: unknown;
  text?: string;
  body?: Uint8Array;
}

export interface MockResponseInit {
  status?: number;
  headers?: Record<string, string | undefined>;
}

export type MockRouteHandler = (
  request: MockRequest
) => MockResponse | Promise<MockResponse>;

export interface MockRoute {
  method: string;
  pathname: string;
  handler: MockRouteHandler;
}

export interface MockRouterOptions {
  routes?: MockRoute[];
}

export interface MockRouter {
  handle(request: MockIncomingRequest): Promise<MockResponse | undefined>;
  handleNodeRequest(
    req: IncomingMessage,
    res: ServerResponse
  ): Promise<boolean>;
}
