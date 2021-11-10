import type { Request } from '@sveltejs/kit';
import type { MaybePromise } from '@sveltejs/kit/types/helper';
import type { ServerRequest, ServerResponse } from '@sveltejs/kit/types/hooks';
import { parse } from 'cookie';
import type { User } from '../types';

type HandleInput = {
  request: ServerRequest<Record<string, any>>;
  resolve: (
    request: ServerRequest<Record<string, any>>,
  ) => MaybePromise<ServerResponse>;
};

type Session = {
  user: User | null;
};

export async function handle({
  request,
  resolve,
}: HandleInput): Promise<ServerResponse> {
  const cookies = parse(request.headers.cookie || '');
  const { user: userCookie = null } = cookies;

  if (userCookie) {
    const userBuffer = Buffer.from(userCookie, 'base64');
    const userStr = userBuffer.toString('utf-8');
    const user: User = JSON.parse(userStr);
    request.locals.user = user;
  } else {
    request.locals.user = null;
  }

  return await resolve(request);
}

export function getSession(
  request: Request<Record<string, any>>,
): MaybePromise<Session> {
  const { locals } = request;
  const { user = null } = locals;
  return {
    user,
  };
}