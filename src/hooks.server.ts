import type { Handle } from '@sveltejs/kit';
import { parse } from 'cookie';
import jwtDecode from 'jwt-decode';
import type { BaseUser, ParsedUserToken, User } from './types/app';
import effects from './utilities/effects';
import { isLoginEnabled } from './utilities/login';
import { ADMIN_ROLE } from './utilities/permissions';
import { env } from '$env/dynamic/public';

export const handle: Handle = async ({ event, resolve }) => {
  try {
    if (!isLoginEnabled()) {
      const permissibleQueries = await effects.getUserQueries(null);
      const rolePermissions = await effects.getRolePermissions(null);
      event.locals.user = {
        activeRole: ADMIN_ROLE,
        allowedRoles: [ADMIN_ROLE],
        defaultRole: ADMIN_ROLE,
        id: 'unknown',
        permissibleQueries,
        rolePermissions,
        token: '',
      };
    } else {

      const cookieHeader = event.request.headers.get('cookie') ?? '';
      const cookies = parse(cookieHeader);
      const { activeRole: activeRoleCookie = null, user: userCookie = null, iPlanetDirectoryPro: camToken = null } = cookies;

      // try to get role with current JWT
      if (userCookie) {
        const user = await computeRolesFromCookies(userCookie, activeRoleCookie);
        if (user) {
          console.log(`existing JWT was valid, not checking SSO...`);
          event.locals.user = user;
          return await resolve(event);
        }
      }

      // otherwise try to get userID with cam token
      if (camToken) {
          console.log(`trying SSO, since JWT was invalid`);
          const valid = await effects.validateSSO(camToken);
          if (!valid) {
            console.log("Invalid CAM token, redirecting to CAM UI")
            const SSO_LOGIN_URL = env.PUBLIC_SSO_LOGIN_URL;

            const base = event.request.url;

            return new Response(null, {
              status: 307,
              headers: { location: `${SSO_LOGIN_URL}?goto=${base}` }
            })
          }

          const camUser = await effects.loginSSO(camToken);
          if (camUser) {
            const user: BaseUser = {
              id: camUser.message,
              token: camUser.token ?? ""
            };
            const camRoles = await computeRolesFromJWT(user, activeRoleCookie);

            if (camRoles) {
              console.log(`successfully SSO'd for user ${camRoles.id}`);
              event.locals.user = camRoles;
              const userStr = JSON.stringify(user);
              const userCookie = Buffer.from(userStr).toString('base64');
              event.cookies.set("user", userCookie, { path: "/" });
              event.cookies.set("activeRole", camRoles.activeRole, { path: "/" });
              return await resolve(event);
            }
          }
      }

      // otherwise, we can't auth
      console.log("unable to auth with JWT or CAM token");
      event.locals.user = null;
    }
  } catch (e) {
    console.log(e);
    event.locals.user = null;
  }

  return await resolve(event);
};

async function computeRolesFromJWT(baseUser: BaseUser, activeRole: string | null): Promise<User | null> {
  const { success } = await effects.session(baseUser);
  if (!success) return null;

  const decodedToken: ParsedUserToken = jwtDecode(baseUser.token);

  const allowedRoles = decodedToken['https://hasura.io/jwt/claims']['x-hasura-allowed-roles'];
  const defaultRole = decodedToken['https://hasura.io/jwt/claims']['x-hasura-default-role'];
  activeRole ??=  defaultRole;
  const user: User = {
    ...baseUser,
    activeRole,
    allowedRoles,
    defaultRole,
    permissibleQueries: null,
    rolePermissions: null,
  };
  const permissibleQueries = await effects.getUserQueries(user);

  const rolePermissions = await effects.getRolePermissions(user);
  return {
    ...user,
    permissibleQueries,
    rolePermissions,
  };
}

async function computeRolesFromCookies(userCookie: string | null, activeRoleCookie: string | null): Promise<User | null> {
  const userBuffer = Buffer.from(userCookie ?? "", 'base64');
  const userStr = userBuffer.toString('utf-8');
  const baseUser: BaseUser = JSON.parse(userStr);

  return computeRolesFromJWT(baseUser, activeRoleCookie);
}
