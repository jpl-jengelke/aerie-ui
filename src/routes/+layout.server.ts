import { base } from '$app/paths';
import { redirect } from '@sveltejs/kit';
import { shouldRedirectToLogin } from '../utilities/login';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ locals, url }) => {
  if (!url.pathname.includes('login') && shouldRedirectToLogin(locals.user)) {
    throw redirect(302, `${base}/login`);
  }
  return { ...locals };
};
