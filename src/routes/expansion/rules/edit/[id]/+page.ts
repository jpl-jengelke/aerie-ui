import { base } from '$app/paths';
import { redirect } from '@sveltejs/kit';
import effects from '../../../../../utilities/effects';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ parent, params }) => {
  const { user } = await parent();

  const { id: ruleIdParam } = params;

  if (ruleIdParam !== null && ruleIdParam !== undefined) {
    const ruleIdAsNumber = parseFloat(ruleIdParam);

    if (!Number.isNaN(ruleIdAsNumber)) {
      const initialRule = await effects.getExpansionRule(ruleIdAsNumber, user);

      if (initialRule !== null) {
        return {
          initialRule,
          user,
        };
      }
    }
  }

  throw redirect(302, `${base}/expansion/rules`);
};
