import { base } from '$app/paths';
import { redirect } from '@sveltejs/kit';
import effects from '../../../../utilities/effects';
import { parseFloatOrNull } from '../../../../utilities/generic';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ parent, url }) => {
  const { user } = await parent();

  if (!user) {
    throw redirect(302, `${base}/login`);
  }

  const { models = [], plans = [] } = await effects.getPlansAndModelsForScheduling();

  const modelId: string | null = url.searchParams.get('modelId');
  const specId: string | null = url.searchParams.get('specId');
  const initialModelId: number | null = parseFloatOrNull(modelId);
  const initialSpecId: number | null = parseFloatOrNull(specId);

  return {
    initialModelId,
    initialSpecId,
    models,
    plans,
  };
};