import type { Writable } from 'svelte/store';
import { writable } from 'svelte/store';
import Toastify from 'toastify-js';
import { ExecutionStatus } from '../utilities/enums';
import { SUB_SCHEDULING_SPEC_GOALS } from '../utilities/gql';
import req from '../utilities/requests';
import { getGqlSubscribable } from './subscribable';

/* Stores. */

export const schedulingSpecGoals = getGqlSubscribable<SchedulingSpecGoal[]>(
  SUB_SCHEDULING_SPEC_GOALS,
  { specification_id: -1 },
  [],
);

export const schedulingStatus: Writable<ExecutionStatus> = writable(
  ExecutionStatus.Clean,
);

/* Utility Functions. */

export async function createSchedulingGoal(
  goal: SchedulingGoalInsertInput,
): Promise<SchedulingGoal | null> {
  const newGoal = await req.createSchedulingGoal(goal);
  if (newGoal) {
    Toastify({
      backgroundColor: '#2da44e',
      duration: 3000,
      gravity: 'bottom',
      position: 'left',
      text: 'Scheduling Goal Created Successfully',
    }).showToast();
    return newGoal;
  } else {
    Toastify({
      backgroundColor: '#a32a2a',
      duration: 3000,
      gravity: 'bottom',
      position: 'left',
      text: 'Scheduling Goal Create Failed',
    }).showToast();
    return null;
  }
}
