import { derived, writable, type Readable, type Writable } from 'svelte/store';
import type { ExpansionRuleSlim, ExpansionSequence, ExpansionSet } from '../types/expansion';
import gql from '../utilities/gql';
import type { Status } from '../utilities/status';
import { simulationDatasetId } from './simulation';
import { gqlSubscribable } from './subscribable';

/* Subscriptions. */

export const expansionRules = gqlSubscribable<ExpansionRuleSlim[]>(gql.SUB_EXPANSION_RULES, {}, [], null);

export const expansionSequences = gqlSubscribable<ExpansionSequence[]>(gql.SUB_EXPANSION_SEQUENCES, {}, [], null);

export const expansionSets = gqlSubscribable<ExpansionSet[]>(gql.SUB_EXPANSION_SETS, {}, [], null);

/* Writeable. */

export const creatingExpansionSequence: Writable<boolean> = writable(false);

export const createExpansionRuleError: Writable<string | null> = writable(null);

export const expansionRulesColumns: Writable<string> = writable('2fr 3px 1fr');

export const expansionRulesFormColumns: Writable<string> = writable('1fr 3px 2fr');

export const expansionSetsColumns: Writable<string> = writable('2fr 3px 1fr');

export const expansionSetsFormColumns: Writable<string> = writable('1fr 3px 2fr');

export const expansionRunsColumns: Writable<string> = writable('1fr 3px 2fr');

export const savingExpansionRule: Writable<boolean> = writable(false);

export const savingExpansionSet: Writable<boolean> = writable(false);

export const planExpansionStatus: Writable<Status | null> = writable(null);

export const selectedExpansionSetId: Writable<number | null> = writable(null);

/* Derived. */

export const filteredExpansionSequences: Readable<ExpansionSequence[]> = derived(
  [expansionSequences, simulationDatasetId],
  ([$expansionSequences, $simulationDatasetId]) =>
    $expansionSequences.filter(sequence => sequence.simulation_dataset_id === $simulationDatasetId),
);

export function resetExpansionStores(): void {
  createExpansionRuleError.set(null);
  creatingExpansionSequence.set(false);
  savingExpansionRule.set(false);
  savingExpansionSet.set(false);
  planExpansionStatus.set(null);
  selectedExpansionSetId.set(null);
}
