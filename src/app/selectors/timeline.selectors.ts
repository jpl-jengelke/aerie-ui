import { createFeatureSelector, createSelector } from '@ngrx/store';
import { TimelineState } from '../reducers/timeline.reducer';
import { TimeRange } from '../types';

const getTimelineState = createFeatureSelector<TimelineState>('timeline');

export const getMarginBottom = createSelector(
  getTimelineState,
  (state: TimelineState): number => state.marginBottom,
);

export const getMarginLeft = createSelector(
  getTimelineState,
  (state: TimelineState): number => state.marginLeft,
);

export const getMarginRight = createSelector(
  getTimelineState,
  (state: TimelineState): number => state.marginRight,
);

export const getMarginTop = createSelector(
  getTimelineState,
  (state: TimelineState): number => state.marginTop,
);

export const getViewTimeRange = createSelector(
  getTimelineState,
  (state: TimelineState): TimeRange => state.viewTimeRange,
);
