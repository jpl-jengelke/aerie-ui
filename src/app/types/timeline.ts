import { ActivityType } from './activity-type';
import { Violation } from './simulation';
import { StringTMap } from './string-t-map';

export interface ActivityLayer extends Layer {
  points?: ActivityPoint[];
}

export interface ActivityPoint extends Point {
  children?: ActivityPoint[];
  duration: number;
  label?: Label;
  parent: string | null;
}

export interface Axis {
  id: string;
  color?: string;
  label?: Label;
  scaleDomain?: number[];
  tickCount?: number;
}

export interface CreatePoint {
  activityType: ActivityType;
  startTimestamp: string;
  type: string;
}

export interface DeletePoint {
  id: string;
  type: string;
}

export interface HorizontalGuide {
  id: string;
  label: Label;
  rowId: string;
  y: number;
  yAxisId: string;
}

export interface HorizontalGuideEvent {
  guide?: HorizontalGuide;
  mode: 'create' | 'edit';
  rowId?: string;
  yAxes?: Axis[];
}

export interface Label {
  align?: CanvasTextAlign;
  baseline?: CanvasTextBaseline;
  color?: string;
  fontFace?: string;
  fontSize?: number;
  hidden?: boolean;
  text: string;
}

export interface Layer {
  chartType: 'activity' | 'line' | 'x-range';
  color?: string;
  filter?: {
    activity?: {
      type?: string;
    };
    state?: {
      name?: string;
    };
  };
  id: string;
  type: 'activity' | 'state';
  yAxisId?: string;
}

export interface LineLayer extends Layer {
  points?: LinePoint[];
}

export interface LinePoint extends Point {
  radius?: number;
  y: number;
}

export interface MouseOverPoints<T> {
  e: MouseEvent;
  points: T[];
  pointsById?: StringTMap<T>;
}

export interface MouseSelectPoints<T> {
  e: MouseEvent;
  points: T[];
  pointsById?: StringTMap<T>;
}

export interface Point {
  color?: string;
  id: string;
  selected?: boolean;
  type: 'activity' | 'line' | 'x-range';
  x: number;
}

export interface Row {
  autoAdjustHeight?: boolean;
  height?: number;
  horizontalGuides?: HorizontalGuide[];
  id: string;
  layers: Layer[];
  violations?: Violation[];
  yAxes?: Axis[];
}

export interface SavePoint {
  id: string;
  type: string;
  value: any;
}

export interface SelectPoint {
  id: string;
  type: string;
}

export interface Timeline {
  rows: Row[];
}

export interface UpdatePoint {
  id: string;
  type: string;
  value: any;
}

export interface UpdateRow {
  rowId: string;
  update: any;
}

export interface XAxisTick {
  date: Date;
  time: string;
  yearDay: string;
}

export interface XRangeLayer extends Layer {
  points?: XRangePoint[];
}

export interface XRangePoint extends Point {
  label?: Label;
}