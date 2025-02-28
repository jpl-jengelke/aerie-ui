import type { UserId } from './app';
import type { Tag } from './tags';
import type { TimeRange } from './timeline';

export type Constraint = {
  created_at: string;
  definition: string;
  description: string;
  id: number;
  model_id: number | null;
  name: string;
  owner: UserId;
  plan_id: number | null;
  tags: { tag: Tag }[];
  updated_at: string;
  updated_by: UserId;
};

export type ConstraintInsertInput = Omit<
  Constraint,
  'id' | 'created_at' | 'updated_at' | 'owner' | 'updated_by' | 'tags'
>;

export type ConstraintType = 'model' | 'plan';

export type ConstraintViolation = {
  activityInstanceIds: number[];
  windows: TimeRange[];
};

export type ConstraintResult = {
  gaps: TimeRange[];
  resourceIds: string[];
  violations: ConstraintViolation[] | null;
};

export type ConstraintResultWithName = ConstraintResult & { constraintName: string };

export type ConstraintResponse = {
  constraintId: Constraint['id'];
  constraintName: Constraint['name'];
  errors: UserCodeError[];
  results: ConstraintResult;
  success: boolean;
  type: ConstraintType;
};

export type UserCodeError = {
  location: CodeLocation;
  message: string;
  stack: string;
};

export type CodeLocation = {
  column: number;
  line: number;
};
