import { get, writable } from 'svelte/store';
import type { Field, FieldStore, ValidatorFn } from '../types';
import { validateField } from '../utilities/validators';

function initialField<T>(
  initialValue: T,
  initialValidators: ValidatorFn<T>[] = [],
): Field<T> {
  return {
    dirty: false,
    dirtyAndValid: false,
    errors: [],
    firstError: null,
    initialValue,
    invalid: false,
    pending: false,
    valid: false,
    validators: initialValidators,
    value: initialValue,
  };
}

export function field<T>(
  initialValue: T,
  initialValidators: ValidatorFn<T>[] = [],
): FieldStore<T> {
  const field: Field<T> = initialField(initialValue, initialValidators);
  const { set, subscribe, update } = writable<Field<T>>(field);

  return {
    set(newField: Field<T>) {
      const dirty = newField.initialValue !== newField.value;
      set({ ...newField, dirty });
    },
    subscribe,
    update,
    async validate(newValue?: T): Promise<boolean> {
      const currentField: Field<T> = get(this);
      const value = newValue === undefined ? currentField.value : newValue;
      const newField: Field<T> = { ...currentField, pending: true, value };
      set(newField);

      const errors = await validateField(newField);
      const firstError = errors.length ? errors[0] : null;
      const invalid = errors.length > 0;
      const pending = false;
      const valid = !invalid;
      const dirtyAndValid = newField.dirty && valid;

      set({
        ...newField,
        dirtyAndValid,
        firstError,
        invalid,
        pending,
        valid,
      });

      return valid;
    },
  };
}