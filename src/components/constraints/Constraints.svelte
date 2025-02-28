<svelte:options immutable={true} />

<script lang="ts">
  import { goto } from '$app/navigation';
  import { base } from '$app/paths';
  import type { ICellRendererParams } from 'ag-grid-community';
  import { constraintsAll, constraintsColumns } from '../../stores/constraints';
  import type { User } from '../../types/app';
  import type { Constraint } from '../../types/constraint';
  import type { DataGridColumnDef, DataGridRowSelection, RowId } from '../../types/data-grid';
  import type { ModelSlim } from '../../types/model';
  import type { PlanSlim } from '../../types/plan';
  import effects from '../../utilities/effects';
  import { permissionHandler } from '../../utilities/permissionHandler';
  import { featurePermissions } from '../../utilities/permissions';
  import Input from '../form/Input.svelte';
  import CssGrid from '../ui/CssGrid.svelte';
  import CssGridGutter from '../ui/CssGridGutter.svelte';
  import DataGridActions from '../ui/DataGrid/DataGridActions.svelte';
  import { tagsCellRenderer, tagsFilterValueGetter } from '../ui/DataGrid/DataGridTags';
  import SingleActionDataGrid from '../ui/DataGrid/SingleActionDataGrid.svelte';
  import Panel from '../ui/Panel.svelte';
  import SectionTitle from '../ui/SectionTitle.svelte';
  import ConstraintEditor from './ConstraintEditor.svelte';

  export let user: User | null;

  type CellRendererParams = {
    deleteConstraint: (constraint: Constraint) => void;
    editConstraint: (constraint: Constraint) => void;
  };
  type ConstraintsCellRendererParams = ICellRendererParams<Constraint> & CellRendererParams;
  type ConstraintsPermissionsMap = {
    models: Record<number, boolean>;
    plans: Record<number, boolean>;
  };
  type ConstraintsPlanMap = Record<number, PlanSlim>;

  export let initialModelMap: Record<number, ModelSlim> = {};
  export let initialPlanMap: Record<number, PlanSlim> = {};
  export let initialPlans: PlanSlim[] = [];

  const baseColumnDefs: DataGridColumnDef[] = [
    {
      field: 'id',
      filter: 'number',
      headerName: 'ID',
      resizable: true,
      sortable: true,
      suppressAutoSize: true,
      suppressSizeToFit: true,
      width: 60,
    },
    { field: 'name', filter: 'text', headerName: 'Name', minWidth: 80, resizable: true, sortable: true },
    {
      field: 'model_id',
      filter: 'number',
      headerName: 'Model ID',
      sortable: true,
      suppressAutoSize: true,
      suppressSizeToFit: true,
      width: 95,
    },
    {
      field: 'plan_id',
      filter: 'number',
      headerName: 'Plan ID',
      sortable: true,
      suppressAutoSize: true,
      suppressSizeToFit: true,
      width: 80,
    },
    {
      field: 'owner',
      filter: 'string',
      headerName: 'Owner',
      sortable: true,
      suppressAutoSize: true,
      suppressSizeToFit: true,
      width: 80,
    },
    {
      field: 'updated_by',
      filter: 'string',
      headerName: 'Updated By',
      sortable: true,
      suppressAutoSize: true,
      suppressSizeToFit: true,
      width: 120,
    },
    {
      autoHeight: true,
      cellRenderer: tagsCellRenderer,
      field: 'tags',
      filter: 'text',
      filterValueGetter: tagsFilterValueGetter,
      headerName: 'Tags',
      resizable: true,
      sortable: false,
      width: 220,
      wrapText: true,
    },
  ];
  const permissionError = 'You do not have permission to create a constraint.';

  let columnDefs = baseColumnDefs;
  let constraintsDeletePermissionsMap: ConstraintsPermissionsMap = {
    models: {},
    plans: {},
  };
  let constraintsEditPermissionsMap: ConstraintsPermissionsMap = {
    models: {},
    plans: {},
  };
  let constraintsPlanMap: ConstraintsPlanMap = {};
  let constraintModelId: number | null = null;
  let filterText: string = '';
  let filteredConstraints: Constraint[] = [];
  let hasPermission: boolean = false;
  let selectedConstraint: Constraint | null = null;

  $: filteredConstraints = $constraintsAll.filter(constraint => {
    const filterTextLowerCase = filterText.toLowerCase();
    const includesId = `${constraint.id}`.includes(filterTextLowerCase);
    const includesName = constraint.name.toLocaleLowerCase().includes(filterTextLowerCase);
    return includesId || includesName;
  });
  $: if (selectedConstraint !== null) {
    const found = $constraintsAll.findIndex(constraint => constraint.id === selectedConstraint?.id);
    if (found === -1) {
      selectedConstraint = null;
    }
  }
  $: constraintModelId = getConstraintModelId(selectedConstraint);
  $: constraintsDeletePermissionsMap = ($constraintsAll ?? []).reduce(
    (prevMap: ConstraintsPermissionsMap, constraint: Constraint) => {
      const { model_id, plan_id } = constraint;

      if (plan_id !== null) {
        const plan = initialPlanMap[plan_id];
        if (plan) {
          return {
            ...prevMap,
            plans: {
              ...prevMap.plans,
              [plan_id]: featurePermissions.constraints.canDelete(user, plan, constraint),
            },
          };
        }
      } else if (model_id !== null) {
        const model = initialModelMap[model_id];
        if (model) {
          return {
            ...prevMap,
            models: {
              ...prevMap.models,
              [model_id]: model.plans.reduce((prevPermission: boolean, { id }) => {
                const plan = initialPlanMap[id];
                if (plan) {
                  return prevPermission || featurePermissions.constraints.canDelete(user, plan, constraint);
                }
                return prevPermission;
              }, false),
            },
          };
        }
      }

      return prevMap;
    },
    {
      models: {},
      plans: {},
    },
  );
  $: constraintsEditPermissionsMap = ($constraintsAll ?? []).reduce(
    (prevMap: ConstraintsPermissionsMap, constraint: Constraint) => {
      const { model_id, plan_id } = constraint;

      if (plan_id !== null) {
        const plan = initialPlanMap[plan_id];
        if (plan) {
          return {
            ...prevMap,
            plans: {
              ...prevMap.plans,
              [plan_id]: featurePermissions.constraints.canUpdate(user, plan, constraint),
            },
          };
        }
      } else if (model_id !== null) {
        const model = initialModelMap[model_id];
        if (model) {
          return {
            ...prevMap,
            models: {
              ...prevMap.models,
              [model_id]: model.plans.reduce((prevPermission: boolean, { id }) => {
                const plan = initialPlanMap[id];
                if (plan) {
                  return prevPermission || featurePermissions.constraints.canUpdate(user, plan, constraint);
                }
                return prevPermission;
              }, false),
            },
          };
        }
      }

      return prevMap;
    },
    {
      models: {},
      plans: {},
    },
  );
  $: constraintsPlanMap = ($constraintsAll ?? []).reduce((prevMap: ConstraintsPlanMap, constraint: Constraint) => {
    const { model_id, plan_id, id } = constraint;

    if (plan_id !== null) {
      const plan = initialPlanMap[plan_id];
      return {
        ...prevMap,
        [id]: plan,
      };
    } else if (model_id !== null) {
      const model = initialModelMap[model_id];
      if (model) {
        const modelPlan = model.plans.find(({ id }) => {
          const plan = initialPlanMap[id];
          return featurePermissions.constraints.canDelete(user, plan, constraint);
        });

        if (modelPlan) {
          return {
            ...prevMap,
            [id]: initialPlanMap[modelPlan.id],
          };
        }
      }
    }

    return prevMap;
  }, {});
  $: {
    hasPermission = initialPlans.reduce((prevPermission: boolean, plan) => {
      return prevPermission || hasPlanPermission(plan, user);
    }, false);
    columnDefs = [
      ...baseColumnDefs,
      {
        cellClass: 'action-cell-container',
        cellRenderer: (params: ConstraintsCellRendererParams) => {
          const actionsDiv = document.createElement('div');
          actionsDiv.className = 'actions-cell';
          new DataGridActions({
            props: {
              deleteCallback: params.deleteConstraint,
              deleteTooltip: {
                content: 'Delete Constraint',
                placement: 'bottom',
              },
              editCallback: params.editConstraint,
              editTooltip: {
                content: 'Edit Constraint',
                placement: 'bottom',
              },
              hasDeletePermission: params.data ? hasDeletePermission(user, params.data) : false,
              hasEditPermission: params.data ? hasEditPermission(user, params.data) : false,
              rowData: params.data,
            },
            target: actionsDiv,
          });

          return actionsDiv;
        },
        cellRendererParams: {
          deleteConstraint,
          editConstraint,
        } as CellRendererParams,
        field: 'actions',
        headerName: '',
        resizable: false,
        sortable: false,
        suppressAutoSize: true,
        suppressSizeToFit: true,
        width: 55,
      },
    ];
  }

  async function deleteConstraint(constraint: Constraint) {
    const constraintPlan = constraintsPlanMap[constraint.id];
    const success = await effects.deleteConstraint(constraint, constraintPlan, user);

    if (success) {
      filteredConstraints = filteredConstraints.filter(c => constraint.id !== c.id);

      if (constraint.id === selectedConstraint?.id) {
        selectedConstraint = null;
      }
    }
  }

  function deleteConstraintContext(event: CustomEvent<RowId[]>) {
    const id = event.detail[0] as number;
    const constraint = $constraintsAll.find(c => c.id === id);
    if (constraint) {
      deleteConstraint(constraint);
    }
  }

  function editConstraint({ id }: Pick<Constraint, 'id'>) {
    goto(`${base}/constraints/edit/${id}`);
  }

  function editConstraintContext(event: CustomEvent<RowId[]>) {
    editConstraint({ id: event.detail[0] as number });
  }

  function getConstraintModelId(selectedConstraint: Constraint | null): number | null {
    if (selectedConstraint !== null) {
      const { model_id, plan_id } = selectedConstraint;

      if (plan_id !== null) {
        const plan = initialPlans.find(plan => plan.id === plan_id);
        if (plan) {
          return plan.model_id;
        }
      } else if (model_id !== null) {
        return model_id;
      }
    }

    return null;
  }

  function hasDeletePermission(_user: User | null, constraint: Constraint) {
    const { model_id, plan_id } = constraint;
    if (plan_id !== null) {
      return constraintsDeletePermissionsMap.plans[plan_id] ?? false;
    } else if (model_id !== null) {
      return constraintsDeletePermissionsMap.models[model_id] ?? false;
    }

    return false;
  }

  function hasEditPermission(_user: User | null, constraint: Constraint) {
    const { model_id, plan_id } = constraint;
    if (plan_id !== null) {
      return constraintsEditPermissionsMap.plans[plan_id] ?? false;
    } else if (model_id !== null) {
      return constraintsEditPermissionsMap.models[model_id] ?? false;
    }

    return false;
  }

  function hasPlanPermission(plan: PlanSlim, user: User | null): boolean {
    return featurePermissions.constraints.canCreate(user, plan);
  }

  function toggleConstraint(event: CustomEvent<DataGridRowSelection<Constraint>>) {
    const {
      detail: { data: clickedConstraint, isSelected },
    } = event;

    if (isSelected) {
      selectedConstraint = clickedConstraint;
    } else if (selectedConstraint?.id === clickedConstraint.id) {
      selectedConstraint = null;
    }
  }
</script>

<CssGrid bind:columns={$constraintsColumns}>
  <Panel>
    <svelte:fragment slot="header">
      <SectionTitle>Constraints</SectionTitle>

      <Input>
        <input bind:value={filterText} class="st-input" placeholder="Filter constraints" style="width: 100%;" />
      </Input>

      <div class="right">
        <button
          class="st-button secondary ellipsis"
          use:permissionHandler={{
            hasPermission,
            permissionError,
          }}
          on:click={() => goto(`${base}/constraints/new`)}
        >
          New
        </button>
      </div>
    </svelte:fragment>

    <svelte:fragment slot="body">
      {#if filteredConstraints.length}
        <SingleActionDataGrid
          {columnDefs}
          hasEdit={true}
          {hasDeletePermission}
          {hasEditPermission}
          itemDisplayText="Constraint"
          items={filteredConstraints}
          {user}
          on:deleteItem={deleteConstraintContext}
          on:editItem={editConstraintContext}
          on:rowSelected={toggleConstraint}
        />
      {:else}
        <div class="p1 st-typography-label">No Constraints Found</div>
      {/if}
    </svelte:fragment>
  </Panel>

  <CssGridGutter track={1} type="column" />

  <ConstraintEditor
    constraintDefinition={selectedConstraint?.definition ?? 'No Constraint Selected'}
    {constraintModelId}
    readOnly={true}
    title="Constraint - Definition Editor (Read-only)"
    {user}
  />
</CssGrid>
